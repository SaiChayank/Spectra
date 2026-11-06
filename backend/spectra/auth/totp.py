"""TOTP (RFC 6238, HMAC-SHA1, 30 s, 6 digits) and the vault that protects its secrets.

Stdlib plus ``cryptography`` (already a dependency).  Design notes:

* **Verification** accepts the current step and one step either side (clock
  skew), compares every candidate in constant time, and returns the matched
  counter so the caller can refuse it (and anything older) next time - a code
  is single-use.
* **The shared secret must be recoverable** to compute codes, so unlike a
  password it cannot be a one-way hash.  It is encrypted with AES-256-GCM
  under a 32-byte key held in a mode-0600 file *outside the database*
  (``totp.key`` next to it), bound to the account (AAD = the user id) so a
  ciphertext cannot be moved to another row.  A stolen database alone does not
  reveal secrets; a stolen database *plus* the key file does.  The key is
  created only when the first secret is encrypted and is never re-created if
  it goes missing (a lost key means undecryptable secrets - the operator
  recovery path is ``spectra auth totp-reset``).
* **Recovery codes** are single-use, 48-bit random, stored only as SHA-256 of
  the normalised code (they are high-entropy, so a fast hash is sufficient).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import threading
from urllib.parse import quote

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

STEP = 30
DIGITS = 6
RECOVERY_COUNT = 8
_VAULT_PREFIX = "v1:"
_RECOVERY_DST = b"spectra/totp/recovery/v1:"


class TotpVaultError(RuntimeError):
    """The secret could not be decrypted (wrong/missing key, tampering, wrong account)."""


# -- RFC 4226 / 6238 -------------------------------------------------------------------

def hotp(secret: bytes, counter: int, digits: int = DIGITS) -> str:
    """RFC 4226 HOTP value for ``counter`` (dynamic truncation)."""
    mac = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** digits).zfill(digits)


def counter_at(timestamp: float, step: int = STEP) -> int:
    return int(timestamp // step)


def verify(secret: bytes, code, now: float, last_counter: int, window: int = 1) -> int | None:
    """Matched counter if ``code`` is valid at ``now`` and newer than ``last_counter``.

    ``window`` steps of skew are tolerated on each side.  Every candidate is
    compared (no early exit) so timing does not reveal which step matched.
    """
    if not isinstance(code, str):
        return None
    code = code.replace(" ", "")
    if len(code) != DIGITS or not (code.isascii() and code.isdigit()):
        return None
    current = counter_at(now)
    matched: int | None = None
    for counter in range(current - window, current + window + 1):
        if hmac.compare_digest(hotp(secret, counter), code) and counter > last_counter:
            matched = counter
    return matched


def new_secret() -> bytes:
    return secrets.token_bytes(20)           # 160 bits, the RFC 4226 recommendation


def to_base32(secret: bytes) -> str:
    return base64.b32encode(secret).decode().rstrip("=")


def from_base32(text: str) -> bytes:
    text = text.strip().replace(" ", "").upper()
    return base64.b32decode(text + "=" * (-len(text) % 8))


def provisioning_uri(secret_b32: str, account: str, issuer: str) -> str:
    """``otpauth://`` URI that authenticator apps import (Key URI Format)."""
    return (f"otpauth://totp/{quote(issuer, safe='')}:{quote(account, safe='')}"
            f"?secret={secret_b32}&issuer={quote(issuer, safe='')}")


# -- recovery codes ----------------------------------------------------------------------

def new_recovery_codes(n: int = RECOVERY_COUNT) -> list[str]:
    codes: set[str] = set()
    while len(codes) < n:
        raw = secrets.token_hex(6)           # 48 bits
        codes.add(f"{raw[:4]}-{raw[4:8]}-{raw[8:]}")
    return sorted(codes)


def normalize_recovery(code: str) -> str:
    return code.strip().lower().replace("-", "").replace(" ", "")


def hash_recovery(code: str) -> str:
    return hashlib.sha256(_RECOVERY_DST + normalize_recovery(code).encode()).hexdigest()


def looks_like_recovery(code: str) -> bool:
    c = normalize_recovery(code)
    return len(c) == 12 and all(ch in "0123456789abcdef" for ch in c)


# -- the vault -----------------------------------------------------------------------------

class TotpVault:
    """AES-256-GCM encryption of TOTP secrets under a key file kept off the database."""

    def __init__(self, key_path: str) -> None:
        self._path = key_path
        self._lock = threading.Lock()
        self._key: bytes | None = None

    def _read_key(self) -> bytes | None:
        try:
            with open(self._path, "r", encoding="ascii") as fh:
                key = bytes.fromhex(fh.read().strip())
        except (OSError, ValueError):
            return None
        return key if len(key) == 32 else None

    def _key_for_encrypt(self) -> bytes:
        with self._lock:
            if self._key is None:
                self._key = self._read_key()
            if self._key is None:
                self._key = self._create_key()
            return self._key

    def _create_key(self) -> bytes:
        """Create the key file (0600, exclusive); if a racing process won, use its key."""
        os.makedirs(os.path.dirname(os.path.abspath(self._path)), exist_ok=True)
        key = secrets.token_bytes(32)
        try:
            fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            existing = self._read_key()
            if existing is None:
                raise TotpVaultError("the TOTP key file exists but is unreadable or malformed") from None
            return existing
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(key.hex() + "\n")
        return key

    def encrypt(self, secret: bytes, user_id: int) -> str:
        key = self._key_for_encrypt()
        nonce = secrets.token_bytes(12)
        blob = AESGCM(key).encrypt(nonce, secret, self._aad(user_id))
        return _VAULT_PREFIX + base64.b64encode(nonce + blob).decode()

    def decrypt(self, token: str, user_id: int) -> bytes:
        if not isinstance(token, str) or not token.startswith(_VAULT_PREFIX):
            raise TotpVaultError("not a vault token")
        key = self._read_key()               # re-read: never invent a key on the decrypt path
        if key is None:
            raise TotpVaultError("TOTP key file is missing or unreadable")
        try:
            raw = base64.b64decode(token[len(_VAULT_PREFIX):], validate=True)
            return AESGCM(key).decrypt(raw[:12], raw[12:], self._aad(user_id))
        except (InvalidTag, ValueError):
            raise TotpVaultError("TOTP secret failed authentication") from None

    @staticmethod
    def _aad(user_id: int) -> bytes:
        return f"spectra-totp:{int(user_id)}".encode()
