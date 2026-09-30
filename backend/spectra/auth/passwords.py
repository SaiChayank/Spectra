"""Local authentication primitives: password hashing (stdlib scrypt only).

No third-party crypto dependency: :func:`hashlib.scrypt` (memory-hard, part of
the standard library's OpenSSL bindings) with a per-password random salt.
The stored encoding is self-describing so parameters can evolve without
invalidating existing hashes::

    scrypt$<n>$<r>$<p>$<salt_b64>$<hash_b64>

Verification never raises on malformed input (a corrupt row simply fails to
verify), and :func:`verify_dummy` gives callers the *same* CPU cost for an
unknown username as for a real one, so login timing cannot be used to
enumerate accounts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

#: scrypt work factors (n=16384 => ~16 MiB and ~50-100 ms per hash on
#: commodity hardware: strong for a local service without slowing logins).
_N = 2 ** 14
_R = 8
_P = 1
_DKLEN = 32
_MAXMEM = 64 * 1024 * 1024  # explicit headroom over the 16 MiB the KDF needs

#: Password policy bounds (enforced when a password is *set*, never at login -
#: the login path must not reveal policy details to an unauthenticated caller).
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 1024

_FORMAT = "scrypt"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
        dklen=_DKLEN, maxmem=_MAXMEM,
    )


def hash_password(password: str) -> str:
    """Hash a password for storage. Never returns the password itself."""
    salt = secrets.token_bytes(16)
    digest = _derive(password, salt, _N, _R, _P)
    return f"{_FORMAT}${_N}${_R}${_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    """Constant-compare check of ``password`` against a stored encoding."""
    try:
        algo, n, r, p, salt_b64, hash_b64 = encoded.split("$")
        if algo != _FORMAT:
            return False
        salt = base64.b64decode(salt_b64, validate=True)
        expected = base64.b64decode(hash_b64, validate=True)
        actual = _derive(password, salt, int(n), int(r), int(p))
    except (ValueError, TypeError, UnicodeError):
        return False  # corrupt/foreign row: fail closed, never raise
    return hmac.compare_digest(actual, expected)


# A fixed dummy hash so an unknown-username login performs the same scrypt
# work as a real one (anti user-enumeration). Computed lazily: one hash on
# the first unknown login instead of at import time for every process.
_DUMMY_ENCODED: str | None = None


def verify_dummy(password: str) -> bool:
    """Burn the same CPU cost as :func:`verify_password`; always False."""
    global _DUMMY_ENCODED
    if _DUMMY_ENCODED is None:
        _DUMMY_ENCODED = hash_password("spectra-dummy-credential")
    return verify_password(password, _DUMMY_ENCODED)


def check_password_policy(password: str) -> None:
    """Raise ``ValueError`` when a password may not be *set*.

    Login deliberately does not call this: rejecting short passwords there
    would tell an attacker which accounts exist before they authenticate.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(
            f"password must be at most {MAX_PASSWORD_LENGTH} characters")
