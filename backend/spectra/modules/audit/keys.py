"""Audit signing-key provider seam (Phase 9F).

``AuditLog`` never holds a secret: it asks a provider to sign and to say what
its public key is.  Swapping the file-backed provider for a KMS/HSM one is one
class implementing :class:`AuditKeyProvider`; nothing else in the audit code
changes.

Contract (all a provider must honour):

* ``public_key()`` - the *current* key's compressed secp256k1 point, hex, the
  same form ``schnorr_verify`` takes;
* ``sign(msg)`` - a Schnorr signature (``curve.schnorr_sign`` format) by the
  current key over ``msg``; the secret never leaves the provider;
* ``rotate()`` - switch to a brand-new key and return its public key.  After
  it returns, ``sign`` must use the new key only.  The audit log records the
  rotation (epoch + chain entry) *after* this returns; a crash in between is
  repaired on the next start, which registers the unrecorded key as a new
  epoch (loudly, with a chain entry).

No cloud dependency ships in v1; this file-backed provider is the only one.
"""

from __future__ import annotations

import os
import threading
from typing import Protocol, runtime_checkable

from .curve import G, N as N_ORDER, compress, pt_mul, schnorr_keypair, schnorr_sign

KEY_FILE = "audit_signing.key"


@runtime_checkable
class AuditKeyProvider(Protocol):
    def public_key(self) -> str: ...

    def sign(self, msg: bytes) -> str: ...

    def rotate(self) -> str: ...


def _pub_from_secret(secret_hex: str) -> str:
    x = int(secret_hex, 16)
    if not (0 < x < N_ORDER):
        raise ValueError("stored signing key is out of range")
    return compress(pt_mul(x, G))


class FileKeyProvider:
    """The v1 provider: one hex secret in a mode-0600 file (or in memory)."""

    def __init__(self, path: str | None) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._secret, self._pub = self._load_or_create()

    # -- AuditKeyProvider ------------------------------------------------------

    def public_key(self) -> str:
        return self._pub

    def sign(self, msg: bytes) -> str:
        with self._lock:
            return schnorr_sign(self._secret, msg)

    def rotate(self) -> str:
        with self._lock:
            secret, pub = schnorr_keypair()
            self._write(secret)
            self._secret, self._pub = secret, pub
            return pub

    # -- storage ----------------------------------------------------------------

    def _load_or_create(self) -> tuple[str, str]:
        path = self._path
        if path and os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    secret = fh.read().strip()
                if secret:
                    return secret, _pub_from_secret(secret)
            except (OSError, ValueError):
                pass  # unreadable or invalid: fall through to a fresh key
        secret, pub = schnorr_keypair()
        self._write(secret)
        return secret, pub

    def _write(self, secret: str) -> None:
        """Atomically replace the key file; it is never visible with wider modes."""
        path = self._path
        if not path:
            return
        tmp = f"{path}.tmp"
        try:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(secret + "\n")
            os.replace(tmp, path)
        except OSError:  # pragma: no cover - read-only dirs: ephemeral key
            try:
                os.unlink(tmp)
            except OSError:
                pass
