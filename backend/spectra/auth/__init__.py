"""Authentication primitives (no HTTP, no persistence): password hashing.

The service that orchestrates logins, sessions and user management lives in
:mod:`spectra.services.auth`; the role/permission vocabulary lives in
:mod:`spectra.authz`.
"""

from __future__ import annotations

from .passwords import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    check_password_policy,
    hash_password,
    password_needs_rehash,
    verify_dummy,
    verify_password,
)

__all__ = [
    "MAX_PASSWORD_LENGTH",
    "MIN_PASSWORD_LENGTH",
    "check_password_policy",
    "hash_password",
    "password_needs_rehash",
    "verify_dummy",
    "verify_password",
]
