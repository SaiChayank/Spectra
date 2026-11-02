"""Local authentication: logins, expiring sessions, users, bootstrap.

Design notes (production-style, deliberately free of identity infrastructure):

* **Hashing** - scrypt from the stdlib (:mod:`spectra.auth.passwords`), a
  random salt per password, self-describing encodings. No plaintext password
  ever reaches storage, logs or a response.
* **Sessions** - a random 256-bit bearer token issued at login; only its
  SHA-256 hash is stored, so a leaked database cannot be replayed as a
  login. The raw token exists solely in the client's HttpOnly cookie (or an
  ``Authorization: Bearer`` header / ``?token=`` for scripts and the event
  WebSocket). Lifetime is an absolute TTL (``session_ttl_minutes``); expired
  rows are deleted on the next validation *and* opportunistically on login.
* **Enumeration resistance** - unknown username and wrong password return one
  indistinguishable 401, and the unknown path still runs a full scrypt
  verification (``verify_dummy``) so timing does not reveal which accounts
  exist. Login never applies the password *policy* (that would leak it).
* **Store binding** - the store is fixed at construction: users and sessions
  belong to the database the API was started with. The engine's ``store``
  rebinding seam (used by API tests to share a temporary store) deliberately
  does not fan out to auth, so sessions issued by this process stay valid for
  its whole lifetime whatever fixture swaps data underneath it.
* **Bootstrap** - the first admin is created only while the users table is
  empty: password from ``SPECTRA_ADMIN_PASSWORD`` if it meets the policy,
  otherwise a generated secret written to a mode-restricted file under the
  data directory (never logged).
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import secrets
import time

from ..auth import (
    check_password_policy,
    hash_password,
    password_needs_rehash,
    verify_dummy,
    verify_password,
)
from ..authz import ADMIN, ROLES, permissions_for
from ..config import Config, get_config
from ..store import Store, StoreError

log = logging.getLogger("spectra.auth")

#: Session cookie name (HttpOnly, SameSite=Lax, path=/).
SESSION_COOKIE = "spectra_session"

#: The one message every failed login returns - never "no such user".
INVALID_CREDENTIALS = "invalid username or password"
#: Returned when no valid session backs a protected request.
UNAUTHENTICATED = "not authenticated"
#: Returned when the presented session row exists but passed its TTL, so the
#: dashboard can distinguish "your session expired" from "log in".
SESSION_EXPIRED = "session expired"

#: username: 3-32 chars, alphanumeric first, then [_.-] allowed.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$")

#: Seconds of inactivity before a session's last-seen is written again
#: (avoids one UPDATE per request; expiry itself is absolute, not idle).
_TOUCH_INTERVAL = 60.0


class AuthError(Exception):
    """Mapped to an HTTP error by the routers (``status_code``/``detail``)."""

    status_code = 400
    default_detail = "authentication error"

    def __init__(self, detail: str | None = None):
        self.detail = self.default_detail if detail is None else detail
        super().__init__(self.detail)


class AuthUnavailable(AuthError):
    """Persistence is off: sessions cannot be issued or validated."""

    status_code = 503
    default_detail = "authentication requires persistence to be enabled"


class CredentialsError(AuthError):
    """Wrong username *or* password - one shared, generic failure."""

    status_code = 401
    default_detail = INVALID_CREDENTIALS


class SessionExpired(AuthError):
    status_code = 401
    default_detail = SESSION_EXPIRED


class InvalidUser(AuthError):
    status_code = 404
    default_detail = "user not found"


class UsernameTaken(AuthError):
    status_code = 409
    default_detail = "username already exists"


class UserPolicyError(AuthError):
    """Bad username/password/role supplied to create/update (422)."""

    status_code = 422


class UserGuardError(AuthError):
    """Structural guard: self-deletion or removing the last admin (409)."""

    status_code = 409


def hash_token(token: str) -> str:
    """SHA-256 hex digest of a raw session token (what storage keeps)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class LoginThrottle:
    """Sliding-window failed-login meter (per client ip + username).

    Online password guessing is the one attack the local account store
    cannot answer with key material, so repeated failures from one source
    are shed with 429 + ``Retry-After`` before any scrypt work runs.
    Keys are the *(ip, username)* pair - a spray across many usernames from
    one ip is capped by the per-ip bucket, while distinct sources each get
    their own budget (no shared-lockout amplification against a victim).
    Counts only :class:`CredentialsError`: policy/unavailability failures
    never lock anyone out, and a successful login clears its key.  Memory
    is bounded: buckets expire with the window and the table is pruned on
    every check.
    """

    def __init__(self, limit: int = 10, ip_limit: int = 40,
                 window: float = 60.0):
        self.limit = limit
        self.ip_limit = ip_limit
        self.window = window
        self._failures: dict[tuple[str, str], list[float]] = {}
        self._ip_failures: dict[str, list[float]] = {}

    @staticmethod
    def _prune(bucket: list[float], now: float, window: float) -> list[float]:
        cutoff = now - window
        kept = [t for t in bucket if t > cutoff]
        return kept

    def retry_after(self, ip: str, username: str) -> float | None:
        """Seconds to wait when blocked, else ``None`` (allowed to try)."""
        now = time.monotonic()
        key = (ip, username.casefold())
        self._failures[key] = self._prune(
            self._failures.get(key, []), now, self.window)
        self._ip_failures[ip] = self._prune(
            self._ip_failures.get(ip, []), now, self.window)
        waits = [self._unblock_time(self._failures[key], self.limit, now),
                 self._unblock_time(self._ip_failures[ip], self.ip_limit, now)]
        blocked = [w for w in waits if w is not None]
        if not blocked:
            return None
        # Both buckets must fall under their limits; wait for the slower one.
        return max(1.0, max(blocked))

    def _unblock_time(self, bucket: list[float], limit: int,
                      now: float) -> float | None:
        """When ``bucket`` drops below ``limit`` entries, or ``None``."""
        if len(bucket) < limit:
            return None
        # Ascending timestamps: dropping len-limit+1 oldest entries frees the
        # bucket, i.e. when the entry at index len-limit slides out of window.
        return max(1.0, bucket[len(bucket) - limit] + self.window - now)

    def record_failure(self, ip: str, username: str) -> None:
        now = time.monotonic()
        key = (ip, username.casefold())
        self._failures.setdefault(key, []).append(now)
        self._ip_failures.setdefault(ip, []).append(now)
        if len(self._failures) > 4096:  # table bound (hostile key spraying)
            self._prune_table(now)

    def record_success(self, ip: str, username: str) -> None:
        self._failures.pop((ip, username.casefold()), None)

    def reset(self) -> None:
        """Drop all state (test/fixture hygiene)."""
        self._failures.clear()
        self._ip_failures.clear()

    def _prune_table(self, now: float) -> None:
        expired = []
        for key, value in self._failures.items():
            self._failures[key] = pruned = self._prune(
                value, now, self.window)
            if not pruned:
                expired.append(key)
        for key in expired:
            del self._failures[key]
        expired_ips = []
        for ip, value in self._ip_failures.items():
            self._ip_failures[ip] = pruned = self._prune(
                value, now, self.window)
            if not pruned:
                expired_ips.append(ip)
        for ip in expired_ips:
            del self._ip_failures[ip]


class AuthService:
    """Login/session/user lifecycle for the local accounts (see module doc)."""

    def __init__(self, store: Store | None, config: Config | None = None):
        self.store = store
        self.config = config or get_config()
        #: Failed-login limiter consulted by the login route *before* scrypt.
        self.throttle = LoginThrottle()

    # -- availability / session lifetime --------------------------------------

    @property
    def available(self) -> bool:
        return self.store is not None

    @property
    def ttl_seconds(self) -> float:
        return max(60.0, float(self.config.session_ttl_minutes) * 60.0)

    # -- bootstrap ------------------------------------------------------------

    def bootstrap(self) -> dict | None:
        """Create the first admin while the users table is empty.

        Returns the new public user, or ``None`` when an account already
        exists (bootstrap runs once per database) or persistence is off.
        """
        if self.store is None or self.store.count_users() > 0:
            return None
        username = (self.config.admin_username or "admin").strip() or "admin"
        password = os.environ.get("SPECTRA_ADMIN_PASSWORD", "").strip()
        generated = False
        if password:
            try:
                check_password_policy(password)
            except ValueError:
                log.warning(
                    "SPECTRA_ADMIN_PASSWORD fails the password policy; "
                    "generating a one-time password instead")
                password = ""
        if not password:
            password = secrets.token_urlsafe(18)
            generated = True
        try:
            user = self.store.create_user(username, hash_password(password),
                                          ADMIN)
        except StoreError as exc:  # UNIQUE: a racing process bootstrapped
            log.warning("bootstrap skipped: %s", exc)
            return None
        if generated:
            path = self._write_bootstrap_file(username, password)
            log.warning(
                "bootstrapped admin '%s'; one-time password written to %s "
                "(restricted permissions) - sign in, change it, then delete "
                "that file", username, path)
        else:
            log.info("bootstrapped admin '%s' from SPECTRA_ADMIN_PASSWORD",
                     username)
        return user

    def _write_bootstrap_file(self, username: str, password: str) -> str:
        """Write initial credentials to a mode-600 file (best effort)."""
        path = os.path.join(self.config.data_dir, "admin_bootstrap.txt")
        os.makedirs(self.config.data_dir, exist_ok=True)
        payload = (
            "# Spectra initial admin credentials - delete this file after the\n"
            "# first sign-in / password change (it is a one-time secret).\n"
            f"username={username}\n"
            f"password={password}\n"
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, payload.encode("utf-8"))
        finally:
            os.close(fd)
        try:
            os.chmod(path, 0o600)  # Windows: best effort, POSIX: restrictive
        except OSError:  # pragma: no cover - platform dependent
            pass
        return path

    # -- login / sessions -----------------------------------------------------

    def login(self, username: str, password: str) -> tuple[dict, str, float]:
        """Verify credentials and open a session.

        Returns ``(public_user, raw_token, expires_at)``. An unknown username
        performs the same scrypt work as a real one before failing with the
        same generic 401 (anti-enumeration).
        """
        if self.store is None:
            raise AuthUnavailable()
        creds = self.store.find_user_credentials(username)
        if creds is None:
            verify_dummy(password)
            raise CredentialsError()
        if not verify_password(password, creds["password_hash"]):
            raise CredentialsError()
        if password_needs_rehash(creds["password_hash"]):
            # Store-level write (no session revocation): the row is upgraded
            # in place to the current work factor right after its own proof,
            # so pre-hardening accounts reach the stronger parameters on the
            # first successful login instead of never.
            try:
                self.store.update_user(
                    creds["id"], password_hash=hash_password(password))
                log.info("upgraded password hash parameters for '%s'",
                         creds["username"])
            except StoreError:  # pragma: no cover - login must not fail here
                log.warning("password rehash failed for '%s'",
                            creds["username"], exc_info=True)
        now = time.time()
        self.store.purge_expired_sessions(now)  # opportunistic housekeeping
        token = secrets.token_urlsafe(32)
        expires_at = now + self.ttl_seconds
        self.store.create_session(creds["id"], hash_token(token), expires_at)
        self.store.set_user_login_time(creds["id"])
        user = self.store.get_user(creds["id"])
        if user is None:  # pragma: no cover - row was read moments ago
            raise CredentialsError()
        return user, token, expires_at

    def validate(self, token: str) -> dict | None:
        """Resolve a raw session token to a principal (internal shape).

        Returns ``None`` for an unknown/deleted session and raises
        :class:`SessionExpired` when the row outlived its TTL - both become
        401 at the HTTP layer with different detail. The returned dict is for
        server-side use only: it carries the token hash and must never be
        serialized to a response as-is.
        """
        if self.store is None or not token:
            return None
        token_hash = hash_token(token)
        row = self.store.get_session(token_hash)
        if row is None:
            return None
        now = time.time()
        if float(row["expires_at"]) <= now:
            self.store.delete_session(token_hash)
            raise SessionExpired()
        user = self.store.get_user(row["user_id"])
        if user is None:  # account deleted under a live session
            self.store.delete_session(token_hash)
            return None
        if now - float(row["last_seen_at"]) > _TOUCH_INTERVAL:
            self.store.touch_session(token_hash, now)
        return {
            "user_id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "permissions": permissions_for(user["role"]),
            "session": {
                "expires_at": float(row["expires_at"]),
                "token_hash": token_hash,
            },
        }

    def logout(self, token_hash: str) -> None:
        """Delete the session row behind ``token_hash`` (idempotent).

        The caller passes the hash already resolved from the principal -
        logout must not need the raw token (it is HttpOnly in the cookie).
        """
        if self.store is None or not token_hash:
            return
        self.store.delete_session(token_hash)

    # -- user management ------------------------------------------------------

    def list_users(self) -> list[dict]:
        self._require_store()
        return self.store.list_users()

    def get_user(self, user_id: int) -> dict:
        self._require_store()
        user = self.store.get_user(user_id)
        if user is None:
            raise InvalidUser()
        return user

    def create_user(self, username: str, password: str, role: str) -> dict:
        """Create an account (policy-checked, duplicate-safe)."""
        self._require_store()
        username = (username or "").strip()
        if not _USERNAME_RE.match(username):
            raise UserPolicyError(
                "username must be 3-32 characters, start with a letter or "
                "digit, and contain only letters, digits, '_', '.' or '-'")
        if role not in ROLES:
            raise UserPolicyError(
                f"role must be one of {', '.join(ROLES)}")
        try:
            check_password_policy(password)
        except ValueError as exc:
            raise UserPolicyError(str(exc)) from exc
        if self.store.find_user_credentials(username) is not None:
            raise UsernameTaken()
        try:
            return self.store.create_user(username, hash_password(password),
                                          role)
        except StoreError as exc:
            if "UNIQUE" in str(exc):  # raced another create of the same name
                raise UsernameTaken() from exc
            raise

    def update_user(self, user_id: int, *, role: str | None = None,
                    password: str | None = None) -> dict:
        """Apply a role and/or password change.

        A password change revokes **every** session of that account, so an
        attacker holding an old session token loses access immediately (the
        caller's own session included when an admin rotates their password).
        A role change needs no revocation: each request re-reads the role.
        """
        self._require_store()
        user = self.store.get_user(user_id)
        if user is None:
            raise InvalidUser()
        if role is None and password is None:
            raise UserPolicyError(
                "nothing to update: provide a role and/or a password")
        if role is not None and role not in ROLES:
            raise UserPolicyError(f"role must be one of {', '.join(ROLES)}")
        if (role is not None and role != "ADMIN"
                and user["role"] == "ADMIN"
                and self.store.count_admin_users() <= 1):
            raise UserGuardError("cannot demote the last ADMIN account")
        password_hash = None
        if password is not None:
            try:
                check_password_policy(password)
            except ValueError as exc:
                raise UserPolicyError(str(exc)) from exc
            password_hash = hash_password(password)
        updated = self.store.update_user(user_id, role=role,
                                         password_hash=password_hash)
        if updated is None:
            raise InvalidUser()
        if password_hash is not None:
            revoked = self.store.invalidate_user_sessions(user_id)
            log.info("password changed for '%s'; revoked %d session(s)",
                     updated["username"], revoked)
        return updated

    def delete_user(self, user_id: int, actor_id: int | None = None) -> None:
        """Delete an account (sessions cascade); guards self/last-admin."""
        self._require_store()
        user = self.store.get_user(user_id)
        if user is None:
            raise InvalidUser()
        if actor_id is not None and user_id == actor_id:
            raise UserGuardError("you cannot delete your own account")
        if user["role"] == "ADMIN" and self.store.count_admin_users() <= 1:
            raise UserGuardError("cannot delete the last ADMIN account")
        self.store.delete_user(user_id)

    # -- internals ------------------------------------------------------------

    def _require_store(self) -> None:
        if self.store is None:
            raise AuthUnavailable()
