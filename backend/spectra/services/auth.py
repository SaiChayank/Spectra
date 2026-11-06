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

from ..auth import totp
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


def _totp_now() -> float:
    """Clock for second-factor checks (a seam: tests pin it)."""
    return time.time()


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


class TotpStateError(AuthError):
    """Enrolment is in the wrong state for the request (409)."""

    status_code = 409
    default_detail = "two-factor state conflict"


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


class _Meter:
    """Failures per key -> escalating, self-expiring blocks.

    ``limit`` failures inside ``window`` start a block of ``window`` seconds;
    each further episode doubles it, up to ``max_block``.  Strikes persist
    after a block ends and are forgotten once the key has been quiet for
    ``strike_ttl`` seconds (or on a success), so no key stays blocked longer
    than ``max_block`` and nothing is permanent.  Tables are bounded.
    """

    MAX_KEYS = 10_000

    def __init__(self, limit: int, window: float, max_block: float,
                 strike_ttl: float, clock) -> None:
        self.limit, self.window = limit, window
        self.max_block, self.strike_ttl = max_block, strike_ttl
        self.clock = clock
        self.events: dict = {}      # key -> failure times inside the window
        self.blocks: dict = {}      # key -> {"until": t, "strikes": n}

    def wait(self, key, now: float) -> float | None:
        block = self.blocks.get(key)
        if block is not None and block["until"] > now:
            return block["until"] - now
        return None

    def fail(self, key, now: float) -> None:
        block = self.blocks.get(key)
        if block is not None and block["until"] > now:
            return                      # already blocked: attempts do not extend it
        if block is not None and now - block["until"] > self.strike_ttl:
            del self.blocks[key]        # quiet long enough: forgiven
            block = None
        times = [t for t in self.events.get(key, ()) if t > now - self.window]
        times.append(now)
        if len(times) >= self.limit:
            strikes = (block["strikes"] if block else 0) + 1
            length = min(self.window * 2 ** (strikes - 1), self.max_block)
            self.blocks.pop(key, None)  # re-insert last: dict order = recency
            self.blocks[key] = {"until": now + length, "strikes": strikes}
            self.events.pop(key, None)
        else:
            self.events[key] = times
        if len(self.events) > self.MAX_KEYS or len(self.blocks) > self.MAX_KEYS:
            self._shrink(now)

    def success(self, key) -> None:
        self.events.pop(key, None)
        self.blocks.pop(key, None)

    def clear(self) -> None:
        self.events.clear()
        self.blocks.clear()

    def _shrink(self, now: float) -> None:
        for key in [k for k, v in self.events.items()
                    if not v or v[-1] <= now - self.window]:
            del self.events[key]
        for key in [k for k, v in self.blocks.items()
                    if now - v["until"] > self.strike_ttl]:
            del self.blocks[key]
        # ponytail: if >MAX_KEYS keys are still live (a hostile spray) the oldest
        # are dropped, which can forget a block; the per-ip meter bounds how fast
        # one source can create keys.  Upgrade: a sketch / LRU with a real budget.
        for table in (self.events, self.blocks):
            while len(table) > self.MAX_KEYS:
                del table[next(iter(table))]


class LoginThrottle:
    """Escalating failed-login throttle (per client ip + username, and per ip).

    Online password guessing is the one attack the local account store
    cannot answer with key material, so repeated failures from one source
    are shed with 429 + ``Retry-After`` before any scrypt work runs.  The
    first episode blocks for ``window`` seconds; each repeat doubles the
    block up to ``max_block`` (see :class:`_Meter`).

    Properties (tested in ``test_login_backoff.py``):

    * keys are *(ip, username)* and *ip*, never the username alone, so an
      attacker cannot lock the real admin out of other networks (no
      shared-lockout amplification) - **but** behind a reverse proxy every
      client shares the proxy's address, so one guesser can block them all
      until the block expires (at most ``max_block``); trusting
      ``X-Forwarded-For`` is a separate, deliberate setting and is not done;
    * the decision depends only on the source and the *attempted* name, never
      on whether the account exists, and blocked attempts are not counted
      again (no extension attacks);
    * no block is permanent: it expires, strikes decay after ``strike_ttl``,
      a success clears them, and a restart clears everything - that is the
      recovery path for a locked-out only admin on a single host;
    * counts only :class:`CredentialsError`: policy/unavailability failures
      never lock anyone out.
    """

    def __init__(self, limit: int = 10, ip_limit: int = 40,
                 window: float = 60.0, max_block: float = 900.0,
                 strike_ttl: float = 3600.0, clock=time.monotonic):
        self.limit = limit
        self.ip_limit = ip_limit
        self.window = window
        self.clock = clock
        self._pair = _Meter(limit, window, max_block, strike_ttl, clock)
        self._ip = _Meter(ip_limit, window, max_block, strike_ttl, clock)

    def retry_after(self, ip: str, username: str) -> float | None:
        """Seconds to wait when blocked, else ``None`` (allowed to try)."""
        now = self.clock()
        waits = [w for w in (self._pair.wait((ip, username.casefold()), now),
                             self._ip.wait(ip, now)) if w is not None]
        return max(1.0, max(waits)) if waits else None

    def record_failure(self, ip: str, username: str) -> None:
        now = self.clock()
        self._pair.fail((ip, username.casefold()), now)
        self._ip.fail(ip, now)

    def record_success(self, ip: str, username: str) -> None:
        self._pair.success((ip, username.casefold()))

    def reset(self) -> None:
        """Drop all state (test/fixture hygiene; what a restart does)."""
        self._pair.clear()
        self._ip.clear()


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

    def login(self, username: str, password: str,
              totp_code: str | None = None) -> tuple[dict, str, float]:
        """Verify credentials and open a session.

        Returns ``(public_user, raw_token, expires_at)``. An unknown username
        performs the same scrypt work as a real one before failing with the
        same generic 401 (anti-enumeration).  An account with a second factor
        enabled needs ``totp_code`` (an authenticator code or a recovery code)
        in the *same* request; a missing or wrong one fails with the same
        generic 401 and is counted by the throttle, so the response never
        reveals that the password was right or that the account has a factor.
        """
        if self.store is None:
            raise AuthUnavailable()
        creds = self.store.find_user_credentials(username)
        if creds is None:
            verify_dummy(password)
            raise CredentialsError()
        if not verify_password(password, creds["password_hash"]):
            raise CredentialsError()
        self._check_second_factor(creds["id"], totp_code)
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

    # -- optional TOTP second factor ---------------------------------------------

    @property
    def _vault(self) -> totp.TotpVault:
        vault = getattr(self, "_totp_vault", None)
        if vault is None or vault._path != self.config.totp_key_path:
            vault = self._totp_vault = totp.TotpVault(self.config.totp_key_path)
        return vault

    def totp_enabled(self, user_id: int) -> bool:
        row = self.store.totp_get(user_id) if self.store is not None else None
        return bool(row and row["enabled"])

    def _check_second_factor(self, user_id: int, code: str | None) -> None:
        """No-op for accounts without TOTP; else the code must be valid and fresh."""
        row = self.store.totp_get(user_id)
        if not row or not row["enabled"]:
            return
        if not code or not self._accept_code(user_id, row, code):
            raise CredentialsError()

    def _accept_code(self, user_id: int, row: dict, code: str) -> bool:
        """True and consumed if ``code`` is a valid authenticator or recovery code."""
        if totp.looks_like_recovery(code):        # 12 hex chars; a TOTP code is exactly 6 digits
            return self.store.totp_consume_recovery(user_id, totp.hash_recovery(code))
        try:
            secret = self._vault.decrypt(row["secret_enc"], user_id)
        except totp.TotpVaultError:
            log.error("TOTP secret for user id %s is undecryptable (key file lost or changed); "
                      "reset with: spectra auth totp-reset <username>", user_id)
            return False
        counter = totp.verify(secret, code, _totp_now(), int(row["last_counter"]))
        return counter is not None and self.store.totp_advance(user_id, counter)

    def _credentials(self, username: str, password: str) -> dict:
        creds = self.store.find_user_credentials(username)
        if creds is None:
            verify_dummy(password)
            raise CredentialsError()
        if not verify_password(password, creds["password_hash"]):
            raise CredentialsError()
        return creds

    def totp_begin(self, username: str, password: str, issuer: str | None = None) -> dict:
        """Start enrolment (password re-entry required): returns the secret once."""
        if self.store is None:
            raise AuthUnavailable()
        creds = self._credentials(username, password)
        if self.totp_enabled(creds["id"]):
            raise TotpStateError("two-factor authentication is already enabled")
        secret = totp.new_secret()
        self.store.totp_put_pending(creds["id"], self._vault.encrypt(secret, creds["id"]))
        b32 = totp.to_base32(secret)
        issuer = issuer or self.config.totp_issuer
        return {"secret": b32, "issuer": issuer,
                "otpauth_uri": totp.provisioning_uri(b32, creds["username"], issuer)}

    def totp_confirm(self, user_id: int, code: str) -> list[str]:
        """Enable the pending enrolment with a first valid code; returns recovery codes."""
        row = self.store.totp_get(user_id)
        if row is None or row["enabled"]:
            raise TotpStateError("no pending two-factor enrolment")
        try:
            secret = self._vault.decrypt(row["secret_enc"], user_id)
        except totp.TotpVaultError:
            raise TotpStateError("the pending enrolment cannot be read; start again") from None
        counter = totp.verify(secret, code, _totp_now(), int(row["last_counter"]))
        if counter is None:
            raise CredentialsError("invalid code")
        codes = totp.new_recovery_codes()
        if not self.store.totp_enable(user_id, counter, [totp.hash_recovery(c) for c in codes]):
            raise TotpStateError("no pending two-factor enrolment")
        return codes

    def totp_disable(self, username: str, password: str, code: str) -> dict:
        """Turn the factor off (password + a valid code or recovery code)."""
        if self.store is None:
            raise AuthUnavailable()
        creds = self._credentials(username, password)
        row = self.store.totp_get(creds["id"])
        if not row or not row["enabled"]:
            raise TotpStateError("two-factor authentication is not enabled")
        if not code or not self._accept_code(creds["id"], row, code):
            raise CredentialsError("invalid code")
        self.store.totp_delete(creds["id"])
        return {"username": creds["username"]}

    def totp_reset(self, user_id: int) -> dict:
        """Operator/admin reset (no factor needed): removes enrolment and recovery codes."""
        user = self.get_user(user_id)
        self.store.totp_delete(user_id)
        return user

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
