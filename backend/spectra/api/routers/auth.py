"""Authentication routes: login, logout, current user.

Login is one of the two public routes (see ``PUBLIC_ROUTES``); logout and
``me`` require a session like everything else. Responses carry identity and
permissions only - never the password hash, the raw token, or the token
hash that storage keeps.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from ...services.auth import AuthError, CredentialsError
from ..runtime import engine
from ..schemas import Out
from ..security import (
    auth_error,
    clear_session_cookie,
    identity_payload,
    public_principal,
    require,
    set_session_cookie,
)

router = APIRouter()


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)
    #: authenticator code or recovery code; required only for accounts that
    #: enabled two-factor - sent in the same request so the response never
    #: reveals whether a password was right or a factor exists
    totp_code: str | None = Field(None, max_length=32)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    #: same bounds as user creation / PATCH; the service re-runs the full policy
    new_password: str = Field(min_length=8, max_length=1024)
    #: needed only when the account has two-factor enabled (same rule as login)
    totp_code: str | None = Field(None, max_length=32)


class TotpSetupRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


class TotpEnableRequest(BaseModel):
    code: str = Field(min_length=1, max_length=32)


class TotpDisableRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)
    code: str = Field(min_length=1, max_length=32)


class Identity(Out):
    id: int
    username: str
    role: str
    permissions: list[str]
    totp_enabled: bool


class IdentityResponse(Out):
    user: Identity
    expires_at: float


class OkResponse(Out):
    ok: bool


class PasswordChanged(Out):
    ok: bool
    sign_in_required: bool


class TotpSetup(Out):
    secret: str
    issuer: str
    otpauth_uri: str


class TotpRecovery(Out):
    recovery_codes: list[str]


class TotpDisabled(Out):
    totp_enabled: bool


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/api/auth/login", response_model=IdentityResponse)
def auth_login(req: LoginRequest, response: Response,
               request: Request) -> dict:
    """Open a session; sets the HttpOnly cookie and returns the identity.

    Unknown username and wrong password answer the same generic 401 (the
    service burns identical scrypt work for both), so this endpoint cannot
    be used to enumerate accounts.  Repeated failures from one source are
    shed with 429 + ``Retry-After`` *before* any scrypt work runs (the
    throttle keys on ip + username, so neither a spray nor a targeted guess
    loop gets unlimited attempts).  Failed attempts are deliberately not
    audited: the audit log is never pruned, and unauthenticated writes into
    it would be an unbounded amplification path.
    """
    ip = _client_ip(request)
    wait = engine.auth.throttle.retry_after(ip, req.username)
    if wait is not None:
        raise HTTPException(
            status_code=429,
            detail="too many failed login attempts",
            headers={"Retry-After": str(int(wait) + 1)})
    try:
        user, token, expires_at = engine.auth.login(
            req.username, req.password, req.totp_code)
    except CredentialsError as exc:
        engine.auth.throttle.record_failure(ip, req.username)
        raise auth_error(exc) from exc
    except AuthError as exc:  # persistence off (503) and friends
        raise auth_error(exc) from exc
    engine.auth.throttle.record_success(ip, req.username)
    set_session_cookie(response, token)
    engine.audit_service.append(
        "auth.login", {"username": user["username"]},
        actor=user["username"])
    return identity_payload(user, expires_at, engine.auth.totp_enabled(user["id"]))


@router.post("/api/auth/logout", response_model=OkResponse)
def auth_logout(response: Response,
                principal: dict = Depends(require("read"))) -> dict:
    """Invalidate the caller's session and clear the cookie (idempotent)."""
    engine.auth.logout(principal["session"]["token_hash"])
    clear_session_cookie(response)
    engine.audit_service.append(
        "auth.logout", {"username": principal["username"]},
        actor=principal["username"])
    return {"ok": True}


@router.get("/api/auth/me", response_model=IdentityResponse)
def auth_me(principal: dict = Depends(require("read"))) -> dict:
    """The signed-in identity: username, role, permissions, expiry."""
    return public_principal(principal, engine.auth.totp_enabled(principal["user_id"]))


@router.post("/api/auth/password", response_model=PasswordChanged)
def auth_password(req: PasswordChangeRequest, request: Request,
                  response: Response,
                  principal: dict = Depends(require("read"))) -> dict:
    """Change the caller's own password (any role; needs the current one).

    Wrong current password (or missing/wrong TOTP code) answers a generic 403
    and counts toward the login throttle for (ip, username), so a stolen
    session cannot be used to guess the password; once throttled: 429 +
    ``Retry-After`` before any scrypt work.  Success revokes every session of
    the user (this one included), clears the cookie and audits the change
    (never the password).  401 is left to mean "no/expired session" so the
    dashboard's global 401 handler is not triggered by a typo.
    """
    username, ip = principal["username"], _client_ip(request)
    wait = engine.auth.throttle.retry_after(ip, username)
    if wait is not None:
        raise HTTPException(status_code=429, detail="too many failed attempts",
                            headers={"Retry-After": str(int(wait) + 1)})
    try:
        engine.auth.change_own_password(
            principal["user_id"], req.current_password, req.new_password,
            req.totp_code)
    except CredentialsError as exc:
        engine.auth.throttle.record_failure(ip, username)
        raise HTTPException(status_code=403,
                            detail="current password is incorrect") from exc
    except AuthError as exc:
        raise auth_error(exc) from exc
    engine.auth.throttle.record_success(ip, username)
    clear_session_cookie(response)
    engine.audit_service.append(
        "auth.password_changed", {"username": username}, actor=username)
    return {"ok": True, "sign_in_required": True}


# -- optional TOTP second factor (self-service) ---------------------------------------
# Password re-entry guards setup/disable (a stolen session alone cannot enrol its
# own authenticator or strip the owner's), and wrong passwords/codes feed the same
# throttle as login, so none of these is a free guessing oracle.

def _throttled(request: Request, username: str, action):
    ip = _client_ip(request)
    wait = engine.auth.throttle.retry_after(ip, username)
    if wait is not None:
        raise HTTPException(status_code=429, detail="too many failed attempts",
                            headers={"Retry-After": str(int(wait) + 1)})
    try:
        return action()
    except CredentialsError as exc:
        engine.auth.throttle.record_failure(ip, username)
        raise auth_error(exc) from exc
    except AuthError as exc:
        raise auth_error(exc) from exc


@router.post("/api/auth/totp/setup", response_model=TotpSetup)
def totp_setup(req: TotpSetupRequest, request: Request,
               principal: dict = Depends(require("read"))) -> dict:
    """Begin enrolling an authenticator app; returns the secret and otpauth URI once."""
    return _throttled(request, principal["username"], lambda: engine.auth.totp_begin(
        principal["username"], req.password))


@router.post("/api/auth/totp/enable", response_model=TotpRecovery)
def totp_enable(req: TotpEnableRequest, request: Request,
                principal: dict = Depends(require("read"))) -> dict:
    """Confirm with a first valid code; returns the single-use recovery codes once."""
    codes = _throttled(request, principal["username"], lambda: engine.auth.totp_confirm(
        principal["user_id"], req.code))
    engine.audit_service.append(
        "auth.totp_enabled", {"username": principal["username"]},
        actor=principal["username"])
    return {"recovery_codes": codes}


@router.post("/api/auth/totp/disable", response_model=TotpDisabled)
def totp_disable(req: TotpDisableRequest, request: Request,
                 principal: dict = Depends(require("read"))) -> dict:
    """Turn the second factor off (password + a valid code or a recovery code)."""
    out = _throttled(request, principal["username"], lambda: engine.auth.totp_disable(
        principal["username"], req.password, req.code))
    engine.audit_service.append(
        "auth.totp_disabled", {"username": out["username"]},
        actor=principal["username"])
    return {"totp_enabled": False}
