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


class TotpSetupRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


class TotpEnableRequest(BaseModel):
    code: str = Field(min_length=1, max_length=32)


class TotpDisableRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)
    code: str = Field(min_length=1, max_length=32)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/api/auth/login")
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


@router.post("/api/auth/logout")
def auth_logout(response: Response,
                principal: dict = Depends(require("read"))) -> dict:
    """Invalidate the caller's session and clear the cookie (idempotent)."""
    engine.auth.logout(principal["session"]["token_hash"])
    clear_session_cookie(response)
    engine.audit_service.append(
        "auth.logout", {"username": principal["username"]},
        actor=principal["username"])
    return {"ok": True}


@router.get("/api/auth/me")
def auth_me(principal: dict = Depends(require("read"))) -> dict:
    """The signed-in identity: username, role, permissions, expiry."""
    return public_principal(principal, engine.auth.totp_enabled(principal["user_id"]))


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


@router.post("/api/auth/totp/setup")
def totp_setup(req: TotpSetupRequest, request: Request,
               principal: dict = Depends(require("read"))) -> dict:
    """Begin enrolling an authenticator app; returns the secret and otpauth URI once."""
    return _throttled(request, principal["username"], lambda: engine.auth.totp_begin(
        principal["username"], req.password))


@router.post("/api/auth/totp/enable")
def totp_enable(req: TotpEnableRequest, request: Request,
                principal: dict = Depends(require("read"))) -> dict:
    """Confirm with a first valid code; returns the single-use recovery codes once."""
    codes = _throttled(request, principal["username"], lambda: engine.auth.totp_confirm(
        principal["user_id"], req.code))
    engine.audit_service.append(
        "auth.totp_enabled", {"username": principal["username"]},
        actor=principal["username"])
    return {"recovery_codes": codes}


@router.post("/api/auth/totp/disable")
def totp_disable(req: TotpDisableRequest, request: Request,
                 principal: dict = Depends(require("read"))) -> dict:
    """Turn the second factor off (password + a valid code or a recovery code)."""
    out = _throttled(request, principal["username"], lambda: engine.auth.totp_disable(
        principal["username"], req.password, req.code))
    engine.audit_service.append(
        "auth.totp_disabled", {"username": out["username"]},
        actor=principal["username"])
    return {"totp_enabled": False}
