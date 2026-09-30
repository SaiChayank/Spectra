"""Authentication routes: login, logout, current user.

Login is one of the two public routes (see ``PUBLIC_ROUTES``); logout and
``me`` require a session like everything else. Responses carry identity and
permissions only - never the password hash, the raw token, or the token
hash that storage keeps.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response
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


@router.post("/api/auth/login")
def auth_login(req: LoginRequest, response: Response) -> dict:
    """Open a session; sets the HttpOnly cookie and returns the identity.

    Unknown username and wrong password answer the same generic 401 (the
    service burns identical scrypt work for both), so this endpoint cannot
    be used to enumerate accounts. Failed attempts are deliberately not
    audited: the audit log is never pruned, and unauthenticated writes into
    it would be an unbounded amplification path.
    """
    try:
        user, token, expires_at = engine.auth.login(req.username, req.password)
    except CredentialsError as exc:
        raise auth_error(exc) from exc
    except AuthError as exc:  # persistence off (503) and friends
        raise auth_error(exc) from exc
    set_session_cookie(response, token)
    engine.audit_service.append(
        "auth.login", {"username": user["username"]},
        actor=user["username"])
    return identity_payload(user, expires_at)


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
    return public_principal(principal)
