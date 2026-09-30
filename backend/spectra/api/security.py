"""Authentication gate + permission dependencies for the HTTP layer.

Two cooperating layers:

1. ``auth_gate`` (registered as ``@app.middleware("http")``): **default-deny**
   - every ``/api/`` request must carry a valid session unless its
   ``(method, path)`` is listed in :data:`PUBLIC_ROUTES`. A route added
   tomorrow is protected the moment it is added; the resolved principal is
   stored on ``request.state`` so lower layers read it once.
2. :func:`require` (router/route dependencies): answers **403** when the
   caller's role lacks the route's permission (:mod:`spectra.authz`), and
   doubles as an authentication check if the gate were ever removed.

FastAPI's global ``dependencies=`` parameter cannot be used for (1): it also
applies to WebSocket routes, where ``Request`` is not injected. The event
stream therefore authenticates at handshake time in :mod:`spectra.api.app`
via :func:`resolve_ws_principal` - middleware written for ``http`` scopes
never sees a websocket scope.

Session tokens come from the HttpOnly cookie (browser), an
``Authorization: Bearer`` header, or ``?token=`` (the WebSocket).
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse

from ..authz import has_permission, permissions_for
from ..services.auth import (
    UNAUTHENTICATED,
    AuthError,
    AuthUnavailable,
    SESSION_COOKIE,
)
from .runtime import engine

#: Reachable without a session. Login must precede having one; health is the
#: liveness probe. Everything else under ``/api/`` is default-deny.
PUBLIC_ROUTES: frozenset[tuple[str, str]] = frozenset({
    ("GET", "/api/health"),
    ("POST", "/api/auth/login"),
})

#: FastAPI's own schema/doc surfaces (static descriptions, no data) and the
#: non-API paths that should keep answering 404 rather than 401.
_PUBLIC_PREFIXES = ("/docs", "/redoc", "/openapi.json", "/favicon.ico")


def token_from_request(request: Request) -> str | None:
    """Raw session token: cookie first (browsers), then bearer header."""
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        return token
    header = request.headers.get("authorization", "")
    if header[:7].lower() == "bearer ":
        return header[7:].strip() or None
    return None


def resolve_principal(request: Request) -> dict | None:
    """Validate the request's session; memoized on ``request.state``.

    Returns ``None`` when there is no usable session, raises
    :class:`SessionExpired` for an expired one (distinct 401 detail) and
    :class:`AuthUnavailable` when persistence is off (503). The principal
    carries the session's token hash for logout - it must never be
    serialized into a response.
    """
    cached = getattr(request.state, "spectra_principal", None)
    if cached is not None:
        return cached
    if not engine.auth.available:
        raise AuthUnavailable()
    token = token_from_request(request)
    if not token:
        return None
    principal = engine.auth.validate(token)  # raises SessionExpired on TTL
    if principal is None:
        return None
    request.state.spectra_principal = principal
    return principal


def resolve_ws_principal(cookies: Mapping[str, str],
                         query: Mapping[str, str]) -> dict | None:
    """Handshake validation for the event WebSocket (cookie or ``?token=``).

    Any failure - no token, unknown session, expired, persistence off -
    collapses to ``None`` so the handler can reject the upgrade without
    telling a probe which of those it was.
    """
    token = cookies.get(SESSION_COOKIE) or query.get("token")
    if not token or not engine.auth.available:
        return None
    try:
        return engine.auth.validate(token)
    except AuthError:
        return None


def require(permission: str):
    """Route dependency: valid session **and** the role's permission (403).

    Returns the principal, so handlers receive attribution (``actor``) and
    the caller's session in one argument.
    """

    async def dependency(request: Request) -> dict:
        try:
            principal = resolve_principal(request)
        except AuthError as exc:
            raise HTTPException(status_code=exc.status_code,
                                detail=exc.detail) from exc
        if principal is None:
            raise HTTPException(
                status_code=401, detail=UNAUTHENTICATED,
                headers={"WWW-Authenticate": "Bearer"})
        if not has_permission(principal["role"], permission):
            raise HTTPException(
                status_code=403,
                detail=f"role {principal['role']} lacks the "
                       f"'{permission}' permission")
        return principal

    # Introspectable name (tests walk app.routes and see require_<perm>)
    dependency.__name__ = "require_" + permission.replace(":", "_")
    return dependency


def auth_error(exc: AuthError) -> HTTPException:
    """Map an :class:`AuthError` to its HTTP exception (routers' helper)."""
    return HTTPException(status_code=exc.status_code, detail=exc.detail)


def _error_response(status_code: int, detail: str,
                    headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status_code,
                        headers=headers)


async def auth_gate(request: Request, call_next):
    """Default-deny middleware (see module docstring). Registered per-app."""
    if request.method == "OPTIONS":
        return await call_next(request)  # CORS preflight carries no session
    path = request.url.path
    if path.startswith(_PUBLIC_PREFIXES) or \
            (request.method, path) in PUBLIC_ROUTES:
        return await call_next(request)
    if not path.startswith("/api/"):
        return await call_next(request)  # not API surface (docs, 404s, ...)
    try:
        principal = resolve_principal(request)
    except AuthError as exc:
        return _error_response(exc.status_code, exc.detail)
    if principal is None:
        return _error_response(401, UNAUTHENTICATED,
                               headers={"WWW-Authenticate": "Bearer"})
    return await call_next(request)


# -- response shaping (identity without secrets) -------------------------------

def identity_payload(user: dict, expires_at: float) -> dict:
    """Login/``me`` response: identity + permissions, never token material."""
    return {
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "permissions": permissions_for(user["role"]),
        },
        "expires_at": expires_at,
    }


def public_principal(principal: dict) -> dict:
    """``/me`` response from a principal (no token hash, no internals)."""
    return {
        "user": {
            "id": principal["user_id"],
            "username": principal["username"],
            "role": principal["role"],
            "permissions": list(principal["permissions"]),
        },
        "expires_at": principal["session"]["expires_at"],
    }


def set_session_cookie(response: Response, token: str) -> None:
    """Attach the HttpOnly session cookie (SameSite=Lax, optional Secure)."""
    cfg = engine.config
    response.set_cookie(
        SESSION_COOKIE, token,
        max_age=int(cfg.session_ttl_minutes * 60),
        path="/", httponly=True, samesite="lax",
        secure=cfg.session_cookie_secure,
    )


def clear_session_cookie(response: Response) -> None:
    """Remove the session cookie on logout (mirrors the set attributes)."""
    cfg = engine.config
    response.delete_cookie(
        SESSION_COOKIE, path="/", httponly=True, samesite="lax",
        secure=cfg.session_cookie_secure,
    )
