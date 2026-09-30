"""User management routes (ADMIN only: ``users:manage``).

Passwords are accepted here only to be scrypt-hashed by the service; role
changes take effect on the target user's very next request (roles are read
per request, never cached in the session), and a password change revokes
that user's sessions. Responses use the store's public projection - the
password hash never appears.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ...services.auth import AuthError
from ..runtime import engine
from ..security import auth_error, require

router = APIRouter(dependencies=[Depends(require("users:manage"))])

_ROLE_PATTERN = "^(ADMIN|ANALYST|VIEWER)$"


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=1024)
    role: str = Field(pattern=_ROLE_PATTERN)


class UserUpdate(BaseModel):
    role: str | None = Field(None, pattern=_ROLE_PATTERN)
    password: str | None = Field(None, min_length=8, max_length=1024)


@router.get("/api/users")
def users_list() -> dict:
    """Every account (public projection - no hashes)."""
    items = engine.auth.list_users()
    return {"count": len(items), "items": items}


@router.get("/api/users/{user_id}")
def users_get(user_id: int) -> dict:
    try:
        return engine.auth.get_user(user_id)
    except AuthError as exc:
        raise auth_error(exc) from exc


@router.post("/api/users")
def users_create(req: UserCreate,
                 principal: dict = Depends(require("users:manage"))) -> dict:
    """Create an account (username format + password policy enforced)."""
    try:
        user = engine.auth.create_user(req.username, req.password, req.role)
    except AuthError as exc:
        raise auth_error(exc) from exc
    engine.audit_service.append(
        "user.create",
        {"username": user["username"], "role": user["role"]},
        actor=principal["username"])
    return user


@router.patch("/api/users/{user_id}")
def users_update(user_id: int, req: UserUpdate,
                 principal: dict = Depends(require("users:manage"))) -> dict:
    """Change role and/or password; a password change revokes all sessions."""
    try:
        user = engine.auth.update_user(user_id, role=req.role,
                                       password=req.password)
    except AuthError as exc:
        raise auth_error(exc) from exc
    engine.audit_service.append(
        "user.update",
        {"username": user["username"], "role": user["role"],
         "password_changed": req.password is not None},
        actor=principal["username"])
    return user


@router.delete("/api/users/{user_id}")
def users_delete(user_id: int,
                 principal: dict = Depends(require("users:manage"))) -> dict:
    """Delete an account (guards: not yourself, never the last ADMIN)."""
    try:
        engine.auth.delete_user(user_id, actor_id=principal["user_id"])
    except AuthError as exc:
        raise auth_error(exc) from exc
    engine.audit_service.append(
        "user.delete", {"user_id": user_id},
        actor=principal["username"])
    return {"ok": True, "deleted": user_id}
