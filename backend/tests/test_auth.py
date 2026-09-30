"""Authentication, RBAC and user-management tests (local accounts, no OAuth).

Covers the DoD directly:

* protected resources require authentication (a sweep over **every** route),
* role restrictions work per role (VIEWER / ANALYST / ADMIN),
* sessions are persistent, expiring and invalidatable (logout, password
  change, deletion),
* the event WebSocket authorizes its handshake (cookie and ``?token=``),
* login is enumeration-resistant and never leaks hashes or token material.
"""

from __future__ import annotations

import os
import re
import time

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from spectra.api.app import app
from spectra.api.runtime import engine
from spectra.api.security import PUBLIC_ROUTES, SESSION_COOKIE
from spectra.auth import verify_password
from spectra.authz import PERMISSIONS, ROLES
from spectra.services.auth import UserGuardError, hash_token

ADMIN_PASSWORD = os.environ["SPECTRA_ADMIN_PASSWORD"]
GENERIC_LOGIN_FAILURE = "invalid username or password"

# Carries the session-scoped admin cookie (see conftest).
client = TestClient(app)


def fresh_client() -> TestClient:
    """A client with no session cookie (anonymous caller)."""
    c = TestClient(app)
    c.cookies.clear()
    return c


def login(c: TestClient, username: str, password: str):
    return c.post("/api/auth/login",
                  json={"username": username, "password": password})


def user_id_for(c: TestClient, username: str) -> int | None:
    res = c.get("/api/users")
    assert res.status_code == 200, res.text
    for user in res.json()["items"]:
        if user["username"] == username:
            return int(user["id"])
    return None


# -- login --------------------------------------------------------------------

def test_login_success_shape_and_cookie(raw_client):
    res = login(raw_client, "admin", ADMIN_PASSWORD)
    assert res.status_code == 200, res.text
    body = res.json()
    assert set(body) == {"user", "expires_at"}
    assert body["user"]["username"] == "admin"
    assert body["user"]["role"] == "ADMIN"
    assert set(body["user"]["permissions"]) == set(PERMISSIONS)
    assert body["expires_at"] > time.time()
    # no secret material in the body
    assert "password" not in res.text and "token" not in res.text
    # HttpOnly + SameSite cookie is how the browser gets the token
    cookie_header = res.headers.get("set-cookie", "")
    assert SESSION_COOKIE in cookie_header
    assert "HttpOnly" in cookie_header and "SameSite=lax" in cookie_header
    assert raw_client.cookies.get(SESSION_COOKIE)


def test_login_failures_are_indistinguishable(raw_client):
    """Unknown user and wrong password: same status, same generic detail."""
    unknown = login(fresh_client(), "no_such_user_x", "whatever-123")
    wrong = login(fresh_client(), "admin", "wrong-password-123")
    assert unknown.status_code == 401
    assert wrong.status_code == 401
    assert unknown.json()["detail"] == GENERIC_LOGIN_FAILURE
    assert wrong.json()["detail"] == GENERIC_LOGIN_FAILURE
    # a failed login never opens a session
    assert fresh_client().get("/api/auth/me").status_code == 401


def test_login_never_applies_password_policy(raw_client):
    """A 1-char password on the login path answers 401, not 422: the policy
    (and its length hint) is only enforced when a password is *set*."""
    res = login(raw_client, "admin", "x")
    assert res.status_code == 401
    assert res.json()["detail"] == GENERIC_LOGIN_FAILURE


def test_login_without_persistence_is_503(raw_client):
    auth = engine.auth
    prev = auth.store
    try:
        auth.store = None
        res = login(raw_client, "admin", ADMIN_PASSWORD)
        assert res.status_code == 503
        assert raw_client.get("/api/stats").status_code == 503
    finally:
        auth.store = prev


# -- default-deny: every route needs a session --------------------------------

def test_every_api_route_requires_a_session(raw_client):
    """Sweep: no /api/ route answers an anonymous caller (except the two
    public ones) - a newly added route is protected by construction."""
    checked = 0
    for route in app.routes:
        methods = getattr(route, "methods", None)
        if not methods:
            continue  # websocket / mounts
        path = re.sub(r"\{[^}]+\}", "1", route.path)
        if not path.startswith("/api/"):
            continue
        for method in sorted(m for m in methods if m not in ("HEAD", "OPTIONS")):
            if (method, path) in PUBLIC_ROUTES:
                continue
            res = raw_client.request(method, path)
            assert res.status_code == 401, (
                f"{method} {route.path} answered {res.status_code} "
                f"without a session ({res.text[:120]})")
            assert res.headers.get("www-authenticate") == "Bearer"
            checked += 1
    assert checked >= 70  # the sweep actually walked the API surface


def test_public_routes_stay_public(raw_client):
    assert raw_client.get("/api/health").status_code == 200
    # login validates its body (422) without demanding a session (never 401)
    res = raw_client.post("/api/auth/login", json={})
    assert res.status_code == 422


# -- current user / logout / expiry -------------------------------------------

def test_me_returns_identity_without_secrets(client):
    res = client.get("/api/auth/me")
    assert res.status_code == 200
    body = res.json()
    assert body["user"]["username"] == "admin"
    assert body["user"]["role"] == "ADMIN"
    assert set(body["user"]["permissions"]) == set(PERMISSIONS)
    assert body["expires_at"] > time.time()
    assert "token" not in res.text and "password" not in res.text


def test_logout_deletes_the_session_and_replay_is_dead():
    c = fresh_client()
    assert login(c, "admin", ADMIN_PASSWORD).status_code == 200
    token = c.cookies.get(SESSION_COOKIE)
    assert engine.store.get_session(hash_token(token)) is not None

    res = c.post("/api/auth/logout")
    assert res.status_code == 200 and res.json() == {"ok": True}
    assert engine.store.get_session(hash_token(token)) is None
    assert c.get("/api/auth/me").status_code == 401

    # replaying the old token must not resurrect the session
    c.cookies.set(SESSION_COOKIE, token)
    assert c.get("/api/auth/me").status_code == 401


def test_expired_session_is_rejected_and_purged():
    c = fresh_client()
    assert login(c, "admin", ADMIN_PASSWORD).status_code == 200
    token = c.cookies.get(SESSION_COOKIE)
    token_hash = hash_token(token)
    db = engine.store._db
    db.execute("UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
               (time.time() - 5, token_hash))
    db.commit()

    res = c.get("/api/auth/me")
    assert res.status_code == 401
    assert res.json()["detail"] == "session expired"  # distinct from 401-unknown
    assert engine.store.get_session(token_hash) is None  # purged, not just read
    assert login(c, "admin", ADMIN_PASSWORD).status_code == 200  # fresh session


def test_password_change_revokes_every_session(client):
    """An admin rotating a password kills all of that user's sessions."""
    username, old_pw, new_pw = "test_rotate", "rotate-pass-123", "rotated-pass-456"
    res = client.post("/api/users", json={
        "username": username, "password": old_pw, "role": "VIEWER"})
    assert res.status_code in (200, 409), res.text
    user_id = user_id_for(client, username)
    assert user_id is not None

    c1, c2 = fresh_client(), fresh_client()
    assert login(c1, username, old_pw).status_code == 200
    assert login(c2, username, old_pw).status_code == 200

    res = client.patch(f"/api/users/{user_id}", json={"password": new_pw})
    assert res.status_code == 200
    assert "password_hash" not in res.text

    assert c1.get("/api/auth/me").status_code == 401
    assert c2.get("/api/auth/me").status_code == 401
    assert login(fresh_client(), username, old_pw).status_code == 401
    assert login(fresh_client(), username, new_pw).status_code == 200


# -- role matrix ---------------------------------------------------------------

def test_viewer_is_read_only(viewer_client):
    assert viewer_client.get("/api/auth/me").json()["user"]["role"] == "VIEWER"
    # reads: dashboard + reports
    for path in ("/api/stats", "/api/status", "/api/history/flows",
                 "/api/history/detections", "/api/captures", "/api/model",
                 "/api/pqc"):
        assert viewer_client.get(path).status_code == 200, path
    # investigation surface
    assert viewer_client.get("/api/graph").status_code == 403
    assert viewer_client.get("/api/audit/entries").status_code == 403
    assert viewer_client.get("/api/incidents").status_code == 403
    # operations (ADMIN)
    assert viewer_client.get("/api/users").status_code == 403
    res = viewer_client.post("/api/capture/start", json={"mode": "live"})
    assert res.status_code == 403
    assert "capture:manage" in res.json()["detail"]
    res = viewer_client.post("/api/model/train", json={"capture_id": 1})
    assert res.status_code == 403
    res = viewer_client.post("/api/edge/link", json={"link": "sat"})
    assert res.status_code == 403


def test_analyst_can_investigate_but_not_operate(analyst_client):
    assert analyst_client.get("/api/auth/me").json()["user"]["role"] == "ANALYST"
    # investigate
    assert analyst_client.get("/api/graph").status_code == 200
    assert analyst_client.get("/api/audit/entries").status_code == 200
    assert analyst_client.get("/api/incidents").status_code == 200
    res = analyst_client.post("/api/incidents", json={"title": "rbac probe"})
    assert res.status_code == 200
    assert res.json()["created_by"] == "test_analyst"
    # still no ADMIN powers
    assert analyst_client.get("/api/users").status_code == 403
    res = analyst_client.post("/api/capture/start", json={"mode": "live"})
    assert res.status_code == 403
    res = analyst_client.post("/api/model/train", json={"capture_id": 1})
    assert res.status_code == 403
    res = analyst_client.post("/api/edge/link", json={"link": "sat"})
    assert res.status_code == 403
    # reads still fine
    assert analyst_client.get("/api/stats").status_code == 200


def test_admin_passes_authorization_into_business_validation(client):
    """ADMIN answers 403 nowhere: edge/link reaches its handler (400 for an
    unknown link proves the permission layer was passed, not that it was
    skipped - an anonymous caller of the same route gets 401)."""
    assert client.get("/api/users").status_code == 200
    res = client.post("/api/edge/link", json={"link": "no-such-link"})
    assert res.status_code == 400
    assert fresh_client().post("/api/edge/link",
                               json={"link": "no-such-link"}).status_code == 401


# -- user management ------------------------------------------------------------

def test_user_management_lifecycle(client):
    username, password = "test_promote", "promote-pass-123"
    res = client.post("/api/users", json={
        "username": username, "password": password, "role": "VIEWER"})
    assert res.status_code == 200, res.text
    user_id = int(res.json()["id"])
    assert "password_hash" not in res.text and "scrypt$" not in res.text

    c = fresh_client()
    assert login(c, username, password).status_code == 200
    assert c.get("/api/graph").status_code == 403          # VIEWER

    res = client.patch(f"/api/users/{user_id}", json={"role": "ANALYST"})
    assert res.status_code == 200 and res.json()["role"] == "ANALYST"
    assert c.get("/api/graph").status_code == 200          # role change is live

    # duplicates / policy
    dup = client.post("/api/users", json={
        "username": username.upper(), "password": password, "role": "VIEWER"})
    assert dup.status_code == 409
    weak = client.post("/api/users", json={
        "username": "test_weak", "password": "short", "role": "VIEWER"})
    assert weak.status_code == 422
    bad_role = client.post("/api/users", json={
        "username": "test_badrole", "password": password, "role": "ROOT"})
    assert bad_role.status_code == 422
    bad_name = client.post("/api/users", json={
        "username": "a b", "password": password, "role": "VIEWER"})
    assert bad_name.status_code == 422
    assert client.get("/api/users/999999").status_code == 404

    # deletion kills the account and its live session
    res = client.delete(f"/api/users/{user_id}")
    assert res.status_code == 200
    assert c.get("/api/auth/me").status_code == 401
    assert login(fresh_client(), username, password).status_code == 401


def test_user_guards_self_and_last_admin(client):
    admin = next(u for u in client.get("/api/users").json()["items"]
                 if u["role"] == "ADMIN")
    res = client.delete(f"/api/users/{admin['id']}")
    assert res.status_code == 409
    assert "own account" in res.json()["detail"]
    # last-admin guard (service level: no actor bypasses the self-guard)
    with pytest.raises(UserGuardError, match="last ADMIN"):
        engine.auth.delete_user(int(admin["id"]))


# -- WebSocket authorization ------------------------------------------------------

def test_websocket_rejects_missing_or_bad_sessions(raw_client):
    with pytest.raises(WebSocketDisconnect) as missing:
        with raw_client.websocket_connect("/ws/events"):
            pass
    assert missing.value.code == 4401

    with pytest.raises(WebSocketDisconnect) as bogus:
        with raw_client.websocket_connect("/ws/events?token=not-a-token"):
            pass
    assert bogus.value.code == 4401


def test_websocket_accepts_cookie_and_token_sessions(client, viewer_client):
    with client.websocket_connect("/ws/events") as ws:
        assert ws.receive_json()["type"] == "status"    # HttpOnly cookie
    with viewer_client.websocket_connect("/ws/events") as ws:
        assert ws.receive_json()["type"] == "status"    # any role with read
    token = client.cookies.get(SESSION_COOKIE)
    anonymous = fresh_client()
    with anonymous.websocket_connect(f"/ws/events?token={token}") as ws:
        assert ws.receive_json()["type"] == "status"    # scripts/CI: ?token=


# -- storage hygiene -------------------------------------------------------------

def test_no_hash_or_raw_token_is_ever_exposed(client):
    # API responses
    assert "password_hash" not in client.get("/api/users").text
    assert "scrypt$" not in client.get("/api/users").text
    assert "token_hash" not in client.get("/api/auth/me").text

    # storage keeps only the SHA-256 of the token
    c = fresh_client()
    assert login(c, "admin", ADMIN_PASSWORD).status_code == 200
    token = c.cookies.get(SESSION_COOKIE)
    assert engine.store.get_session(token) is None          # raw token is no key
    assert engine.store.get_session(hash_token(token)) is not None
    for row in engine.store._db.query("SELECT * FROM sessions"):
        assert token not in " ".join(str(v) for v in row.values())


def test_password_hash_is_scrypt_never_plaintext():
    creds = engine.store.find_user_credentials("admin")
    assert creds is not None
    assert creds["password_hash"].startswith("scrypt$")
    assert creds["password_hash"] != ADMIN_PASSWORD
    assert verify_password(ADMIN_PASSWORD, creds["password_hash"])
    assert not verify_password("wrong-password-123", creds["password_hash"])


def test_bootstrap_runs_once_per_database():
    before = engine.store.count_users()
    assert engine.auth.bootstrap() is None     # users exist: no reset, no new
    assert engine.store.count_users() == before


def test_roles_and_permissions_are_consistent():
    from spectra.authz import ROLE_PERMISSIONS, has_permission, permissions_for
    assert set(ROLES) == set(ROLE_PERMISSIONS)
    for role in ROLES:
        perms = permissions_for(role)
        assert all(has_permission(role, p) for p in perms)
        assert not has_permission(role, "nope:permission")
        assert has_permission("ADMIN", "users:manage")
    assert not has_permission("VIEWER", "capture:manage")
    assert not has_permission("ANALYST", "users:manage")
    assert not has_permission("UNKNOWN", "read")
