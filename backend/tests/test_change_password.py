"""POST /api/auth/password: any signed-in user changes their OWN password."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

import spectra.services.auth as auth_mod
from spectra.api.app import app
from spectra.api.runtime import engine
from spectra.api.security import SESSION_COOKIE
from spectra.auth import totp

OLD, NEW = "old-pass-12345", "new-pass-67890"


def _login(c, user, pw):
    return c.post("/api/auth/login", json={"username": user, "password": pw})


def _anon():
    c = TestClient(app)
    c.cookies.clear()
    return c


@pytest.fixture
def make_user(client):
    """Create throwaway accounts (cleaned up); returns (username, signed-in client)."""
    made = []

    def _make(role):
        name = f"pwchg_{role.lower()}"
        r = client.post("/api/users", json={"username": name, "password": OLD, "role": role})
        assert r.status_code == 200, r.text
        made.append(r.json()["id"])
        c = _anon()
        assert _login(c, name, OLD).status_code == 200
        return name, c

    yield _make
    engine.auth.throttle.reset()
    for uid in made:
        client.delete(f"/api/users/{uid}")


@pytest.mark.parametrize("role", ["VIEWER", "ANALYST", "ADMIN"])
def test_each_role_changes_own_password(make_user, role):
    name, c = make_user(role)
    other = _anon()
    assert _login(other, name, OLD).status_code == 200  # a second session
    r = c.post("/api/auth/password", json={"current_password": OLD, "new_password": NEW})
    assert r.status_code == 200, r.text
    assert r.json() == {"ok": True, "sign_in_required": True}
    assert OLD not in r.text and NEW not in r.text
    # every session revoked, the caller's and the other one
    assert c.get("/api/auth/me").status_code == 401
    assert other.get("/api/auth/me").status_code == 401
    assert "Max-Age=0" in r.headers["set-cookie"] or '=""' in r.headers["set-cookie"]
    # new password logs in, old does not
    assert _login(_anon(), name, OLD).status_code == 401
    assert _login(_anon(), name, NEW).status_code == 200


def test_old_cookie_is_dead_after_change(make_user):
    _, c = make_user("VIEWER")
    token = c.cookies.get(SESSION_COOKIE)
    assert c.post("/api/auth/password",
                  json={"current_password": OLD, "new_password": NEW}).status_code == 200
    stale = _anon()
    stale.cookies.set(SESSION_COOKIE, token)
    assert stale.get("/api/auth/me").status_code == 401


def test_wrong_current_password_403_generic_and_throttled(make_user):
    name, c = make_user("VIEWER")
    body = {"current_password": "not-the-password", "new_password": NEW}
    for _ in range(10):
        r = c.post("/api/auth/password", json=body)
        assert r.status_code == 403
        assert r.json() == {"detail": "current password is incorrect"}
    r = c.post("/api/auth/password", json=body)
    assert r.status_code == 429 and "retry-after" in r.headers
    # throttled even with the right password: no brute force from a stolen session
    assert c.post("/api/auth/password",
                  json={"current_password": OLD, "new_password": NEW}).status_code == 429
    assert c.get("/api/auth/me").status_code == 200  # session intact, password unchanged
    engine.auth.throttle.reset()
    assert _login(_anon(), name, OLD).status_code == 200


def test_policy_enforced_and_nothing_changes_on_reject(make_user):
    name, c = make_user("ANALYST")
    for bad in ("short", "x" * 1025):
        r = c.post("/api/auth/password", json={"current_password": OLD, "new_password": bad})
        assert r.status_code == 422
    assert c.get("/api/auth/me").status_code == 200
    assert _login(_anon(), name, OLD).status_code == 200


def test_new_equal_to_current_rejected(make_user):
    _, c = make_user("VIEWER")
    r = c.post("/api/auth/password", json={"current_password": OLD, "new_password": OLD})
    assert r.status_code == 422
    assert c.get("/api/auth/me").status_code == 200


def test_unauthenticated_is_401(raw_client):
    r = raw_client.post("/api/auth/password",
                        json={"current_password": OLD, "new_password": NEW})
    assert r.status_code == 401


def test_audit_entry_has_no_secrets(make_user, client):
    name, c = make_user("VIEWER")
    assert c.post("/api/auth/password",
                  json={"current_password": OLD, "new_password": NEW}).status_code == 200
    res = client.get("/api/audit/entries", params={"kind": "auth.password_changed"})
    items = [e for e in res.json()["items"] if e.get("actor") == name]
    assert items, res.text
    dump = json.dumps(items)
    assert OLD not in dump and NEW not in dump and "scrypt" not in dump


def test_totp_account_needs_a_valid_code(make_user, monkeypatch):
    name, c = make_user("VIEWER")
    now = 1_800_000_000.0
    monkeypatch.setattr(auth_mod, "_totp_now", lambda: now)
    secret = totp.from_base32(
        c.post("/api/auth/totp/setup", json={"password": OLD}).json()["secret"])
    cnt = totp.counter_at(now)
    assert c.post("/api/auth/totp/enable",
                  json={"code": totp.hotp(secret, cnt)}).status_code == 200
    body = {"current_password": OLD, "new_password": NEW}
    assert c.post("/api/auth/password", json=body).status_code == 403  # no code
    assert c.post("/api/auth/password",
                  json={**body, "totp_code": "000000"}).status_code == 403
    ok = c.post("/api/auth/password",
                json={**body, "totp_code": totp.hotp(secret, cnt + 1)})
    assert ok.status_code == 200, ok.text
    engine.auth.throttle.reset()
    assert _login(_anon(), name, NEW).status_code == 401  # right password, but the account needs its code
