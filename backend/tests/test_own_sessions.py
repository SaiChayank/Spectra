"""A signed-in user can list and end their OWN sessions (GET /api/auth/sessions, DELETE /api/auth/sessions/{id}).

Object-level rule: another user's session id answers exactly like a nonexistent one (404) and is never touched.
Responses carry ids and times only, never the token or its hash.
"""
from __future__ import annotations

import secrets
import time

import pytest
from fastapi.testclient import TestClient

from spectra.api.app import app
from spectra.api.runtime import engine
from spectra.api.security import SESSION_COOKIE
from spectra.services.auth import AuthService
from spectra.store import Store

PW = "session-test-pw-1"
_ip = iter(range(1, 250))
_created: list[int] = []


@pytest.fixture(autouse=True)
def _isolation():
    engine.auth.throttle.reset()
    yield
    engine.auth.throttle.reset()
    while _created:
        engine.auth.delete_user(_created.pop())


def _user(role: str = "VIEWER") -> str:
    name = f"sess_{secrets.token_hex(4)}"
    res = TestClient(app).post("/api/users", json={"username": name, "password": PW, "role": role})
    assert res.status_code == 200, res.text
    _created.append(res.json()["id"])
    return name


def _signed_in(name: str) -> TestClient:
    c = TestClient(app, client=(f"198.18.0.{next(_ip)}", 50000))
    c.cookies.clear()
    res = c.post("/api/auth/login", json={"username": name, "password": PW})
    assert res.status_code == 200, res.text
    return c


def _sessions(c: TestClient) -> list[dict]:
    res = c.get("/api/auth/sessions")
    assert res.status_code == 200, res.text
    assert res.headers["Cache-Control"] == "no-store"
    return res.json()["items"]


def test_lists_only_my_sessions_and_marks_the_current_one():
    me = _user()
    a, b = _signed_in(me), _signed_in(me)
    _signed_in(_user())                                         # someone else's session exists too
    items = _sessions(a)
    assert len(items) == 2
    assert [s["current"] for s in items].count(True) == 1
    assert set(items[0]) == {"id", "created_at", "last_seen_at", "expires_at", "current"}
    raw = a.get("/api/auth/sessions").text
    for c in (a, b):
        assert c.cookies.get(SESSION_COOKIE) not in raw          # never the token
    assert "token" not in raw and "hash" not in raw


def test_ending_another_of_my_sessions_signs_only_that_one_out():
    me = _user("ANALYST")
    a, b = _signed_in(me), _signed_in(me)
    other = next(s["id"] for s in _sessions(a) if not s["current"])
    res = a.delete(f"/api/auth/sessions/{other}")
    assert res.status_code == 200, res.text
    assert res.json() == {"ok": True, "revoked": other, "current": False}
    assert b.get("/api/auth/me").status_code == 401
    assert a.get("/api/auth/me").status_code == 200
    assert len(_sessions(a)) == 1


def test_someone_elses_session_is_a_404_and_is_left_alone():
    victim = _signed_in(_user())
    vid = _sessions(victim)[0]["id"]
    attacker = _signed_in(_user())
    res = attacker.delete(f"/api/auth/sessions/{vid}")
    missing = attacker.delete("/api/auth/sessions/999999999")
    assert res.status_code == missing.status_code == 404
    assert res.json() == missing.json()                         # no oracle for "exists but not yours"
    assert victim.get("/api/auth/me").status_code == 200


def test_ending_the_current_session_signs_me_out():
    a = _signed_in(_user())
    cur = next(s["id"] for s in _sessions(a) if s["current"])
    res = a.delete(f"/api/auth/sessions/{cur}")
    assert res.status_code == 200 and res.json()["current"] is True
    assert "spectra_session=" in res.headers.get("set-cookie", "")     # cookie cleared
    a.cookies.clear()
    assert a.get("/api/auth/me").status_code == 401


def test_needs_a_session(raw_client):
    assert raw_client.get("/api/auth/sessions").status_code == 401
    assert raw_client.delete("/api/auth/sessions/1").status_code == 401


@pytest.mark.parametrize("bad", ["0", "-1", "abc"])
def test_session_id_is_validated(bad):
    assert _signed_in(_user()).delete(f"/api/auth/sessions/{bad}").status_code == 422


def test_cross_origin_delete_is_refused():
    a = _signed_in(_user())
    sid = _sessions(a)[0]["id"]
    res = a.delete(f"/api/auth/sessions/{sid}", headers={"Origin": "http://evil.localhost:9999"})
    assert res.status_code == 403 and a.get("/api/auth/me").status_code == 200


def test_ending_a_session_is_audited_without_secrets():
    name = _user()
    a, b = _signed_in(name), _signed_in(name)
    other = next(s["id"] for s in _sessions(a) if not s["current"])
    assert a.delete(f"/api/auth/sessions/{other}").status_code == 200
    log = TestClient(app).get("/api/audit/entries", params={"kind": "auth.session_revoked", "actor": name})
    items = log.json()["items"]
    assert items and items[0]["payload"] == {"username": name, "session_id": other, "current": False}
    assert b.cookies.get(SESSION_COOKIE) not in log.text


def test_expired_sessions_are_not_listed(tmp_path):
    store = Store(str(tmp_path / "s.db"))
    svc = AuthService(store)
    u = svc.create_user("expiry", PW, "VIEWER")
    store.create_session(u["id"], "h-live", time.time() + 600)
    store.create_session(u["id"], "h-dead", time.time() - 1)
    listed = svc.list_own_sessions(u["id"], "h-live")
    assert [s["current"] for s in listed] == [True]
    store.close()
