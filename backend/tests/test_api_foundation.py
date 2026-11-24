"""Foundation behaviour shared by every route: unexpected-error shape,
readiness, response headers and login-throttle visibility."""

from __future__ import annotations

import logging

import pytest

from spectra.api.runtime import engine
from spectra.db.migrations import MIGRATIONS
from spectra.services.auth import LoginThrottle


# -- unexpected errors ------------------------------------------------------------

def _boom(*args, **kwargs):
    raise RuntimeError("internal detail /srv/private/secret.db")


def test_unhandled_error_is_a_generic_json_500_with_request_id(client, monkeypatch, caplog):
    monkeypatch.setattr(engine.system, "snapshot", _boom)
    with caplog.at_level(logging.ERROR, logger="spectra.api"):
        res = client.get("/api/stats", headers={"X-Request-ID": "req-abc123"})
    assert res.status_code == 500
    assert res.headers["content-type"].startswith("application/json")
    assert res.json() == {"detail": "internal server error", "request_id": "req-abc123"}
    assert res.headers["X-Request-ID"] == "req-abc123"
    assert "/srv/private" not in res.text
    # the full exception is in the server log, tied to the same request id
    logged = [r for r in caplog.records if getattr(r, "event", "") == "unhandled_error"]
    assert logged and logged[0].request_id == "req-abc123" and logged[0].exc_info


def test_unhandled_error_keeps_cors_headers_for_the_dashboard(client, monkeypatch):
    # without CORS headers the browser hides the 500 and the UI says "server unreachable"
    monkeypatch.setattr(engine.system, "snapshot", _boom)
    res = client.get("/api/stats", headers={"Origin": "http://localhost:5173"})
    assert res.status_code == 500
    assert res.headers["access-control-allow-origin"] == "http://localhost:5173"


# -- readiness ----------------------------------------------------------------------

def test_ready_is_public_and_reports_each_check(raw_client):
    res = raw_client.get("/api/ready")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body == {"ready": True,
                    "checks": {"data_dir": "ok", "database": "ok", "schema": "current"}}


def test_ready_answers_503_when_storage_cannot_be_written(raw_client, monkeypatch):
    monkeypatch.setattr(engine.system, "_writability",
                        lambda: {"data_dir": "failed", "database": "ok"})
    res = raw_client.get("/api/ready")
    assert res.status_code == 503
    assert res.json()["ready"] is False
    assert res.json()["checks"]["data_dir"] == "failed"


def test_ready_answers_503_when_the_schema_is_behind(raw_client, monkeypatch):
    latest = MIGRATIONS[-1].version
    monkeypatch.setattr(type(engine.store), "schema_version",
                        property(lambda self: latest - 1))
    res = raw_client.get("/api/ready")
    assert res.status_code == 503
    assert res.json()["checks"]["schema"] == "behind"


def test_busy_database_is_still_ready(raw_client, monkeypatch):
    # a held write lock is transient: health stays 200 for it, so readiness does too
    monkeypatch.setattr(engine.system, "_writability",
                        lambda: {"data_dir": "ok", "database": "busy"})
    assert raw_client.get("/api/ready").status_code == 200


# -- response headers ---------------------------------------------------------------

@pytest.mark.parametrize("path", ["/api/status", "/api/alerts", "/api/users", "/api/metrics"])
def test_api_responses_are_never_mime_sniffed(client, path):
    res = client.get(path)
    assert res.status_code == 200, res.text
    assert res.headers["X-Content-Type-Options"] == "nosniff"


def test_error_responses_carry_nosniff_too(raw_client):
    res = raw_client.get("/api/status")
    assert res.status_code == 401
    assert res.headers["X-Content-Type-Options"] == "nosniff"


# -- login throttle visibility --------------------------------------------------------

def test_throttle_counts_and_logs_each_block_without_the_username(caplog):
    clock = [0.0]
    throttle = LoginThrottle(limit=3, ip_limit=100, window=60, clock=lambda: clock[0])
    with caplog.at_level(logging.WARNING, logger="spectra.auth"):
        for _ in range(3):
            throttle.record_failure("10.0.0.9", "victim-admin")
        throttle.record_failure("10.0.0.9", "victim-admin")   # already blocked: not a new block
    assert throttle.blocks_started == 1
    lines = [r for r in caplog.records if getattr(r, "event", "") == "login_throttled"]
    assert len(lines) == 1
    assert lines[0].scope == "ip_user" and lines[0].block_s == 60
    text = caplog.text + repr(lines[0].__dict__)
    assert "victim-admin" not in text and "10.0.0.9" not in text


def test_blocks_are_exposed_as_a_metric(client):
    before = engine.auth.throttle.blocks_started
    text = client.get("/api/metrics").text
    assert "# TYPE spectra_login_blocks_total counter" in text
    assert f"spectra_login_blocks_total {before}" in text
