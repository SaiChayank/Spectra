"""Runtime check of the 'never log secrets' rule (Phase 11): drive real requests through the
app with the structured formatter installed and assert no secret value reaches a log line.
The SAST rule checks source; this checks what is actually emitted."""
from __future__ import annotations

import io
import logging

import pytest

from spectra.observability import RequestIdFilter, StructuredFormatter

WRONG_PW = "Wr0ng-Pass-MARKER-91"
QUERY_TOKEN = "QTOKEN-MARKER-77"
BAD_COOKIE = "BADSESSION-MARKER-55"
NEW_USER_PW = "NewUser-Pass-MARKER-33"


@pytest.fixture
def log_text():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(StructuredFormatter())
    handler.addFilter(RequestIdFilter())
    root = logging.getLogger()
    old = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    yield stream.getvalue
    root.removeHandler(handler)
    root.setLevel(old)


def test_no_secret_value_is_logged_at_runtime(client, raw_client, log_text):
    raw_client.post("/api/auth/login", json={"username": "admin", "password": WRONG_PW})
    raw_client.post("/api/auth/login", json={"username": "nobody-x", "password": WRONG_PW})
    raw_client.get(f"/api/health?token={QUERY_TOKEN}&password={QUERY_TOKEN}")
    raw_client.get("/api/auth/me", headers={"Cookie": f"spectra_session={BAD_COOKIE}"})
    raw_client.get("/api/audit/head", headers={"Authorization": f"Bearer {BAD_COOKIE}"})
    client.post("/api/users", json={"username": "scrub_probe", "password": NEW_USER_PW, "role": "VIEWER"})
    client.post("/api/users", json={"username": "scrub_probe", "password": NEW_USER_PW, "role": "VIEWER"})  # 409 path
    text = log_text()
    assert "http_request" in text, "the probe produced no request log lines - the test would be vacuous"
    for marker in (WRONG_PW, QUERY_TOKEN, BAD_COOKIE, NEW_USER_PW):
        assert marker not in text, f"secret marker leaked into logs: {marker[:6]}..."
