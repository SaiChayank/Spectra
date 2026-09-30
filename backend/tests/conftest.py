"""Shared test helpers: hermetic app wiring + authentication plumbing.

Responsibilities, in order of execution:

1. **Hermetic data directory** - ``SPECTRA_DATA_DIR`` points at a fresh temp
   directory *before* any ``spectra`` import, so the shared API engine, its
   bootstrap admin, the capture store and the audit key never touch the
   developer's dev database, and every pytest session starts from an empty
   deterministic database (admin password set below).
2. **Eager admin session** - the suite long predates authentication: its
   hundreds of assertions assume requests just work. One admin login runs at
   import, and every ``TestClient`` constructed afterwards starts with that
   session cookie. Auth tests opt out explicitly (``raw_client``,
   ``login_as``), so both styles coexist without weakening the API tests:
   they still exercise every route, just as ADMIN.
3. **Capture fixtures** - the managed-capture contract (bytes up via
   multipart, then capture ids only; teardown removes rows + files).
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
import time

import pytest

# -- 1. hermetic data dir (must precede any spectra import) -------------------

_TEST_DATA_DIR = tempfile.mkdtemp(prefix="spectra_tests_")
os.environ["SPECTRA_DATA_DIR"] = _TEST_DATA_DIR
# Deterministic bootstrap credential for THIS test process only (the dev
# server keeps whatever password its own environment bootstrapped).
os.environ["SPECTRA_ADMIN_PASSWORD"] = "spectra-test-admin-pw"
atexit.register(lambda: shutil.rmtree(_TEST_DATA_DIR, ignore_errors=True))

# -- 2. app + eager admin session --------------------------------------------

from fastapi.testclient import TestClient as _BaseTestClient  # noqa: E402

import spectra.api.app as app_module  # noqa: E402  (migrations + bootstrap)
from spectra.api.security import SESSION_COOKIE  # noqa: E402

_app = app_module.app
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = os.environ["SPECTRA_ADMIN_PASSWORD"]
_admin_session: dict[str, str | None] = {"token": None}


def _login(client, username: str, password: str):
    return client.post("/api/auth/login",
                       json={"username": username, "password": password})


_res = _login(_BaseTestClient(_app), ADMIN_USERNAME, ADMIN_PASSWORD)
assert _res.status_code == 200, (
    f"admin bootstrap login failed during test setup: "
    f"{_res.status_code} {_res.text}")
_admin_session["token"] = _res.cookies.get(SESSION_COOKIE)


class _AuthedTestClient(_BaseTestClient):
    """TestClient that carries the session-scoped admin cookie by default."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if _admin_session["token"]:
            self.cookies.set(SESSION_COOKIE, _admin_session["token"])


# Test modules do `from fastapi.testclient import TestClient` at import time;
# pytest imports this conftest first, so they pick up the authed variant.
import fastapi.testclient as _ftc  # noqa: E402

_ftc.TestClient = _AuthedTestClient


# -- auth fixtures for the role-matrix tests ---------------------------------

@pytest.fixture
def client():
    """Fresh admin-authenticated client for the shared app (conftest patch
    also injects the session cookie; this exists so tests can request it as
    an explicit fixture)."""
    return _AuthedTestClient(_app)


@pytest.fixture
def raw_client():
    """A client with **no** session (unauthenticated request patterns)."""
    client = _AuthedTestClient(_app)
    client.cookies.clear()
    return client


@pytest.fixture(scope="session")
def role_accounts():
    """One known account per non-admin role, created once per session."""
    accounts = {
        "VIEWER": ("test_viewer", "viewer-pass-123"),
        "ANALYST": ("test_analyst", "analyst-pass-123"),
    }
    client = _BaseTestClient(_app)
    res = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert res.status_code == 200, res.text
    for role, (username, password) in accounts.items():
        res = client.post("/api/users", json={
            "username": username, "password": password, "role": role})
        assert res.status_code in (200, 409), f"{role}: {res.text}"
    return accounts


@pytest.fixture
def login_as():
    """Factory: fresh unauthenticated client, logged in as the given user."""

    def _login_as(username: str, password: str):
        client = _AuthedTestClient(_app)
        client.cookies.clear()
        res = _login(client, username, password)
        assert res.status_code == 200, (
            f"login as {username} failed: {res.status_code} {res.text}")
        return client

    return _login_as


@pytest.fixture
def viewer_client(role_accounts, login_as):
    """Signed in as a VIEWER (read-only role)."""
    username, password = role_accounts["VIEWER"]
    return login_as(username, password)


@pytest.fixture
def analyst_client(role_accounts, login_as):
    """Signed in as an ANALYST (investigate + incidents, no capture/users)."""
    username, password = role_accounts["ANALYST"]
    return login_as(username, password)


# -- capture fixtures ---------------------------------------------------------

@pytest.fixture
def upload_capture():
    """Upload a local PCAP through ``POST /api/captures``; returns the body.

    The response body carries the generated ``capture_id`` plus the metadata
    to assert on. The capture is deleted (row + stored file) when the test
    ends, so the shared capture store does not accumulate test fixtures.
    """
    pending: list[tuple[object, int]] = []

    def _upload(client, path: str, filename: str | None = None) -> dict:
        name = filename or os.path.basename(path)
        with open(path, "rb") as fh:
            data = fh.read()

        def post():
            return client.post(
                "/api/captures",
                files={"file": (name, data, "application/octet-stream")})

        res = post()
        if res.status_code == 409:
            # Identical bytes already stored (leftover from an earlier run -
            # the demo pcaps are deterministic). Replace that stale resource
            # so this import yields a fresh, unprocessed capture.
            detail = res.json().get("detail")
            assert isinstance(detail, dict) and detail.get("capture_id"), res.text
            client.delete(f"/api/captures/{detail['capture_id']}")
            res = post()
        assert res.status_code == 200, res.text
        body = res.json()
        pending.append((client, int(body["capture_id"])))
        return body

    yield _upload

    for client, capture_id in pending:
        try:
            client.delete(f"/api/captures/{capture_id}")
        except Exception:  # noqa: BLE001 - teardown must never fail a test
            pass


@pytest.fixture
def process_capture():
    """Ensure a capture is processing, then wait for a terminal status.

    Tolerates the caller having already issued the process request (the row
    then reads PROCESSING); any other 409 - or a non-terminal timeout -
    fails the test.
    """

    def _process(client, capture_id: int, timeout: float = 45.0) -> dict:
        res = client.post(f"/api/captures/{capture_id}/process")
        if res.status_code != 200:
            det = client.get(f"/api/captures/{capture_id}").json()
            # Tolerate only "already started" (by the caller, or finished
            # between the two calls); UPLOADED here means it never started.
            assert res.status_code == 409 and det.get("status") != "UPLOADED", \
                f"{res.status_code}: {res.text} (status={det.get('status')})"
        deadline = time.time() + timeout
        while time.time() < deadline:
            det = client.get(f"/api/captures/{capture_id}").json()
            if det.get("status") in ("COMPLETED", "FAILED", "STOPPED"):
                return det
            time.sleep(0.05)
        raise AssertionError(
            f"capture {capture_id} never finished: "
            f"{client.get(f'/api/captures/{capture_id}').json()}")

    return _process
