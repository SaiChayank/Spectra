"""Operational storage failures: busy / full answer 503, never a 500 or a leak."""

from __future__ import annotations

import errno
import os
import sqlite3
import stat

import pytest

from spectra.api.app import app, engine
from spectra.db.connection import Database, StoreUnavailable, _wrap

from .conftest import ADMIN_PASSWORD, ADMIN_USERNAME

_USER = {"password": "Str0ng-Passw0rd!x", "role": "VIEWER"}


def _assert_plain_503(res):
    assert res.status_code == 503, res.text
    assert res.headers["retry-after"]
    assert res.json() == {"detail": "storage temporarily unavailable"}


def test_locked_database_write_returns_503_reads_and_health_work(client):
    db = engine.store._db
    db.conn.execute("PRAGMA busy_timeout=100")           # keep the test fast
    other = sqlite3.connect(engine.config.db_path, timeout=1, isolation_level=None)
    other.execute("BEGIN EXCLUSIVE")
    try:
        res = client.post("/api/users", json={"username": "locked-user", **_USER})
        _assert_plain_503(res)
        assert "locked" not in res.text and "INSERT" not in res.text
        assert client.get("/api/stats").status_code == 200   # reads keep working
        health = client.get("/api/health")
        assert health.status_code == 200                      # busy, not unhealthy
        assert health.json()["writable"]["database"] == "busy"
    finally:
        other.execute("ROLLBACK")
        other.close()
        db.conn.execute("PRAGMA busy_timeout=5000")
    res = client.post("/api/users", json={"username": "locked-user2", **_USER})
    assert res.status_code == 200, res.text                  # recovers, no restart


def test_disk_full_login_returns_503(raw_client, monkeypatch):
    real = Database.execute

    def full(self, sql, params=()):
        if sql.lstrip().upper().startswith(("INSERT", "UPDATE")):
            raise _wrap(sqlite3.OperationalError("database or disk is full"))
        return real(self, sql, params)

    monkeypatch.setattr(Database, "execute", full)
    res = raw_client.post("/api/auth/login", json={
        "username": ADMIN_USERNAME, "password": ADMIN_PASSWORD})
    _assert_plain_503(res)
    assert "disk" not in res.text


def test_enospc_oserror_returns_503(client):
    def enospc():
        raise OSError(errno.ENOSPC, "No space left on device", "/secret/path")

    app.add_api_route("/api/_t_enospc", enospc)
    # first, ahead of the web UI's catch-all route (present when the frontend is built)
    app.router.routes.insert(0, app.router.routes.pop())
    try:
        res = client.get("/api/_t_enospc")
    finally:
        app.router.routes.pop(0)
    _assert_plain_503(res)
    assert "secret" not in res.text


def test_wrap_only_maps_busy_and_full():
    assert isinstance(_wrap(sqlite3.OperationalError("database is locked")), StoreUnavailable)
    assert not isinstance(_wrap(sqlite3.OperationalError("no such table: x")), StoreUnavailable)


def test_health_reports_writable_and_leaves_no_files(client):
    before = sorted(os.listdir(engine.config.data_dir))
    body = client.get("/api/health").json()
    assert body["ok"] is True and body["writable"] == {"data_dir": "ok", "database": "ok"}
    assert sorted(os.listdir(engine.config.data_dir)) == before


def test_health_503_when_probe_fails(client, monkeypatch):
    def boom(*a, **k):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr("spectra.services.system.os.open", boom)
    res = client.get("/api/health")
    assert res.status_code == 503
    body = res.json()
    assert body["ok"] is False and body["writable"]["data_dir"] == "failed"
    assert "space" not in res.text


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory modes")
def test_health_503_on_read_only_data_dir(client):
    d = engine.config.data_dir
    mode = stat.S_IMODE(os.stat(d).st_mode)
    os.chmod(d, 0o500)
    try:
        res = client.get("/api/health")
    finally:
        os.chmod(d, mode)
    assert res.status_code == 503 and res.json()["writable"]["data_dir"] == "failed"
