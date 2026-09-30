"""Migration tests: legacy adoption, idempotency, FK rebuild, rollback."""

from __future__ import annotations

import json
import sqlite3
import time

import pytest

from spectra.db import (
    MIGRATIONS,
    Migration,
    StoreError,
    applied_migrations,
    migrate,
)
from spectra.db import migrations as migrations_mod
from spectra.store import Store

# The schema pre-migration releases shipped, verbatim: this is what an
# existing user database looks like on disk, so "upgrade without data loss"
# is tested against the real legacy shape instead of a guess.
LEGACY_SCHEMA = """
CREATE TABLE IF NOT EXISTS captures (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    mode        TEXT NOT NULL,
    source      TEXT,
    started_at  REAL NOT NULL,
    stopped_at  REAL,
    packets     INTEGER DEFAULT 0,
    flows       INTEGER DEFAULT 0,
    detections  INTEGER DEFAULT 0,
    error       TEXT
);
CREATE TABLE IF NOT EXISTS flows (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id  INTEGER,
    ts          REAL NOT NULL,
    proto       TEXT,
    src         TEXT,
    dst         TEXT,
    duration    REAL,
    packets     INTEGER,
    bytes       INTEGER,
    tls_version TEXT,
    sni         TEXT,
    alpn        TEXT,
    ja3         TEXT,
    ja4         TEXT,
    score       REAL,
    anomaly     INTEGER DEFAULT 0,
    reasons     TEXT,
    record      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts);
CREATE INDEX IF NOT EXISTS idx_flows_anomaly ON flows(anomaly, score);
CREATE INDEX IF NOT EXISTS idx_flows_sni ON flows(sni);
CREATE INDEX IF NOT EXISTS idx_flows_capture ON flows(capture_id);
CREATE TABLE IF NOT EXISTS model_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    trained_at    REAL NOT NULL,
    pcap          TEXT,
    n_train       INTEGER,
    contamination REAL,
    metrics       TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    seq        INTEGER PRIMARY KEY,
    ts         REAL NOT NULL,
    kind       TEXT NOT NULL,
    actor      TEXT,
    payload    TEXT NOT NULL,
    leaves     TEXT,
    prev_hash  TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_kind ON audit_log(kind, seq);
"""


def _record(i: int, ts: float, anomaly: bool = False) -> dict:
    return {
        "proto": "TCP",
        "src": f"10.0.0.{i + 1}:40000",
        "dst": "93.184.216.34:443",
        "start_ts": ts,
        "last_ts": ts,
        "duration": 1.0,
        "packets": 10,
        "bytes": 5000,
        "tls_version": "TLS 1.3",
        "sni": "example.com",
        "alpn": ["h2"],
        "ja3": "a" * 32,
        "ja4": "t13d0916h2_8daaf6152771_b0da82dd1658",
        "score": 97.5 if anomaly else 12.0,
        "anomaly": anomaly,
    }


def _legacy_insert(conn: sqlite3.Connection, capture_id: int | None, ts: float,
                   record: dict, score: float, anomaly: bool,
                   reasons: list | None = None) -> None:
    conn.execute(
        """INSERT INTO flows
           (capture_id, ts, proto, src, dst, duration, packets, bytes,
            tls_version, sni, alpn, ja3, ja4, score, anomaly, reasons, record)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (capture_id, ts, record["proto"], record["src"], record["dst"],
         record["duration"], record["packets"], record["bytes"],
         record["tls_version"], record["sni"], json.dumps(record["alpn"]),
         record["ja3"], record["ja4"], score, 1 if anomaly else 0,
         json.dumps(reasons) if reasons else None, json.dumps(record)),
    )


def _write_legacy_db(path: str) -> dict:
    """Create a database exactly as the pre-migration release left it."""
    now = time.time()
    conn = sqlite3.connect(path)
    conn.executescript(LEGACY_SCHEMA)
    conn.execute(
        "INSERT INTO captures (mode, source, started_at, stopped_at, "
        "packets, flows, detections) VALUES ('pcap', 'demo.pcap', ?, ?, 10, 2, 1)",
        (now - 3600, now - 3500),
    )
    capture_id = conn.execute("SELECT id FROM captures").fetchone()[0]
    _legacy_insert(conn, capture_id, now - 60, _record(1, now - 60),
                   score=12.0, anomaly=False)
    reasons = [{"feature": "iat_std_s", "z_score": 5.0, "value": 1.0}]
    _legacy_insert(conn, capture_id, now - 30,
                   _record(2, now - 30, anomaly=True),
                   score=97.5, anomaly=True, reasons=reasons)
    # orphan: points at a capture row that no longer exists
    _legacy_insert(conn, 4242, now - 15, _record(3, now - 15),
                   score=12.0, anomaly=False)
    conn.execute(
        "INSERT INTO model_runs (trained_at, pcap, n_train, contamination, metrics) "
        "VALUES (?, 'base.pcap', 42, 0.05, ?)",
        (now - 7200, json.dumps({"threshold": 0.1})),
    )
    conn.execute(
        "INSERT INTO audit_log (seq, ts, kind, actor, payload, leaves, "
        "prev_hash, entry_hash) VALUES (1, ?, 'start', 'system', '{}', NULL, "
        "'g', 'h1')", (now - 7200,))
    conn.execute(
        "INSERT INTO audit_log (seq, ts, kind, actor, payload, leaves, "
        "prev_hash, entry_hash) VALUES (2, ?, 'alert', 'system', '{}', NULL, "
        "'h1', 'h2')", (now - 7100,))
    conn.commit()
    conn.close()
    return {"now": now, "capture_id": capture_id}


def _tables(store: Store) -> set[str]:
    return {r["name"] for r in store._db.query(
        "SELECT name FROM sqlite_master WHERE type='table'")}


def test_fresh_database_gets_full_schema(tmp_path):
    store = Store(str(tmp_path / "fresh.db"))
    try:
        assert {"captures", "flows", "model_runs", "audit_log", "events",
                "schema_migrations"} <= _tables(store)
        assert [v for v, _ in applied_migrations(store._db)] == [
            m.version for m in MIGRATIONS]
        assert store.schema_version == MIGRATIONS[-1].version
        assert store._db.conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert store._db.query("PRAGMA foreign_key_check") == []
        indexes = {r["name"] for r in store._db.query(
            "SELECT name FROM sqlite_master WHERE type='index' "
            "AND name LIKE 'idx_%'")}
        assert {"idx_flows_ts", "idx_flows_anomaly", "idx_flows_anomaly_ts",
                "idx_flows_capture", "idx_events_ts", "idx_events_type",
                "idx_captures_started", "idx_audit_kind"} <= indexes
    finally:
        store.close()


def test_migrations_apply_exactly_once(tmp_path):
    path = str(tmp_path / "once.db")
    Store(path).close()
    store = Store(path)
    try:
        assert migrate(store._db) == []          # nothing pending on reopen
        assert len(applied_migrations(store._db)) == len(MIGRATIONS)
    finally:
        store.close()


def test_legacy_database_upgrades_without_data_loss(tmp_path):
    path = str(tmp_path / "legacy.db")
    meta = _write_legacy_db(path)

    store = Store(path)
    try:
        # every existing row survived, with its original ids
        page = store.query_flows(limit=50)
        assert page["count"] == 3
        assert {it["id"] for it in page["items"]} == {1, 2, 3}
        assert store._db.query("SELECT COUNT(*) AS n FROM captures")[0]["n"] == 1
        assert store.model_runs()[0]["n_train"] == 42
        assert store.audit_count() == 2

        # flagged history still hydrates (reasons/record round-trip)
        anomaly = store.query_flows(anomaly_only=True)
        assert anomaly["count"] == 1
        assert anomaly["items"][0]["reasons"] == [
            {"feature": "iat_std_s", "z_score": 5.0, "value": 1.0}]
        assert anomaly["items"][0]["sni"] == "example.com"

        # the orphan reference was nulled, the two valid ones kept
        rows = store._db.query("SELECT id, capture_id FROM flows ORDER BY id")
        assert [r["capture_id"] for r in rows] == [
            meta["capture_id"], meta["capture_id"], None]
        assert store._db.query("PRAGMA foreign_key_check") == []
    finally:
        store.close()


def test_legacy_orphan_reference_is_nulled_not_dropped(tmp_path):
    path = str(tmp_path / "orphan.db")
    meta = _write_legacy_db(path)
    store = Store(path)
    try:
        rows = store._db.query(
            "SELECT id, capture_id FROM flows WHERE id = 3")
        assert rows[0]["capture_id"] is None          # reference cleaned
        assert store.query_flows(limit=50)["count"] == 3  # row kept
        assert store._db.query("PRAGMA foreign_key_check") == []
        # id sequence continues after the rebuild (no id reuse/collision)
        store.save_flow(_record(9, meta["now"]), score=None, anomaly=False)
        store.flush()
        newest = store.query_flows(limit=1)["items"][0]
        assert newest["id"] == 4
    finally:
        store.close()


def test_legacy_audit_and_schema_version(tmp_path):
    path = str(tmp_path / "legacy2.db")
    _write_legacy_db(path)
    store = Store(path)
    try:
        assert store.schema_version == MIGRATIONS[-1].version
        head = store.audit_head()
        assert head["seq"] == 2 and head["entry_hash"] == "h2"
        assert "events" in _tables(store)   # new table added on upgrade
    finally:
        store.close()


def test_v4_adds_capture_resource_columns_and_backfills(tmp_path):
    """v4 adds managed-resource columns; historical rows are classified, not lost."""
    path = str(tmp_path / "resources.db")
    _write_legacy_db(path)
    # two more legacy-shape rows: one crashed open, one that errored
    conn = sqlite3.connect(path)
    conn.execute(
        "INSERT INTO captures (mode, source, started_at) "
        "VALUES ('live', 'eth0', ?)", (time.time() - 2 * 86_400,))
    conn.execute(
        "INSERT INTO captures (mode, source, started_at, stopped_at, error) "
        "VALUES ('pcap', 'bad.pcap', ?, ?, 'unreadable file')",
        (time.time() - 7200, time.time() - 7100))
    conn.commit()
    conn.close()

    store = Store(path)
    try:
        assert store.schema_version == MIGRATIONS[-1].version
        rows = store._db.query("SELECT * FROM captures ORDER BY id")
        assert len(rows) == 3

        # backfilled from what the legacy schema recorded
        assert rows[0]["status"] == "COMPLETED"    # stopped_at was set
        assert rows[1]["status"] == "FAILED"       # still open -> errored
        assert "stale session" in rows[1]["error"] # swept at open, with status
        assert rows[2]["status"] == "FAILED" and rows[2]["error"] == "unreadable file"
        assert rows[0]["source_type"] == "path"
        assert rows[1]["source_type"] == "live"
        assert rows[2]["source_type"] == "path"
        # untouched metadata columns stay NULL/0 (nothing invented)
        for r in rows:
            assert r["original_name"] is None and r["stored_name"] is None
            assert r["size_bytes"] == 0 and r["imported_at"] is None
            assert r["content_hash"] is None

        # managed rows then use the new columns end to end
        cid = store.insert_capture_resource(
            original_name="n.pcap", stored_name="cap_abc.pcap",
            size_bytes=10, content_hash="h" * 64, source="n.pcap",
            imported_at=time.time())
        assert store.get_capture(cid)["status"] == "UPLOADED"
        assert store.list_captures(status="UPLOADED")["count"] == 1
        assert store.stored_capture_names() == {"cap_abc.pcap"}

        indexes = {r["name"] for r in store._db.query(
            "SELECT name FROM sqlite_master WHERE type='index'")}
        assert "idx_captures_status" in indexes
    finally:
        store.close()


def test_foreign_keys_enforce_capture_references(tmp_path):
    store = Store(str(tmp_path / "fk.db"))
    try:
        store.save_flow(_record(0, time.time()), score=1.0, anomaly=False,
                        capture_id=999_999)
        with pytest.raises(StoreError):
            store.flush()
        assert store.query_flows()["count"] == 0   # failed batch left nothing
    finally:
        store.close()


def test_delete_capture_keeps_history_via_set_null(tmp_path):
    store = Store(str(tmp_path / "setnull.db"))
    try:
        cid = store.start_capture("pcap", "x.pcap")
        store.save_flow(_record(0, time.time()), score=1.0, anomaly=False,
                        capture_id=cid)
        store.flush()
        store._conn.execute("DELETE FROM captures WHERE id = ?", (cid,))
        store._conn.commit()
        assert store._db.query("SELECT capture_id FROM flows")[0][
            "capture_id"] is None
        assert store.query_flows(limit=50)["count"] == 1  # history untouched
    finally:
        store.close()


def test_failed_migration_rolls_back_and_is_not_recorded(tmp_path, monkeypatch):
    path = str(tmp_path / "boom.db")
    Store(path).close()   # schema current before the failure

    def _boom(db) -> None:
        db.execute("CREATE TABLE boom (x INTEGER)")
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(migrations_mod, "MIGRATIONS",
                        (*MIGRATIONS, Migration(999, "boom", _boom)))
    with pytest.raises(StoreError, match="migration 999"):
        Store(path)
    monkeypatch.undo()

    store = Store(path)
    try:
        assert "boom" not in _tables(store)             # rolled back
        assert all(v != 999 for v, _ in applied_migrations(store._db))
        assert store.schema_version == MIGRATIONS[-1].version
    finally:
        store.close()


def test_v5_auth_tables_users_and_session_cascade(tmp_path):
    """v5: users/sessions exist, lookups are case-insensitive, and deleting
    an account cascades its sessions (FK ON)."""
    store = Store(str(tmp_path / "auth.db"))
    try:
        assert {"users", "sessions"} <= _tables(store)
        assert store.schema_version == MIGRATIONS[-1].version

        user = store.create_user("Alice", "scrypt$16384$8$1$c2FsdA==$aGFzaA==",
                                 "ANALYST")
        assert "password_hash" not in user              # public projection
        assert store.count_users() == 1
        assert store.find_user_credentials("aLiCe")["id"] == user["id"]
        assert store.find_user_credentials("missing") is None

        token_hash = "ab" * 32
        store.create_session(user["id"], token_hash, time.time() + 60)
        assert store.get_session(token_hash) is not None

        store.delete_user(user["id"])
        assert store.get_session(token_hash) is None    # ON DELETE CASCADE
        assert store.count_users() == 0
    finally:
        store.close()


def test_v6_incident_tables_detection_fk_and_guards(tmp_path):
    """v6: incidents/notes with an optional detection FK (SET NULL under flow
    retention) and guarded state transitions."""
    store = Store(str(tmp_path / "inc.db"))
    try:
        assert {"incidents", "incident_notes"} <= _tables(store)

        store.save_flow(_record(0, time.time()), score=9.0, anomaly=True)
        det_id = store.query_flows(limit=1, anomaly_only=True)["items"][0]["id"]

        inc = store.create_incident("suspicious", det_id, "alice")
        assert inc["status"] == "OPEN" and inc["detection_id"] == det_id
        store.add_incident_note(inc["id"], "bob", "on it")
        assert store.incident_note_count(inc["id"]) == 1

        assert store.acknowledge_incident(inc["id"], "bob")
        assert not store.acknowledge_incident(inc["id"], "bob")  # OPEN only
        assert store.resolve_incident(inc["id"], "bob")
        assert not store.resolve_incident(inc["id"], "bob")      # terminal

        # the flagged flow disappears (retention) - the incident survives
        store._conn.execute("DELETE FROM flows WHERE id = ?", (det_id,))
        store._conn.commit()
        assert store.get_incident(inc["id"])["detection_id"] is None
        assert store.incident_notes(inc["id"])[0]["author"] == "bob"
    finally:
        store.close()
