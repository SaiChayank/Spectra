"""Repository tests: batched writes, read-your-writes, bounded retention."""

from __future__ import annotations

import time

from spectra.db import (
    Database,
    FlowRepository,
    RetentionPolicy,
    WriteBuffer,
    migrate,
)
from spectra.pipeline import SpectraEngine
from spectra.store import Store

DAY = 86_400.0
# Large interval: disables the time trigger so tests control flush points.
NO_TICK = 10_000.0


def _record(i: int, ts: float, anomaly: bool = False) -> dict:
    return {
        "proto": "TCP",
        "src": f"10.0.0.{i % 250 + 1}:40000",
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


# -- batched writes / write throughput ---------------------------------------

def test_flows_commit_in_batches_not_per_row(tmp_path):
    now = time.time()
    batched = Store(str(tmp_path / "batched.db"), batch_size=50,
                    flush_interval=NO_TICK)
    per_row = Store(str(tmp_path / "perrow.db"), batch_size=1,
                    flush_interval=NO_TICK)
    try:
        for i in range(120):
            batched.save_flow(_record(i, now), score=12.0, anomaly=False)
        stats = batched.write_stats()
        assert stats["flushes"] == 2        # 100 rows in 2 transactions
        assert stats["staged"] == 20        # remainder waiting for the next flush
        assert stats["flow_rows"] == 100    # durable rows only; 20 more staged

        for i in range(120):
            per_row.save_flow(_record(i, now), score=12.0, anomaly=False)
        assert per_row.write_stats()["flushes"] == 120  # the old cost, for reference

        # same data, far fewer transactions: the DoD "throughput improved"
        assert batched.write_stats()["flushes"] < per_row.write_stats()["flushes"]

        batched.flush()
        assert batched.write_stats()["staged"] == 0
        assert batched.query_flows(limit=1)["count"] == 120
    finally:
        batched.close()
        per_row.close()


def test_reads_see_staged_rows(tmp_path):
    store = Store(str(tmp_path / "ryw.db"), batch_size=1000,
                  flush_interval=NO_TICK)
    try:
        for i in range(5):
            store.save_flow(_record(i, time.time()), score=12.0, anomaly=False)
        assert store.write_stats()["staged"] == 5   # nothing durable yet
        page = store.query_flows()
        assert page["count"] == 5                   # read flushed first
        assert store.write_stats()["staged"] == 0
        assert store.stats()["flows"] == 5          # stats flush too
    finally:
        store.close()


def test_close_and_finish_capture_make_staged_rows_durable(tmp_path):
    path = str(tmp_path / "durability.db")
    store = Store(path, batch_size=1000, flush_interval=NO_TICK)
    cid = store.start_capture("pcap", "demo.pcap")
    store.save_flow(_record(0, time.time()), score=12.0, anomaly=False,
                    capture_id=cid)
    store.finish_capture(cid, packets=10, flows=1, detections=0)
    assert store.write_stats()["staged"] == 0       # flushed at session end
    store.save_flow(_record(1, time.time()), score=12.0, anomaly=False)
    assert store.write_stats()["staged"] == 1
    store.close()

    reopened = Store(path)
    try:
        assert reopened.query_flows(limit=10)["count"] == 2
        session = reopened.recent_captures()[0]
        assert session["stopped_at"] is not None and session["flows"] == 1
    finally:
        reopened.close()


# -- events -------------------------------------------------------------------

def test_event_feed_round_trip_and_filter(tmp_path):
    store = Store(str(tmp_path / "events.db"), batch_size=1000,
                  flush_interval=NO_TICK)
    try:
        store.record_event("status", {"running": True})
        store.record_event("drift", {"psi": 0.1})
        store.record_event("evasion", {"score": 0.98})

        page = store.query_events(limit=10)
        assert page["count"] == 3
        assert page["items"][0]["type"] == "evasion"        # newest first
        only = store.query_events(type="drift")
        assert only["count"] == 1
        assert only["items"][0]["data"] == {"psi": 0.1}
    finally:
        store.close()


def test_event_feed_is_row_capped(tmp_path):
    store = Store(str(tmp_path / "evcap.db"), event_max_rows=10, batch_size=5,
                  flush_interval=NO_TICK)
    try:
        for i in range(30):
            store.record_event("status", {"i": i})
        store.flush()
        assert store.write_stats()["event_rows"] == 10
        page = store.query_events(limit=100)
        assert page["count"] == 10
        assert page["items"][0]["data"] == {"i": 29}  # newest survive
    finally:
        store.close()


def test_engine_persists_lifecycle_events_only(tmp_path):
    store = Store(str(tmp_path / "eng.db"))
    engine = SpectraEngine(model_path=str(tmp_path / "missing.joblib"),
                           store=store)
    try:
        engine.events.emit({"type": "status", "data": {"running": False}})
        engine.events.emit({"type": "flow", "data": {"proto": "TCP"}})
        engine.events.emit({"type": "detection", "data": {"proto": "TCP"}})
        engine.events.emit({"type": "drift", "data": {"psi": 0.01}})

        page = store.query_events(limit=10)
        assert page["count"] == 2                      # flow/detection skipped
        assert {it["type"] for it in page["items"]} == {"status", "drift"}
        assert store.query_flows()["count"] == 0       # no duplicated flow rows
    finally:
        store.close()


# -- retention ----------------------------------------------------------------

def test_flow_and_detection_retention_age_independently(tmp_path):
    now = time.time()
    store = Store(str(tmp_path / "age.db"), batch_size=1000,
                  flush_interval=NO_TICK)
    try:
        store.save_flow(_record(0, now - 100 * DAY), score=12.0, anomaly=False)
        store.save_flow(_record(1, now - 100 * DAY, anomaly=True), score=97.5,
                        anomaly=True)
        store.save_flow(_record(2, now - 10 * DAY), score=12.0, anomaly=False)
        store.flush()

        # benign history aged out; flagged evidence kept (policy 0 = keep)
        store.retention = RetentionPolicy(flow_retention_days=30.0,
                                          stale_session_hours=0.0)
        counts = store.run_retention()
        assert counts["flows"] == 1
        assert counts["detections"] == 0
        assert store.query_flows(limit=10)["count"] == 2

        # flagged rows run on their own, longer clock
        store.retention = RetentionPolicy(detection_retention_days=90.0,
                                          stale_session_hours=0.0)
        counts = store.run_retention()
        assert counts["detections"] == 1
        assert store.query_flows(limit=10)["count"] == 1
    finally:
        store.close()


def test_capture_retention_removes_only_finished_sessions(tmp_path):
    now = time.time()
    store = Store(str(tmp_path / "caps.db"))
    try:
        # a session a crashed process left open 2 days ago
        store._conn.execute(
            "INSERT INTO captures (mode, source, started_at) VALUES (?, ?, ?)",
            ("pcap", "crashed.pcap", now - 2 * DAY))
        # a finished session from 100 days ago
        store._conn.execute(
            "INSERT INTO captures (mode, source, started_at, stopped_at) "
            "VALUES (?, ?, ?, ?)",
            ("pcap", "old.pcap", now - 100 * DAY, now - 100 * DAY + 60))
        store._conn.commit()

        counts = store.run_retention()   # default policy sweeps stale sessions
        assert counts["stale_sessions"] == 1
        swept = [r for r in store.recent_captures() if r["source"] == "crashed.pcap"][0]
        assert swept["stopped_at"] is not None
        assert "stale session" in swept["error"]

        store.retention = RetentionPolicy(capture_retention_days=30.0,
                                          stale_session_hours=0.0)
        counts = store.run_retention()
        assert counts["captures"] == 1               # only the 100-day session
        sources = {r["source"] for r in store.recent_captures()}
        assert sources == {"crashed.pcap"}           # swept one still recent
    finally:
        store.close()


def test_stale_session_closed_when_store_opens(tmp_path):
    path = str(tmp_path / "stale.db")
    store = Store(path)
    store._conn.execute(
        "INSERT INTO captures (mode, source, started_at) VALUES (?, ?, ?)",
        ("live", "x.pcap", time.time() - 2 * DAY))
    store._conn.commit()
    store.close()

    reopened = Store(path)   # startup sweep runs before any capture exists
    try:
        row = reopened.recent_captures()[0]
        assert row["stopped_at"] is not None
        assert "stale session" in row["error"]
        assert row["status"] == "FAILED"
    finally:
        reopened.close()


def test_uploaded_captures_are_not_swept_as_stale_sessions(tmp_path):
    """An import waiting to be processed is a resource, not an open session."""
    now = time.time()
    store = Store(str(tmp_path / "uploaded.db"))
    try:
        cid = store.insert_capture_resource(
            original_name="pending.pcap", stored_name="cap_deadbeef.pcap",
            size_bytes=123, content_hash="h" * 64, source="pending.pcap",
            imported_at=now - 100 * DAY)    # imported ages ago, never run
        counts = store.run_retention()      # default policy sweeps stale
        assert counts["stale_sessions"] == 0

        row = store.get_capture(cid)
        assert row["stopped_at"] is None
        assert row["status"] == "UPLOADED"

        # ...but a *finished* upload ages out with capture retention
        store.finish_capture(cid, packets=1, flows=1, detections=0)
        store.retention = RetentionPolicy(capture_retention_days=30.0,
                                          stale_session_hours=0.0)
        counts = store.run_retention()
        assert counts["captures"] == 1
        assert store.get_capture(cid) is None
    finally:
        store.close()


def test_finish_capture_records_the_lifecycle_status(tmp_path):
    store = Store(str(tmp_path / "status.db"))
    try:
        natural = store.start_capture("pcap", "done.pcap")
        store.finish_capture(natural, packets=1, flows=1, detections=0)
        assert store.get_capture(natural)["status"] == "COMPLETED"

        stopped = store.start_capture("live", "eth0")
        store.finish_capture(stopped, packets=2, flows=0, detections=0,
                             status="STOPPED")
        assert store.get_capture(stopped)["status"] == "STOPPED"

        broken = store.start_capture("pcap", "bad.pcap")
        store.finish_capture(broken, packets=0, flows=0, detections=0,
                             error="cannot read", status="STOPPED")
        row = store.get_capture(broken)
        assert row["status"] == "FAILED" and row["error"] == "cannot read"
    finally:
        store.close()


def test_retention_never_prunes_audit_entries(tmp_path):
    store = Store(str(tmp_path / "audit-age.db"))
    try:
        old = time.time() - 400 * DAY
        for seq, prev, hsh in ((1, "genesis", "h1"), (2, "h1", "h2")):
            store.audit_insert(seq=seq, ts=old, kind="test", actor="tester",
                               payload_json="{}", leaves_json=None,
                               prev_hash=prev, entry_hash=hsh)
        before = store.audit_count()

        store.retention = RetentionPolicy(
            flow_retention_days=1.0, detection_retention_days=1.0,
            capture_retention_days=1.0, event_retention_days=1.0,
            stale_session_hours=1.0)
        counts = store.run_retention()
        assert counts == {"stale_sessions": 0, "captures": 0, "detections": 0,
                          "flows": 0, "events": 0}

        # hash-chain rows intact: still verifiable from seq 1
        assert store.audit_count() == before
        assert store.audit_get(1)["entry_hash"] == "h1"
        assert store.audit_head()["seq"] == 2
    finally:
        store.close()


# -- repositories used directly (data layer, no facade) ----------------------

def test_flow_repository_bounds_itself_with_the_row_cap(tmp_path):
    db = Database(str(tmp_path / "cap.db"))
    migrate(db)
    buffer = WriteBuffer(db, batch_size=1000, flush_interval=NO_TICK)
    repo = FlowRepository(db, buffer, max_rows=10)
    try:
        now = time.time()
        for i in range(25):
            repo.enqueue(_record(i, now), score=12.0, anomaly=False)
        buffer.flush()
        assert repo.rows == 10 and repo.count() == 10
        page = repo.query(limit=50)
        assert page["count"] == 10
        assert {it["id"] for it in page["items"]} == set(range(16, 26))  # newest kept
    finally:
        db.close()
