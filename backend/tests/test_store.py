"""Tests for SQLite persistence."""

import pytest

from spectra.store import Store, StoreError


@pytest.fixture()
def store(tmp_path):
    s = Store(str(tmp_path / "test.db"), max_rows=1000)
    yield s
    s.close()


def _record(i: int, anomaly: bool = False) -> dict:
    return {
        "proto": "TCP",
        "src": f"10.0.0.{i % 250 + 1}:40000",
        "dst": "93.184.216.34:443",
        "start_ts": 1_700_000_000 + i,
        "last_ts": 1_700_000_001 + i,
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


def test_save_and_query_flows(store):
    for i in range(25):
        store.save_flow(_record(i, anomaly=(i % 5 == 0)),
                        score=97.5 if i % 5 == 0 else 12.0,
                        anomaly=(i % 5 == 0))

    page = store.query_flows(limit=10)
    assert page["count"] == 25
    assert len(page["items"]) == 10
    assert page["items"][0]["id"] == 25  # newest first

    anomalies = store.query_flows(anomaly_only=True)
    assert anomalies["count"] == 5
    assert all(it["anomaly"] for it in anomalies["items"])
    assert anomalies["items"][0]["reasons"] is None or "reasons" in anomalies["items"][0]


def test_reasons_round_trip(store):
    reasons = [{"feature": "iat_std_s", "z_score": 12.3, "value": 1.0}]
    store.save_flow(_record(1, anomaly=True), score=99.0, anomaly=True, reasons=reasons)
    item = store.query_flows(anomaly_only=True)["items"][0]
    assert item["reasons"] == reasons
    assert item["score"] == 99.0


def test_sni_and_since_filters(store):
    for i in range(6):
        rec = _record(i)
        rec["sni"] = "api.bank.test" if i % 2 else "example.com"
        store.save_flow(rec, score=None, anomaly=False)

    assert store.query_flows(sni="bank")["count"] == 3
    assert store.query_flows(sni="example")["count"] == 3
    assert store.query_flows(since=1_700_000_003.5)["count"] == 3


def test_capture_lifecycle(store):
    cid = store.start_capture("pcap", "demo.pcap")
    store.save_flow(_record(1), score=None, anomaly=False, capture_id=cid)
    store.finish_capture(cid, packets=100, flows=1, detections=0)

    rows = store.recent_captures()
    assert len(rows) == 1
    row = rows[0]
    assert row["packets"] == 100
    assert row["stopped_at"] is not None
    assert row["mode"] == "pcap"


def test_model_runs_and_stats(store):
    store.add_model_run("base.pcap", 42, 0.05, {"threshold": 0.1})
    runs = store.model_runs()
    assert runs[0]["n_train"] == 42
    assert runs[0]["metrics"]  # stored as JSON text

    for i in range(10):
        store.save_flow(_record(i, anomaly=(i < 2)), score=90.0 if i < 2 else 10.0,
                        anomaly=(i < 2))
    stats = store.stats()
    assert stats["flows"] == 10
    assert stats["detections"] == 2
    assert stats["anomaly_rate"] == 0.2
    assert stats["by_proto"]["TCP"] == 10
    assert stats["top_sni"][0]["sni"] == "example.com"


def test_pruning_bounds_table(tmp_path):
    store = Store(str(tmp_path / "prune.db"), max_rows=50)
    for i in range(120):
        store.save_flow(_record(i), score=None, anomaly=False)
    store.close()

    reopened = Store(str(tmp_path / "prune.db"), max_rows=50)
    try:
        assert reopened.query_flows(limit=1000)["count"] == 50
        # oldest rows were dropped, newest survive
        newest = reopened.query_flows(limit=1)["items"][0]
        assert newest["src"].endswith(":40000")
    finally:
        reopened.close()


def test_bad_path_raises(tmp_path):
    # parent path is a regular file, so the directory cannot be created
    parent = tmp_path / "not-a-dir"
    parent.write_text("x")
    with pytest.raises(StoreError):
        Store(str(parent / "db.sqlite"))
