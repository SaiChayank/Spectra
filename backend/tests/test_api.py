"""API smoke tests (in-process, no server needed)."""

import time

from fastapi.testclient import TestClient

from spectra.api.app import app, engine
from spectra.demo import make_baseline_pcap, make_suspicious_pcap

client = TestClient(app)


def test_health_and_status():
    body = client.get("/api/health").json()
    assert body["ok"] is True and body["service"] == "spectra"
    assert body["version"]
    status = client.get("/api/status").json()
    assert "running" in status and "flows" in status


def test_model_info_before_training():
    info = client.get("/api/model").json()
    assert info["n_features"] > 10
    assert "feature_names" in info


def test_capture_lifecycle_and_stats(tmp_path):
    baseline = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=30)
    suspicious = make_suspicious_pcap(str(tmp_path / "s.pcap"))

    # train through the API
    res = client.post("/api/model/train",
                      json={"pcap_path": baseline, "contamination": 0.05})
    assert res.status_code == 200, res.text
    assert res.json()["n_train"] >= 30

    # start a pcap capture
    res = client.post("/api/capture/start", json={"mode": "pcap", "path": suspicious})
    assert res.status_code == 200, res.text

    deadline = time.time() + 30
    while engine.running and time.time() < deadline:
        time.sleep(0.05)
    assert not engine.running
    client.post("/api/capture/stop")

    stats = client.get("/api/stats").json()
    assert stats["status"]["error"] is None
    assert stats["totals"]["flows"] >= 12
    assert stats["totals"]["detections"] >= 1
    assert stats["timeline"]

    dets = client.get("/api/detections").json()
    assert dets["count"] >= 1
    assert all(d["score"] is not None for d in dets["items"])

    flows = client.get("/api/flows").json()
    assert flows["count"] >= 12


def test_bad_capture_requests(tmp_path):
    res = client.post("/api/capture/start", json={"mode": "pcap"})
    assert res.status_code == 400
    res = client.post("/api/capture/start", json={"mode": "pcap", "path": "/nope.pcap"})
    assert res.status_code == 400


def test_metrics_endpoint():
    text = client.get("/api/metrics").text
    assert "spectra_packets_total" in text
    assert "spectra_flows_total" in text
    assert "spectra_model_trained" in text


def test_history_endpoints(tmp_path):
    if engine.store is None:
        return  # persistence disabled in this environment
    flows = client.get("/api/history/flows?limit=5").json()
    assert flows["count"] >= 0
    assert len(flows["items"]) <= 5

    dets = client.get("/api/history/detections?limit=5").json()
    assert all(it["anomaly"] for it in dets["items"])

    stats = client.get("/api/history/stats").json()
    assert stats["flows"] >= 0 and "by_proto" in stats

    caps = client.get("/api/history/captures").json()
    assert isinstance(caps["items"], list)

    runs = client.get("/api/history/model-runs").json()
    assert isinstance(runs["items"], list)
