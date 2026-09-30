"""API smoke tests (in-process, no server needed)."""

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


def test_capture_lifecycle_and_stats(tmp_path, upload_capture,
                                     process_capture):
    baseline = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=30)
    suspicious = make_suspicious_pcap(str(tmp_path / "s.pcap"))

    # train through the API on a managed capture (no filesystem paths)
    base_id = upload_capture(client, baseline)["capture_id"]
    res = client.post("/api/model/train",
                      json={"capture_id": base_id, "contamination": 0.05})
    assert res.status_code == 200, res.text
    assert res.json()["n_train"] >= 30

    # import + process a pcap capture through the managed workflow
    cap_id = upload_capture(client, suspicious)["capture_id"]
    res = client.post(f"/api/captures/{cap_id}/process")
    assert res.status_code == 200, res.text
    det = process_capture(client, cap_id)
    assert det["status"] == "COMPLETED"
    assert det["flows"] >= 12
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
    """The path-driven pcap start no longer exists: pcap mode is 422."""
    res = client.post("/api/capture/start", json={"mode": "pcap"})
    assert res.status_code == 422
    res = client.post("/api/capture/start", json={"mode": "pcap", "path": "/nope.pcap"})
    assert res.status_code == 422


def test_metrics_endpoint():
    """Prometheus text exposition as real plaintext, not JSON-encoded text."""
    res = client.get("/api/metrics")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/plain")
    text = res.text
    # JSON-encoding would wrap samples in quotes and escapes
    assert not text.lstrip().startswith('"')
    assert "spectra_packets_total " in text
    assert "spectra_flows_total " in text
    assert "spectra_model_trained " in text
    assert "spectra_queue_packets_dropped " in text
    assert "spectra_queue_max_depth " in text
    # every sample line must be `name[{labels}] <float>`
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        sample, sep, value = line.rpartition(" ")
        assert sep == " " and sample, line
        float(value)  # raises if the value is not numeric


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
