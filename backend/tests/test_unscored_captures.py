"""A capture processed while no model is trained must say so (Phase 11 drill finding 7).

Before: the capture completed with 0 detections and no sign that no flow was scored.  Now the capture resource reports
``unscored_flows`` (flows stored with no score) and a ``warnings`` list; both are empty/zero when a model scored the flows.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from spectra.api.app import app, engine
from spectra.demo import make_baseline_pcap, make_suspicious_pcap
from spectra.ml.model import SpectraDetector

client = TestClient(app)


def _run(tmp_path, upload_capture, process_capture, name):
    pcap = make_suspicious_pcap(str(tmp_path / name), seed=hash(name) % 1000)
    cid = upload_capture(client, pcap)["capture_id"]
    return process_capture(client, cid)


def test_untrained_model_marks_the_capture(tmp_path, upload_capture, process_capture):
    saved = engine.model.detector
    engine.model.detector = SpectraDetector()          # untrained
    try:
        det = _run(tmp_path, upload_capture, process_capture, "u.pcap")
    finally:
        engine.model.detector = saved
    assert det["status"] == "COMPLETED"
    assert det["flows"] > 0 and det["detections"] == 0
    assert det["unscored_flows"] == det["flows"]
    assert det["warnings"] and "not trained" in det["warnings"][0]


def test_trained_model_leaves_no_warning(tmp_path, upload_capture, process_capture):
    base = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=40)
    cid = upload_capture(client, base)["capture_id"]
    assert client.post("/api/model/train", json={"capture_id": cid, "contamination": 0.05}).status_code == 200
    det = _run(tmp_path, upload_capture, process_capture, "t.pcap")
    assert det["status"] == "COMPLETED" and det["flows"] > 0
    assert det["unscored_flows"] == 0
    assert det["warnings"] == []
