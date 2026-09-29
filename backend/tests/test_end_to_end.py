"""End-to-end: train on a benign baseline, then detect odd flows in a PCAP."""

import time

from spectra.pipeline import SpectraEngine

from spectra.demo import make_baseline_pcap, make_suspicious_pcap


def test_train_and_scan(tmp_path):
    baseline = make_baseline_pcap(str(tmp_path / "baseline.pcap"), n_flows=40)
    suspicious = make_suspicious_pcap(str(tmp_path / "suspicious.pcap"))
    model_path = str(tmp_path / "model.joblib")

    engine = SpectraEngine(model_path=model_path, idle_timeout=30.0)
    info = engine.train_from_pcap(baseline, contamination=0.05)
    assert info["n_train"] >= 40

    # Model persisted and reloadable
    reloaded = SpectraEngine(model_path=model_path)
    assert reloaded.detector.is_trained

    detections = []
    engine.subscribe(lambda e: detections.append(e["data"]) if e["type"] == "detection" else None)
    engine.start("pcap", path=suspicious)
    deadline = time.time() + 30
    while engine.running and time.time() < deadline:
        time.sleep(0.05)
    assert not engine.running, "capture did not finish"

    assert engine.status["error"] is None
    assert engine.status["flows"] >= 12
    assert detections, "no anomalies detected in suspicious traffic"
    assert all(d["score"] is not None and d["score"] > 50 for d in detections)

    # Beacon flows (no TLS, periodic timing) must be among the detections.
    beacon_hits = [d for d in detections if d["sni"] is None]
    assert beacon_hits, f"expected beacon flows to be flagged, got {detections}"

    # Stats/reporting surface is coherent
    snap = engine.snapshot()
    assert snap["totals"]["flows"] == engine.status["flows"]
    assert snap["totals"]["detections"] == len(detections)
    assert snap["timeline"], "timeline buckets missing"
    assert snap["model"]["trained"] is True


def test_scanning_without_model_records_flows(tmp_path):
    suspicious = make_suspicious_pcap(str(tmp_path / "s.pcap"), n_benign=3, n_beacons=2)
    engine = SpectraEngine(model_path=str(tmp_path / "missing.joblib"))
    engine.start("pcap", path=suspicious)
    deadline = time.time() + 30
    while engine.running and time.time() < deadline:
        time.sleep(0.05)
    assert not engine.running
    assert engine.status["flows"] >= 5
    assert engine.status["detections"] == 0
