"""Phase tests: federated privacy, metrics format, queue telemetry,
capability metadata, and optional-module failure isolation."""

import time

from fastapi.testclient import TestClient

from spectra.api.app import app

client = TestClient(app)


# -- federated privacy -------------------------------------------------------


def test_federated_api_returns_only_safe_summary():
    res = client.post("/api/tee/federate",
                      json={"deltas": [[0.1, 0.2], [0.3, 0.4]],
                            "shareholders": 3})
    assert res.status_code == 200, res.text
    body = res.json()

    # share material and the round seed must never leave the process
    for secret in ("party_shares", "aggregate_shares", "seed"):
        assert secret not in body, f"{secret} leaked through the API"

    # safe summary fields
    assert body["round_id"] and len(body["round_id"]) == 32
    assert body["parties"] == 2
    assert body["shareholders"] == body["threshold"] == 3
    assert body["exact"] is True and body["verified"] is True
    assert len(body["aggregate_digest"]) == 64
    assert body["capability"] == "SIMULATED"
    assert isinstance(body["aggregate"], list) and body["aggregate"]
    assert body["claims"]["raw_data_egress"] == 0


def test_federated_engine_surface_is_safe(tmp_path):
    """CLI and engine consumers get the same sanitized report."""
    from spectra.pipeline import SpectraEngine

    engine = SpectraEngine(model_path=str(tmp_path / "m.joblib"), persist=False)
    report = engine.tee_federate(deltas=[[0.1, 0.2], [0.3, 0.4]],
                                 shareholders=2)
    assert report["exact"] is True
    for secret in ("party_shares", "aggregate_shares", "seed"):
        assert secret not in report


def test_federated_internal_layer_keeps_shares_for_validation():
    """Simulation/testing layer retains full secret-sharing detail."""
    from spectra.modules.tee import federated_round, public_report, recombine

    report = federated_round([[0.1, 0.2], [0.3, 0.4]],
                             shareholders=3, seed=5)
    # internal validation still has everything it needs
    assert len(report["party_shares"]) == 2
    assert len(report["aggregate_shares"]) == 3
    assert report["round_id"] and report["aggregate_digest"]
    agg = recombine(report["aggregate_shares"], k=3)
    assert agg  # k-of-k recombination works internally

    safe = public_report(report)
    for secret in ("party_shares", "aggregate_shares", "seed"):
        assert secret not in safe
    assert safe["aggregate_digest"] == report["aggregate_digest"]
    assert safe["aggregate"] == report["aggregate"]


# -- live-capture queue telemetry ---------------------------------------------


def test_live_source_counts_received_queued_dropped():
    from spectra.capture.live import LiveSource

    src = LiveSource(queue_size=2)
    try:
        zero = src.stats()
        assert zero == {"packets_received": 0, "packets_queued": 0,
                        "packets_dropped": 0, "queue_depth": 0,
                        "max_queue_depth": 0}
        for _ in range(4):
            src._on_packet(object())  # noqa: SLF001 - drive the sniffer hook
        s = src.stats()
        assert s["packets_received"] == 4
        assert s["packets_queued"] == 2
        assert s["packets_dropped"] == 2       # queue full -> counted, not silent
        assert s["queue_depth"] == 2
        assert s["max_queue_depth"] == 2
    finally:
        src.close()


def test_engine_exposes_queue_stats_and_file_source_zeros(tmp_path):
    from spectra.demo import make_baseline_pcap
    from spectra.pipeline import SpectraEngine

    engine = SpectraEngine(model_path=str(tmp_path / "m.joblib"), persist=False)
    assert engine.status["queue"]["packets_dropped"] == 0
    assert engine.status["failures"] == {}

    baseline = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=10)
    engine.start("pcap", path=baseline)
    deadline = time.time() + 30
    while engine.running and time.time() < deadline:
        time.sleep(0.05)
    assert not engine.running

    q = engine.status["queue"]
    assert set(q) == {"packets_received", "packets_queued", "packets_dropped",
                      "queue_depth", "max_queue_depth"}
    # file sources have no internal queue -> zero drops
    assert q["packets_dropped"] == 0

    # metrics expose the same telemetry
    text = client.get("/api/metrics").text
    assert "spectra_queue_packets_dropped 0" in text


# -- capability metadata ------------------------------------------------------


def test_capabilities_endpoint_reports_maturity():
    from spectra.capabilities import CAPABILITIES

    res = client.get("/api/capabilities")
    assert res.status_code == 200
    body = res.json()
    assert set(body["statuses"]) == set(CAPABILITIES)
    mods = body["modules"]
    assert mods["tee"]["status"] == "SIMULATED"
    assert mods["tee"]["hardware_backed"] is False
    assert mods["edge_deployment"]["status"] == "SIMULATED"
    assert mods["federated"]["status"] == "SIMULATED"
    assert mods["audit"]["status"] == "EXPERIMENTAL"
    # nothing in this build may claim hardware backing
    assert all(m["status"] != "HARDWARE_BACKED" for m in mods.values())
    assert body["hardware_backed_count"] == 0
    for entry in mods.values():
        assert entry["note"]


def test_edge_deploy_response_marks_simulated_capability():
    res = client.post("/api/edge/deploy",
                      json={"node": "mec-int-test", "slice": "urllc"})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["capability"] == "SIMULATED"
    assert body["node"] == "mec-int-test"


# -- optional-module failure isolation -----------------------------------------


def test_module_failures_do_not_stop_capture(tmp_path, monkeypatch):
    import spectra.services.detection as detection_mod
    from spectra.demo import make_baseline_pcap, make_suspicious_pcap
    from spectra.pipeline import SpectraEngine

    baseline = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=30)
    suspicious = make_suspicious_pcap(str(tmp_path / "s.pcap"))
    engine = SpectraEngine(model_path=str(tmp_path / "m.joblib"), persist=False)
    engine.train_from_pcap(baseline, contamination=0.05)

    def boom(*_args, **_kwargs):
        raise RuntimeError("simulated module outage")

    # take down an optional module on every call (PQC in the hot path,
    # which now lives in the detection service after the extraction)
    monkeypatch.setattr(detection_mod, "assess_handshake", boom)

    engine.start("pcap", path=suspicious)
    deadline = time.time() + 30
    while engine.running and time.time() < deadline:
        time.sleep(0.05)
    assert not engine.running

    # core capture and inference survived the module outage
    assert engine.status["error"] is None
    assert engine.status["flows"] >= 12
    failures = engine.status["failures"]
    assert failures.get("pqc", 0) >= 1


def test_pipeline_failure_series_renders_in_metrics():
    """Failure counts reach the Prometheus surface via the API engine."""
    from spectra.api.app import engine as api_engine

    api_engine._record_failure("probe", RuntimeError("probe"))  # noqa: SLF001
    assert api_engine.status["failures"].get("probe", 0) >= 1
    text = client.get("/api/metrics").text
    assert 'spectra_pipeline_failures{component="probe"}' in text


def test_bio_failure_is_isolated_in_flow_path(tmp_path, monkeypatch):
    from spectra.demo import make_baseline_pcap, make_suspicious_pcap
    from spectra.pipeline import SpectraEngine

    baseline = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=30)
    suspicious = make_suspicious_pcap(str(tmp_path / "s.pcap"))
    engine = SpectraEngine(model_path=str(tmp_path / "m.joblib"), persist=False)
    engine.train_from_pcap(baseline, contamination=0.05)

    def boom(*_args, **_kwargs):
        raise RuntimeError("bio sidecar outage")

    monkeypatch.setattr(engine.bio, "assess", boom)

    engine.start("pcap", path=suspicious)
    deadline = time.time() + 30
    while engine.running and time.time() < deadline:
        time.sleep(0.05)
    assert not engine.running
    assert engine.status["error"] is None
    assert engine.status["flows"] >= 12
    if engine.bio.available:
        assert engine.status["failures"].get("bio", 0) >= 1
