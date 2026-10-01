"""Advanced-module integration contracts: one platform, not eight demos.

The eight advanced modules (PQC, TEE, adversarial resilience, digital twin,
audit/ZKP, bio-inspired detection, correlation, edge/5G) must read as one
integration:

* each declares its contract in :mod:`spectra.capabilities` - what it
  consumes, what it produces, whether it may move alert scoring, that it
  is evidence only, how it degrades, and its maturity;
* ``GET /api/capabilities`` serves the contract plus live, guarded
  availability so the frontend can tell real from simulated;
* no module may change the anomaly score, the alert confidence or the
  severity (SCORING_POLICY);
* an optional-module failure degrades that module only - detection and
  the transparency endpoints keep working.
"""

from __future__ import annotations

import json
import time

from fastapi.testclient import TestClient

from spectra.api.app import app
from spectra.api.runtime import engine
from spectra.capabilities import (
    CAPABILITIES,
    SCORING_POLICY,
    capability_contracts,
    module_capabilities,
)
from spectra.config import Config
from spectra.services.events import EventBus
from spectra.services.threat_alerts import ThreatAlertService
from spectra.store import Store

client = TestClient(app)  # session-scoped admin (conftest)

#: The modules the integration brief names explicitly - all must exist.
NAMED_MODULES = ("pqc", "tee", "adversarial", "twin", "audit", "bio",
                 "correlation", "edge", "edge_deployment", "federated")


# -- helpers -------------------------------------------------------------------


def alert_record(**overrides) -> dict:
    """A flow record shaped like the publication path hands it to observe()."""
    base = {
        "src": "10.42.0.9:51111",
        "dst": "beacon.example.com:8443",
        "proto": "TCP",
        "start_ts": 1_700_000_000.0,
        "last_ts": 1_700_000_010.0,
        "duration": 10.0,
        "packets": 30,
        "bytes": 1_600,
        "sni": None,
        "tls_version": None,
        "quic_version": None,
        "alpn": None,
        "ja3": None,
        "ja4": None,
        "slice": None,
        "score": 97.0,
        "anomaly": True,
    }
    base.update(overrides)
    return base


def c2_threat(confidence: float = 0.7) -> dict:
    return {"threat_type": "C2_BEACONING", "confidence": confidence,
            "supporting": [{"signal": "repeated_destination", "weight": 0.4,
                            "detail": "same src->dst pair seen 5 times",
                            "value": 5, "unit": "count"}],
            "contradicting": []}


def make_service(tmp_path):
    """Isolated ThreatAlertService + store (mirrors test_alerts)."""
    cfg = Config()
    cfg.alert_group_seconds = 600.0
    svc_store = Store(str(tmp_path / "contracts.db"))
    bus = EventBus()
    svc = ThreatAlertService(svc_store, cfg, bus, None,
                             model_info=lambda: {"id": "m.joblib",
                                                 "version": "1"})
    return svc, svc_store


# -- 1. the contract table ----------------------------------------------------

def test_every_named_module_declares_a_complete_contract():
    """Input, output, scoring effect, evidence-only, failure, maturity."""
    contracts = capability_contracts()
    for name in NAMED_MODULES:
        assert name in contracts, f"{name} missing from the contract table"

    for name, contract in contracts.items():
        assert contract["title"], name
        assert contract["status"] in CAPABILITIES, name
        assert contract["hardware_backed"] is False, name
        assert contract["consumes"], name
        assert contract["produces"], name
        assert contract["failure"], name
        assert contract["note"], name
        # the scoring invariant: evidence/context only, never a score move
        assert contract["affects_alert_scoring"] is False, name
        assert contract["evidence_only"] is True, name


def test_capability_honesty_guards():
    """No hardware, no MEC, no compliance claims; policy is stated."""
    body = module_capabilities()
    mods = body["modules"]
    assert all(m["status"] != "HARDWARE_BACKED" for m in mods.values())
    assert body["hardware_backed_count"] == 0

    # explicit honesty statements where misreading is most likely
    assert "not regulatory compliance" in mods["audit"]["note"].lower()
    assert "never hardware-backed" in mods["tee"]["note"].lower()
    assert "no real mec or 5g control plane" in \
        mods["edge_deployment"]["note"].lower()

    # the policy ties the table together and is served to consumers
    assert "no advanced module changes" in SCORING_POLICY.lower()
    assert body["scoring_policy"] == SCORING_POLICY

    # serialises cleanly for API consumers
    assert json.dumps(body)


def test_static_contract_has_no_availability_claims():
    """Without a live probe, availability is unknown - not 'up'."""
    body = module_capabilities()
    assert all(m["available"] is None for m in body["modules"].values())
    assert all(m["failures"] is None for m in body["modules"].values())

    merged = module_capabilities({"pqc": {"available": True,
                                          "detail": "3 endpoints assessed",
                                          "failures": 0}})
    assert merged["modules"]["pqc"]["available"] is True
    assert merged["modules"]["pqc"]["failures"] == 0
    assert merged["modules"]["bio"]["available"] is None  # not probed


# -- 2. scoring invariance ----------------------------------------------------

def test_module_annotations_never_move_alert_scoring(tmp_path):
    """Identical flows differing only in module evidence score alike."""
    svc, store = make_service(tmp_path)
    try:
        plain = svc.observe(alert_record(), c2_threat(confidence=0.7),
                            score=97.0)
        # same flow, different source host (grouping is host-based), now
        # carrying bio/PQC/edge evidence on the record
        rich = svc.observe(
            alert_record(src="10.42.0.19:51111",
                         slice="urllc",
                         pqc={"risk": "elevated", "version": "TLS1.3"},
                         immune={"level": "high", "source": "bacterial"},
                         snn_score=0.93, swarm_flag=True),
            c2_threat(confidence=0.7), score=97.0)

        # the evidence is present on the rich alert...
        assert plain["module_annotations"] == {}
        assert set(rich["module_annotations"]) == {
            "pqc", "immune", "snn_score", "swarm_flag"}
        assert rich["metadata"]["slice"] == "urllc"

        # ...and it moved nothing: four independent concepts unchanged
        assert rich["anomaly_score"] == plain["anomaly_score"]
        assert rich["confidence"] == plain["confidence"]
        assert rich["severity"] == plain["severity"]
        assert rich["threat_type"] == plain["threat_type"]
        assert rich["severity_factors"] == plain["severity_factors"]
    finally:
        store.close()


# -- 3. transparent status endpoint -------------------------------------------

def test_capabilities_endpoint_serves_contract_and_live_status():
    res = client.get("/api/capabilities")
    assert res.status_code == 200
    body = res.json()

    assert body["scoring_policy"] == SCORING_POLICY
    assert set(body["statuses"]) == set(CAPABILITIES)
    assert body["hardware_backed_count"] == 0

    for name, mod in body["modules"].items():
        assert mod["status"] in CAPABILITIES, name
        assert mod["hardware_backed"] is False, name
        assert mod["consumes"] and mod["produces"] and mod["failure"], name
        assert mod["affects_alert_scoring"] is False, name
        assert mod["evidence_only"] is True, name
        # live probes ran: availability is a real bool, failures an int
        assert isinstance(mod["available"], bool), name
        assert isinstance(mod["failures"], int), name

    # failure counts mirror the engine's FailureTracker per component
    assert body["modules"]["pqc"]["failures"] == \
        engine.status["failures"].get("pqc", 0)
    assert body["modules"]["correlation"]["failures"] == \
        engine.status["failures"].get("correlation", 0)


def test_capabilities_endpoint_survives_probe_outage(monkeypatch):
    """Transparency must never become a 500: static contract still serves."""
    def boom():
        raise RuntimeError("probe outage")

    monkeypatch.setattr(engine, "capability_status", boom)
    res = client.get("/api/capabilities")
    assert res.status_code == 200
    body = res.json()
    assert set(body["modules"]) == set(capability_contracts())
    # probes failed to run -> unknown, honestly reported
    assert all(m["available"] is None for m in body["modules"].values())
    assert body["modules"]["tee"]["status"] == "SIMULATED"


# -- 4. optional-module failure never breaks detection ------------------------

def test_correlation_outage_does_not_break_detection(tmp_path, monkeypatch):
    """Graph failure: capture + inference survive, failure is counted."""
    from spectra.demo import make_baseline_pcap, make_suspicious_pcap
    from spectra.modules.corr import CorrelationGraph
    from spectra.pipeline import SpectraEngine

    baseline = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=30)
    suspicious = make_suspicious_pcap(str(tmp_path / "s.pcap"))
    eng = SpectraEngine(model_path=str(tmp_path / "m.joblib"), persist=False)
    eng.train_from_pcap(baseline, contamination=0.05)

    def boom(*_args, **_kwargs):
        raise RuntimeError("graph outage")

    monkeypatch.setattr(CorrelationGraph, "observe", boom)

    eng.start("pcap", path=suspicious)
    deadline = time.time() + 30
    while eng.running and time.time() < deadline:
        time.sleep(0.05)
    assert not eng.running

    assert eng.status["error"] is None
    assert eng.status["flows"] >= 12
    assert eng.status["failures"].get("correlation", 0) >= 1

    # and the live status still renders, marking correlation failures
    from spectra.capabilities import module_capabilities
    live = eng.capability_status()
    assert live["correlation"]["failures"] >= 1
    merged = module_capabilities(live)
    assert merged["modules"]["correlation"]["failures"] >= 1
