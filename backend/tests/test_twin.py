"""Module 4: digital twin - topology, propagation, playbooks, shadow mode."""

from __future__ import annotations

import json

import numpy as np
import pytest

from spectra.modules.corr import CorrelationGraph
from spectra.modules.twin import (
    LIBRARY,
    SimulationError,
    ZScoreDetector,
    build_topology,
    evaluate_library,
    playbook_from_detections,
    resolve_initial,
    run_shadow,
    simulate,
    validate_playbook,
)


def rec(src="10.0.0.5:40000", dst="93.184.216.34:443", sni="example.com",
        b=1000, ts=1_700_000_000.0, anomaly=False):
    return {"src": src, "dst": dst, "sni": sni, "bytes": b, "last_ts": ts,
            "anomaly": anomaly, "proto": "TLSv1.3", "packets": 5,
            "duration": 1.0, "tls_version": "TLSv1.3",
            "score": 90.0 if anomaly else 5.0}


def make_graph() -> CorrelationGraph:
    g = CorrelationGraph()
    g.observe(rec(sni="pay.bank.example", dst="10.1.0.10:443", b=500))
    g.observe(rec(sni="billing.bank.example", dst="10.1.0.10:443", b=700))
    g.observe(rec(sni="portal.hospital.example", dst="10.2.0.20:443", b=900))
    g.observe(rec(sni="cdn.shared.example", dst="10.1.0.10:443", b=400))
    g.observe(rec(src="10.0.0.7:41000", sni="portal.hospital.example",
                  dst="10.2.0.20:443", b=300, anomaly=True))
    g.observe(rec(src="10.0.0.9:42000", sni="traffic.city.example",
                  dst="10.3.0.30:443", b=200))
    g.observe(rec(src="10.0.0.7:41001", sni="traffic.city.example",
                  dst="10.3.0.30:443", b=250))
    return g


@pytest.fixture()
def topo() -> dict:
    return build_topology(make_graph())


# -- topology ----------------------------------------------------------------


def test_topology_structure(topo):
    s = topo["summary"]
    assert s["assets"] == 6            # 3 hosts + 3 servers
    assert s["edges"] >= 5             # talks_to channels
    assert s["zones"] >= 3
    assert set(topo["assets"]) == {n["id"] for n in topo["nodes"] if n["asset"]}
    for n in topo["nodes"]:
        assert 0.0 <= n["criticality"] <= 1.0
        assert n["zone"]
    for e in topo["asset_edges"]:
        assert 0.0 < e["normalized"] <= 1.0
        assert e["source"] in topo["assets"] and e["target"] in topo["assets"]
    # domain -> IP hook exists for block-domain playbooks
    assert any(topo["by_domain"].values()), "no domain->IP mapping"
    # hosts talking to bank traffic land in a sensible zone
    zones = {n["id"]: n["zone"] for n in topo["nodes"]}
    assert zones["host:10.0.0.5"] == "fintech"


def test_topology_is_deterministic(topo):
    again = build_topology(make_graph())
    assert again == topo


def test_topology_criticality_reflects_sector(topo):
    crit = {n["id"]: n["criticality"] for n in topo["nodes"]}
    assert crit["domain:portal.hospital.example"] >= crit["domain:cdn.shared.example"]


def test_topology_empty_graph():
    topo = build_topology(CorrelationGraph())
    assert topo["summary"]["assets"] == 0
    assert topo["zones"] == []
    with pytest.raises(SimulationError):
        simulate(topo)


# -- simulation --------------------------------------------------------------


def test_simulation_is_deterministic_and_seedable(topo):
    a = simulate(topo, seed=7, capability=0.9, rounds=10)
    b = simulate(topo, seed=7, capability=0.9, rounds=10)
    assert a == b
    c = simulate(topo, seed=8, capability=0.9, rounds=10)
    assert c["initial"] == a["initial"]
    assert isinstance(c["timeline"], list) and len(c["timeline"]) == 10


def test_no_capability_no_spread(topo):
    result = simulate(topo, seed=5, capability=0.0, rounds=12)
    assert result["total_infected"] <= len(result["initial"])
    assert result["contained"] is True
    assert result["blast_ratio"] <= len(result["initial"]) / result["assets"]


def test_full_capability_reaches_the_component(topo):
    low = simulate(topo, seed=5, capability=0.3, rounds=4, monitoring=0.0)
    high = simulate(topo, seed=5, capability=1.0, rounds=25, monitoring=0.0)
    assert high["total_infected"] >= low["total_infected"]
    assert high["total_infected"] >= 4
    assert high["last_infection_round"] is not None


def test_monitoring_contains_spread(topo):
    free = simulate(topo, seed=5, capability=0.8, rounds=30, monitoring=0.0)
    watched = simulate(topo, seed=5, capability=0.8, rounds=30, monitoring=1.0)
    assert watched["final_infected"] < free["final_infected"]
    assert any(step["detected"] for step in watched["timeline"])


def test_controls_reduce_blast_radius(topo):
    plain = simulate(topo, seed=5, capability=1.0, rounds=25, monitoring=0.0)
    patched = simulate(topo, seed=5, capability=1.0, rounds=25, monitoring=0.0,
                       controls={"patch_hosts": 3})
    segmented = simulate(topo, seed=5, capability=1.0, rounds=25, monitoring=0.0,
                         controls={"segment_zones": True})
    assert plain["total_infected"] >= 5      # uncontrolled, it reaches everything
    assert patched["total_infected"] < plain["total_infected"]
    assert segmented["total_infected"] <= plain["total_infected"]
    assert len(patched["params"]["immune"]) == 3
    # immune assets are never infected
    assert not (set(patched["params"]["immune"]) & set(patched["ever_infected"]))


def test_validation_of_inputs(topo):
    with pytest.raises(SimulationError):
        simulate(topo, rounds=0)
    with pytest.raises(SimulationError):
        simulate(topo, capability=1.5)
    with pytest.raises(SimulationError):
        simulate(topo, controls={"unknown_control": True})
    with pytest.raises(SimulationError):
        simulate(topo, monitoring=2.0)
    with pytest.raises(SimulationError):
        simulate(topo, actions=[{"round": 1, "action": "no_such_action"}])
    with pytest.raises(SimulationError):
        simulate(topo, actions=[{"round": 99, "action": "monitor"}])
    with pytest.raises(SimulationError):
        simulate(topo, initial=["host:not-in-twin"])


def test_seed_selection_prefers_detection_sources(topo):
    seeds = resolve_initial(topo, None)
    assert seeds[0] == "host:10.0.0.7"      # the only node with detections
    explicit = resolve_initial(topo, ["host:10.0.0.5"])
    assert explicit == ["host:10.0.0.5"]
    # ties broken deterministically
    assert resolve_initial(topo, None) == seeds


def test_simulated_actions_apply_and_log(topo):
    target = "host:10.0.0.5"
    base = simulate(topo, seed=4, capability=1.0, rounds=8, monitoring=0.0)
    isolated = simulate(topo, seed=4, capability=1.0, rounds=8, monitoring=0.0,
                        actions=[{"round": 0, "action": "isolate_host",
                                  "target": target}])
    assert isolated["action_log"][0]["applied"] == 1
    assert isolated["total_infected"] <= base["total_infected"]
    # blocked attempts counted
    assert isolated["blocked_attempts"] > 0


def test_block_domain_action_resolves_through_topo(topo):
    dom_ip = topo["by_domain"]["domain:portal.hospital.example"]
    result = simulate(topo, seed=4, capability=1.0, rounds=8, monitoring=0.0,
                      actions=[{"round": 1, "action": "block_domain",
                                "target": "portal.hospital.example"}])
    assert any(entry["action"] == "block_domain" and entry["applied"] == len(dom_ip)
               for entry in result["action_log"])


# -- playbooks ---------------------------------------------------------------


def test_validate_library_playbook_passes_on_spread(topo):
    result = validate_playbook(topo, LIBRARY["full_containment"], seed=7,
                               capability=1.0, rounds=12, monitoring=0.0)
    assert result["baseline"]["total_infected"] > result["baseline"]["initial"]
    assert result["after"]["total_infected"] <= result["baseline"]["total_infected"]
    assert result["verdict"]["state"] in ("pass", "fail")
    assert 0.0 <= result["efficiency"] <= 1.0
    assert result["actions_resolved"]      # auto targets were expanded
    assert len(result["actions_resolved"]) > len(
        LIBRARY["full_containment"]["actions"]) - 1
    if result["verdict"]["state"] == "pass":
        assert result["verdict"]["pass"] is True


def test_validate_noop_when_nothing_spreads(topo):
    result = validate_playbook(topo, LIBRARY["sector_lockdown"], seed=1,
                               capability=0.0, rounds=8)
    assert result["verdict"]["state"] == "noop"
    assert result["verdict"]["pass"] is True
    assert result["reduction"] == 0.0


def test_validate_fails_when_playbook_does_nothing(topo):
    useless = {"name": "no_op", "actions": [], "thresholds": {"min_reduction": 0.9}}
    result = validate_playbook(topo, useless, seed=7, capability=1.0, rounds=10)
    # no actions -> efficiency 0 -> fail (unless baseline itself contained)
    if result["verdict"]["state"] != "noop":
        assert result["verdict"]["state"] == "fail"
        assert result["verdict"]["pass"] is False
        assert result["verdict"]["reasons"]


def test_evaluate_library_ranks_playbooks(topo):
    report = evaluate_library(topo, seed=7, capability=1.0, rounds=12)
    assert report["count"] == len(LIBRARY)
    assert report["best"]
    ranks = [p["rank"] for p in report["playbooks"]]
    assert ranks == list(range(1, len(ranks) + 1))
    # best playbook is a passing one when any pass
    states = {p["playbook"]: p["verdict"]["state"] for p in report["playbooks"]}
    if "pass" in states.values():
        assert states[report["best"]] == "pass"


def test_playbook_from_detections_builds_actions():
    playbook = playbook_from_detections(
        [{"src": "10.0.0.7:41000", "dst": "10.2.0.20:443",
          "sni": "portal.hospital.example", "score": 98.0},
         {"src": "10.0.0.5:40000", "dst": "10.1.0.10:443",
          "sni": "pay.bank.example", "score": 91.0}],
        top=1)
    assert playbook["auto"] is True
    kinds = [a["action"] for a in playbook["actions"]]
    assert "isolate_host" in kinds and "block_ip" in kinds and "block_domain" in kinds
    # only the top detection is used
    assert playbook["actions"][0]["target"] == "host:10.0.0.7"

    empty = playbook_from_detections([])
    assert empty["actions"]          # falls back to monitoring


def test_auto_playbook_rehearses(topo):
    playbook = playbook_from_detections(
        [{"src": "10.0.0.7:41000", "dst": "10.2.0.20:443",
          "sni": "portal.hospital.example", "score": 98.0}])
    result = validate_playbook(topo, playbook, seed=7, capability=1.0, rounds=10)
    assert result["playbook"] == "auto_containment"
    assert result["verdict"]["state"] in ("pass", "fail", "noop")


def test_validate_rejects_bad_playbooks(topo):
    with pytest.raises(SimulationError):
        validate_playbook(topo, {"no_actions": True})
    with pytest.raises(SimulationError):
        validate_playbook(topo, {"actions": [{"round": 1, "action": "drop_nuke"}]},
                          seed=7)


# -- shadow mode -------------------------------------------------------------


def _model(seed=42, contamination=0.05):
    from spectra.ml.model import SpectraDetector

    rng = np.random.default_rng(seed)
    X = rng.normal(0, 1, size=(400, 39))
    model = SpectraDetector(contamination=contamination, random_state=7)
    model.fit(X)
    return model, rng


def test_shadow_requires_trained_model():
    from spectra.ml.model import SpectraDetector

    res = run_shadow(SpectraDetector(), np.zeros((10, 39)))
    assert res["available"] is False
    assert "reason" in res


def test_shadow_empty_window():
    model, _ = _model()
    assert run_shadow(model, np.empty((0, 39)))["available"] is False


def test_shadow_flags_injected_anomalies_and_reports_lift():
    model, rng = _model()
    normal = rng.normal(0, 1, size=(60, 39))
    weird = rng.normal(7, 1, size=(8, 39))
    X = np.vstack([normal, weird])
    labels = np.array([0] * 60 + [1] * 8)

    res = run_shadow(model, X, feature_names=[f"f{i}" for i in range(39)],
                     threshold=3.0, labels=labels)
    assert res["available"] is True
    assert res["window"] == 68
    assert res["truth"] == "labels"

    comp = res["comparison"]
    assert comp["reference_flags"] >= 1
    assert comp["baseline_flags"] >= 1
    assert 0.0 <= comp["baseline_agreement"] <= 1.0
    m = comp["baseline_vs_reference"]
    assert m["tp"] + m["fp"] + m["fn"] + m["tn"] == 68
    assert 0.0 <= m["f1"] <= 1.0
    assert res["baseline_vs_truth"]["tp"] >= 1     # catches the injected spikes

    # candidate configuration: explicit alternative model
    alt, _ = _model(seed=99, contamination=0.1)
    res2 = run_shadow(model, X, candidate=alt,
                      feature_names=[f"f{i}" for i in range(39)])
    assert "candidate_vs_reference" in res2["comparison"]
    assert "f1_lift_vs_baseline" in res2["improvement"]
    assert "candidate" in res2["verdict"]
    assert res2["latency_ms"]["reference"] >= 0

    # scores are in the 0..100 scale used everywhere else
    assert 0.0 <= res["scores"]["mean"] <= 100.0


def test_shadow_candidate_without_model_falls_back():
    model, rng = _model()
    X = rng.normal(0, 1, size=(40, 39))

    class Untrained:
        is_trained = False

    res = run_shadow(model, X, candidate=Untrained())
    assert res["available"] is True
    # fallback candidate is the z-score rule at a tighter threshold
    assert res["comparison"]["candidate_flags"] >= 0


def test_zscore_detector_semantics():
    rng = np.random.default_rng(3)
    X = rng.normal(0, 1, size=(200, 6))
    det = ZScoreDetector(threshold=3.0).fit(X)
    flags = det.predict(X)
    scores = det.score(X)
    assert flags.shape == (200,)
    assert scores.min() >= 0 and scores.max() <= 100
    outlier = np.full((1, 6), 25.0)
    assert det.predict(outlier)[0] == 1
    with pytest.raises(RuntimeError):
        ZScoreDetector().predict(X)


# -- engine + API integration ------------------------------------------------


def test_engine_twin_methods(tmp_path):
    from spectra.demo import make_baseline_pcap, make_suspicious_pcap
    from spectra.pipeline import SpectraEngine

    baseline = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=30)
    suspicious = make_suspicious_pcap(str(tmp_path / "s.pcap"))
    engine = SpectraEngine(model_path=str(tmp_path / "m.joblib"), persist=False)
    engine.train_from_pcap(baseline, contamination=0.05)

    engine.start("pcap", path=suspicious)
    import time as _t

    deadline = _t.time() + 30
    while engine.running and _t.time() < deadline:
        _t.sleep(0.05)
    assert not engine.running
    assert engine.status["flows"] > 0

    topo = engine.twin_topology()
    assert topo["summary"]["assets"] >= 2

    sim = engine.twin_simulate(seed=3, capability=1.0, rounds=8)
    assert sim["topology"]["assets"] == topo["summary"]["assets"]
    assert sim["total_infected"] >= 1

    lib = engine.twin_playbooks()
    assert lib["count"] == len(LIBRARY)
    assert all(item["actions"] for item in lib["items"])

    val = engine.twin_validate(name="beacon_containment", seed=3,
                               capability=1.0, rounds=8)
    assert val["verdict"]["state"] in ("pass", "fail", "noop")

    ranking = engine.twin_evaluate(seed=3, capability=1.0, rounds=8)
    assert ranking["best"]

    rec = engine.twin_recommend()
    assert rec["playbook"]["auto"] is True
    assert "rehearsal" in rec

    shadow = engine.shadow()
    assert shadow["available"] is True, shadow
    assert shadow["window"] > 0

    with pytest.raises(ValueError):
        engine.twin_validate(name="does_not_exist")


def test_twin_api_endpoints(tmp_path):
    import time as _t

    from fastapi.testclient import TestClient

    from spectra.api.app import app, engine
    from spectra.demo import make_baseline_pcap, make_suspicious_pcap

    client = TestClient(app)

    baseline = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=30)
    suspicious = make_suspicious_pcap(str(tmp_path / "s.pcap"))
    if not engine.detector.is_trained:
        res = client.post("/api/model/train",
                          json={"pcap_path": baseline, "contamination": 0.05})
        assert res.status_code == 200, res.text

    res = client.post("/api/capture/start", json={"mode": "pcap", "path": suspicious})
    assert res.status_code == 200, res.text
    deadline = _t.time() + 30
    while engine.running and _t.time() < deadline:
        _t.sleep(0.05)
    client.post("/api/capture/stop")

    res = client.get("/api/twin/topology")
    assert res.status_code == 200, res.text
    topo = res.json()
    assert topo["summary"]["assets"] >= 2
    assert topo["zones"]

    res = client.get("/api/twin/playbooks")
    assert res.status_code == 200
    assert res.json()["count"] == len(LIBRARY)

    res = client.post("/api/twin/simulate",
                      json={"seed": 5, "rounds": 8, "capability": 1.0})
    assert res.status_code == 200, res.text
    assert res.json()["total_infected"] >= 1

    res = client.post("/api/twin/simulate",
                      json={"capability": 2.0})
    assert res.status_code == 422          # pydantic range validation

    res = client.post("/api/twin/simulate",
                      json={"controls": {"bogus": 1}})
    assert res.status_code == 400

    res = client.post("/api/twin/playbook",
                      json={"name": "beacon_containment", "seed": 5,
                            "capability": 1.0, "rounds": 8})
    assert res.status_code == 200, res.text
    report = res.json()
    assert report["verdict"]["state"] in ("pass", "fail", "noop")
    assert "efficiency" in report

    res = client.post("/api/twin/playbook", json={"name": "nope"})
    assert res.status_code == 400

    res = client.post("/api/twin/evaluate",
                      json={"seed": 5, "capability": 1.0, "rounds": 8})
    assert res.status_code == 200
    assert res.json()["best"]

    res = client.post("/api/twin/recommend",
                      json={"seed": 5, "capability": 1.0, "rounds": 8})
    assert res.status_code == 200, res.text
    assert res.json()["playbook"]["auto"] is True

    res = client.post("/api/twin/shadow", json={})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body.get("available") is True and body["window"] > 0
    assert "comparison" in body

    res = client.post("/api/twin/shadow", json={"pcap": "/nope.pcap"})
    assert res.status_code == 404
