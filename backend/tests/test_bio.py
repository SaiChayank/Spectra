"""Module 6: biological-inspired detection - danger theory, SNN, swarm."""

from __future__ import annotations

import json

import numpy as np
import pytest

from spectra.features.extractor import FEATURE_NAMES, N_FEATURES
from spectra.modules.bio import (
    RESPONSES,
    BioSystem,
    MemoryCells,
    SelfModel,
    Swarm,
    TimingSNN,
    assess_immunity,
    band_level,
    danger_signals,
    danger_total,
)

IDX_IAT_MEAN = FEATURE_NAMES.index("iat_mean_s")
IDX_IAT_STD = FEATURE_NAMES.index("iat_std_s")
IDX_RATE = FEATURE_NAMES.index("packets_per_s")
TIMING_IDX = [
    FEATURE_NAMES.index(n) for n in (
        "duration_s", "iat_mean_s", "iat_std_s", "iat_min_s", "iat_max_s",
        "iat_fwd_mean_s", "iat_fwd_std_s", "iat_fwd_mad_s", "packets_per_s",
    )]


def benign_matrix(n: int = 150, seed: int = 42) -> np.ndarray:
    """Benign baseline: tight, coherent timing; other features near normal."""
    rng = np.random.default_rng(seed)
    X = rng.normal(0.0, 1.0, size=(n, N_FEATURES))
    # coherent timing cluster so the SNN has a stable self to compare against
    for i in TIMING_IDX:
        X[:, i] = rng.normal(1.0, 0.05, size=n)
    return X


def burst_row(base: np.ndarray) -> np.ndarray:
    """Deviant flow: every timing feature far from the benign cluster."""
    x = base.copy()
    for i in TIMING_IDX:
        x[i] = 5.0
    return x


@pytest.fixture()
def model() -> SelfModel:
    return SelfModel().fit(benign_matrix())


@pytest.fixture()
def bio() -> BioSystem:
    system = BioSystem(contamination=0.02)
    system.fit(benign_matrix())
    return system


# -- danger theory -----------------------------------------------------------


def test_self_model_affinity(model):
    X = benign_matrix()
    assert model.affinity(X[0]) < 0.4
    assert model.affinity(X[3]) < 0.4
    extreme = X[0] * 40
    assert model.affinity(extreme) > 0.6
    z = model.robust_z(X[0])
    assert z.shape == (N_FEATURES,)
    assert float(np.max(z)) <= 6.0


def test_self_model_requires_matrix(model):
    with pytest.raises(ValueError):
        SelfModel().fit(np.empty((0, N_FEATURES)))
    with pytest.raises(ValueError):
        SelfModel().fit(np.zeros((5, N_FEATURES - 1)))
    with pytest.raises(RuntimeError):
        SelfModel().affinity(np.zeros(N_FEATURES))


def test_band_level_edges():
    assert band_level(0.10, (0.35, 0.55, 0.75)) == 0
    assert band_level(0.35, (0.35, 0.55, 0.75)) == 1
    assert band_level(0.74, (0.35, 0.55, 0.75)) == 2
    assert band_level(0.90, (0.35, 0.55, 0.75)) == 3


def test_escalation_ladder(model):
    """Context signals walk the response from ignore to isolate."""
    x = benign_matrix(1)[0]
    mem = MemoryCells()

    clean = assess_immunity(x, model, mem)
    assert clean["level"] == 0 and clean["response"] == "ignore"
    assert not clean["memory_hit"]

    warm = assess_immunity(x, model, mem, score=75.0)
    assert warm["level"] == 1 and warm["response"] == "monitor"

    flagged = assess_immunity(x, model, mem, score=95.0, anomaly=True)
    assert flagged["level"] == 2 and flagged["response"] == "alert"

    attacked = assess_immunity(x, model, mem, score=95.0, anomaly=True,
                               drift_level="significant")
    assert attacked["level"] == 3 and attacked["response"] == "isolate"

    watched = assess_immunity(x, model, mem, evasion=True)
    assert watched["level"] == 1


def test_affinity_axis_alone_can_isolate(model):
    """A wildly non-self flow isolates even with zero context signals."""
    row = benign_matrix(1)[0]
    x = row * 60
    # keep packet rate at the self value so the rate-spike signal stays quiet -
    # this test isolates the affinity axis alone
    x[IDX_RATE] = row[IDX_RATE]
    out = assess_immunity(x, model, MemoryCells())
    assert out["level"] == 3
    assert out["affinity"] >= 0.75
    assert out["danger_total"] == 0.0


def test_danger_signals_shape_and_cap(model):
    x = benign_matrix(1)[0]
    sigs = danger_signals(x, score=99.0, anomaly=True, drift_level="significant",
                          evasion=True, self_model=model)
    names = [s["name"] for s in sigs]
    assert "detector_flag" in names and "drift" in names
    assert "evasion_watch" in names and "beacon_cadence" in names
    fired = [s for s in sigs if s["fired"]]
    assert fired
    assert danger_total(sigs) <= 1.0      # capped
    # no context, benign flow -> nothing fires
    quiet = danger_signals(x, self_model=model)
    assert danger_total(quiet) == 0.0


def test_beacon_cadence_signal():
    """Metronomic inter-arrival times fire the beacon signal; jittered do not."""
    x = np.zeros(N_FEATURES)
    x[IDX_IAT_MEAN] = 1.0
    x[IDX_IAT_STD] = 0.01               # std/mean = 0.01 -> metronomic
    fired = {s["name"]: s["fired"] for s in danger_signals(x)}
    assert fired["beacon_cadence"] is True

    x[IDX_IAT_STD] = 0.6                # std/mean = 0.6 -> organic
    fired = {s["name"]: s["fired"] for s in danger_signals(x)}
    assert fired["beacon_cadence"] is False


def test_memory_cells_escalate_and_dedupe(model):
    x = benign_matrix(1)[0]
    mem = MemoryCells()
    first = assess_immunity(x, model, mem, score=95.0, anomaly=True)
    assert first["level"] == 2

    assert mem.add(x, model) is True
    assert len(mem) == 1
    assert mem.add(x, model) is False     # duplicate cell rejected

    again = assess_immunity(x, model, mem, score=95.0, anomaly=True)
    assert again["memory_hit"] is True
    assert again["level"] == 3            # immunological memory escalates

    # cap: never grows unbounded
    rng = np.random.default_rng(7)
    added = 0
    for _ in range(100):
        if mem.add(x + rng.normal(0, 3, N_FEATURES), model):
            added += 1
    assert len(mem) <= MemoryCells.MAX


# -- spiking neural network --------------------------------------------------


def test_snn_requires_training():
    snn = TimingSNN()
    assert not snn.trained
    with pytest.raises(RuntimeError):
        snn.score(np.zeros((1, N_FEATURES)))


def test_snn_flags_extreme_timing():
    X = benign_matrix()
    snn = TimingSNN().fit(X)
    # percentile scores are uniform by construction, so compare the *raw*
    # activity that drives them: deviant bursts fire early and in sync
    benign_peak, _ = snn.activity(X)
    evil = np.repeat(burst_row(X[0])[None, :], 5, axis=0)
    evil_peak, _ = snn.activity(evil)
    assert float(np.mean(evil_peak)) > float(np.mean(benign_peak))
    scores = snn.score(evil)
    assert np.all(scores >= snn.threshold_pct)
    assert snn.predict(evil).all()


def test_snn_is_deterministic():
    X = benign_matrix()
    row = burst_row(X[0])[None, :]
    a = TimingSNN().fit(X).score(row)[0]
    b = TimingSNN().fit(X).score(row)[0]
    assert a == b


def test_snn_timing_scale_absorbs_satellite_rtt():
    """A slow link's legitimately large IATs stop reading as anomalous."""
    X = benign_matrix()
    snn = TimingSNN().fit(X)
    slow = benign_matrix(1, seed=9)[0]
    for i in TIMING_IDX:
        slow[i] = 5.0                     # ~5x benign timing (GEO-class RTT)

    # unscaled, the uniform lateness reads as an early synchronized burst;
    # divided by the link scale it lands back inside the benign latency band
    _, _, terrestrial_metric = snn.activity_metric(slow[None, :], timing_scale=1.0)
    _, _, satellite_metric = snn.activity_metric(slow[None, :], timing_scale=5.0)
    assert satellite_metric[0] < terrestrial_metric[0]
    # ...and the flow scores lower on the NTN profile than on terrestrial
    terrestrial = snn.score(slow[None, :], timing_scale=1.0)[0]
    satellite = snn.score(slow[None, :], timing_scale=5.0)[0]
    assert satellite < terrestrial


def test_snn_rejects_wrong_shape():
    snn = TimingSNN().fit(benign_matrix())
    with pytest.raises(ValueError):
        snn.activity(np.zeros((2, N_FEATURES - 1)))


# -- swarm intelligence ------------------------------------------------------


def test_swarm_quorum_and_abstention(bio):
    X = benign_matrix()
    x = X[0]
    swarm = Swarm()

    # only the cadence agent can vote -> no quorum
    alone = swarm.vote(x, reinforce=False)
    assert alone["available"] is False
    assert alone["flag"] is False
    assert "cadence" in alone["abstained"] or alone["abstained"]

    # add the entropy agent (self model present) -> quorum reached
    low = swarm.vote(x, score=5.0, immune_level=0, snn_score=10.0,
                     self_model=bio.self_model, reinforce=False)
    assert low["available"] is True
    assert low["flag"] is False
    assert low["ratio"] < low["quorum"]
    assert low["n_agents"] == 5

    high = swarm.vote(burst_row(x), score=99.0, immune_level=3, snn_score=99.0,
                      self_model=bio.self_model, reinforce=False)
    assert high["flag"] is True
    assert high["ratio"] >= high["quorum"]


def test_swarm_pheromone_reinforcement(bio):
    """Agents matching consensus gain trail strength; dissenters decay."""
    X = benign_matrix()
    x = X[0]
    swarm = Swarm()
    start = dict(swarm.weights)

    # consensus will be "benign" (3 quiet voters vs forest+snn loud? craft it)
    for _ in range(30):
        swarm.vote(x, score=5.0, immune_level=0, snn_score=5.0,
                   self_model=bio.self_model, reinforce=True)

    after = dict(swarm.weights)           # copy: later voting mutates in place
    # everyone agreed it was benign -> all weights stable or boosted
    assert after["forest"] >= start["forest"] - 1e-9
    assert after["cadence"] >= start["cadence"] - 1e-9

    # now force disagreement: forest+snn+immune scream, entropy+cadence quiet
    for _ in range(30):
        swarm.vote(x, score=99.0, immune_level=3, snn_score=99.0,
                   self_model=bio.self_model, reinforce=True)
    dissent = swarm.weights
    # the minority (entropy+cadence voting 0 while flag=True) decays
    assert dissent["entropy"] < after["entropy"]
    assert dissent["cadence"] <= after["cadence"]
    assert all(0.3 <= w <= 3.0 for w in dissent.values())


def test_swarm_no_single_point_of_failure():
    """Losing an agent input never breaks the verdict."""
    X = benign_matrix()
    x = X[0]
    model = SelfModel().fit(X)
    swarm = Swarm()

    # forest quiet (no score) - still a verdict
    without_forest = swarm.vote(x, immune_level=0, snn_score=10.0,
                                self_model=model, reinforce=False)
    assert without_forest["available"]
    assert "forest" in without_forest["abstained"]

    # immune AND forest quiet - still >= 3 agents
    sparse = swarm.vote(x, snn_score=10.0, self_model=model, reinforce=False)
    assert sparse["available"]
    assert sparse["n_agents"] == 3

    # only cadence left -> explicitly unavailable, no crash
    none = swarm.vote(x, reinforce=False)
    assert none["available"] is False
    assert "need >= 2" in none["reason"]


# -- BioSystem orchestration -------------------------------------------------


def test_biosystem_unavailable_until_trained():
    fresh = BioSystem()
    assert not fresh.available
    out = fresh.assess(np.zeros(N_FEATURES), score=50.0)
    assert out["available"] is False
    assert "retrain" in out["reason"]
    with pytest.raises(ValueError):
        fresh.fit(np.zeros((5, N_FEATURES)))


def test_biosystem_assess_shape_and_json(bio):
    X = benign_matrix()
    out = bio.assess(X[0], score=10.0, anomaly=False)
    assert out["available"] is True
    assert out["level"] in (0, 1, 2, 3)
    assert out["response"] == RESPONSES[out["level"]]
    assert out["snn"]["available"] is True
    assert out["swarm"]["available"] is True
    assert 0.0 <= out["immune"]["affinity"] <= 1.0
    json.dumps(out)                       # numpy-free payload

    with pytest.raises(ValueError):
        bio.assess(np.zeros(N_FEATURES - 1))
    report = bio.status()
    json.dumps(report)
    assert report["available"] is True


def test_biosystem_remember_gate(bio):
    X = benign_matrix()
    assert bio.remember(X[0], level=1) is False   # only alert/isolate stored
    assert bio.remember(X[0], level=2) is True
    assert len(bio.memory) == 1
    hist = bio.status()["response_histogram"]
    assert set(hist) == set(RESPONSES)


def test_biosystem_persistence(tmp_path):
    path = str(tmp_path / "bio.joblib")
    bio = BioSystem(contamination=0.05)
    X = benign_matrix()
    bio.fit(X)
    evil = burst_row(X[0])
    before = bio.assess(evil, score=95.0, anomaly=True)
    bio.remember(evil, before["level"])
    bio.save(path)

    reloaded = BioSystem()
    assert reloaded.load(path) is True
    assert reloaded.available
    assert reloaded.contamination == 0.05
    assert len(reloaded.memory) == 1
    after = reloaded.assess(evil, score=95.0, anomaly=True)
    assert after["level"] == before["level"]
    assert after["snn"]["score"] == before["snn"]["score"]

    assert BioSystem().load(str(tmp_path / "missing.joblib")) is False


def test_biosystem_fit_needs_enough_flows():
    with pytest.raises(ValueError):
        BioSystem().fit(benign_matrix(3))


# -- engine integration ------------------------------------------------------


def test_engine_bio_and_slice_wiring(tmp_path):
    from spectra.demo import make_baseline_pcap, make_suspicious_pcap
    from spectra.pipeline import SpectraEngine

    baseline = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=30)
    suspicious = make_suspicious_pcap(str(tmp_path / "s.pcap"))
    engine = SpectraEngine(model_path=str(tmp_path / "m.joblib"), persist=False)
    info = engine.train_from_pcap(baseline, contamination=0.05)
    assert info["bio"]["self_trained"] is True
    assert info["edge"]["n_features"] == 12
    assert engine.bio.available

    engine.start("pcap", path=suspicious)
    import time as _t

    deadline = _t.time() + 30
    while engine.running and _t.time() < deadline:
        _t.sleep(0.05)
    assert not engine.running
    assert engine.status["flows"] > 0

    # every flow record carries a slice; immune annotations where assessed
    flows = list(engine.flows)
    assert all("slice" in f for f in flows)
    assessed = [f for f in flows if "immune" in f]
    assert assessed, "bio layer did not annotate any flow"
    for f in assessed:
        assert f["immune"]["level"] in (0, 1, 2, 3)
        assert f["immune"]["response"] in RESPONSES
        assert f["immune"]["slice_policy"]

    # report + explicit assessment are live and JSON-safe
    report = engine.bio_report()
    json.dumps(report)
    assert report["available"] is True
    assert report["assessed"] >= len(assessed)

    out = engine.bio_assess()
    assert out["available"] is True
    explicit = engine.bio_assess([0.0] * N_FEATURES, score=12.0)
    assert explicit["available"] is True
    with pytest.raises(ValueError):
        engine.bio_assess([0.0] * (N_FEATURES - 1))

    # slice counters tracked
    counts = engine.edge_report()["slice_counts"]
    assert sum(counts.values()) == engine.status["flows"]


def test_engine_bio_offline_without_sidecar(tmp_path):
    """A missing bio sidecar must never break the capture path."""
    from spectra.demo import make_baseline_pcap, make_suspicious_pcap
    from spectra.pipeline import SpectraEngine

    baseline = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=30)
    suspicious = make_suspicious_pcap(str(tmp_path / "s.pcap"))
    engine = SpectraEngine(model_path=str(tmp_path / "m.joblib"), persist=False)
    engine.train_from_pcap(baseline, contamination=0.05)
    # simulate a lost sidecar
    engine.bio = type(engine.bio)(contamination=0.05)
    assert not engine.bio.available

    engine.start("pcap", path=suspicious)
    import time as _t

    deadline = _t.time() + 30
    while engine.running and _t.time() < deadline:
        _t.sleep(0.05)
    assert not engine.running
    assert engine.status["flows"] > 0          # capture completed anyway
    assert all("slice" in f for f in engine.flows)
    assert not any("immune" in f for f in engine.flows)


# -- API ---------------------------------------------------------------------


def test_bio_api(tmp_path, upload_capture):
    from fastapi.testclient import TestClient

    from spectra.api.app import app
    from spectra.demo import make_baseline_pcap

    client = TestClient(app)
    baseline = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=30)
    base_id = upload_capture(client, baseline)["capture_id"]
    trained = client.post("/api/model/train",
                          json={"capture_id": base_id, "contamination": 0.05})
    assert trained.status_code == 200

    status = client.get("/api/bio/status")
    assert status.status_code == 200
    body = status.json()
    assert body["available"] is True
    assert body["swarm"]["quorum"] > 0
    assert set(body["response_histogram"]) == set(RESPONSES)

    bad = client.post("/api/bio/assess", json={"features": [0.0] * 10})
    assert bad.status_code == 400

    ok = client.post("/api/bio/assess",
                     json={"features": [0.0] * N_FEATURES, "score": 42.0})
    assert ok.status_code == 200
    payload = ok.json()
    assert payload["available"] is True
    assert payload["response"] in RESPONSES
    json.dumps(payload)
