"""Module 8: 5G/6G edge-native - slices, MEC micro-detector, NTN links.

(The Phase 4 ingest edge cases live in test_edge.py; this file is the
doc's Module 8 - 5G slice awareness + edge deployment architecture.)
"""

from __future__ import annotations

import json

import numpy as np
import pytest

from spectra.features.extractor import FEATURE_NAMES, N_FEATURES
from spectra.modules.edge import (
    LINK_PROFILES,
    LATENCY_BUDGET_MS,
    MICRO_FEATURES,
    EdgeError,
    EdgeSystem,
    MicroDetector,
    SLICES,
    apply_slice_policy,
    classify_slice,
)


def benign_matrix(n: int = 150, seed: int = 42) -> np.ndarray:
    rng = np.random.default_rng(seed)
    X = rng.normal(0.0, 1.0, size=(n, N_FEATURES))
    for name in ("duration_s", "iat_mean_s", "iat_std_s", "packets_per_s",
                 "bytes_per_s", "bytes_total", "bytes_mean"):
        X[:, FEATURE_NAMES.index(name)] = np.abs(
            rng.normal(1.0, 0.3, size=n))
    return X


def burst_row(base: np.ndarray) -> np.ndarray:
    x = base.copy()
    for name in ("bytes_total", "bytes_per_s", "packets_per_s",
                 "iat_mean_s", "size_entropy"):
        x[FEATURE_NAMES.index(name)] = 50.0
    return x


# -- 5G slice awareness ------------------------------------------------------


def test_classify_slice_rules():
    health = {"sni": "portal.hospital.example", "bytes": 900, "packets": 6,
              "duration": 1.0, "tls_version": "TLS 1.3"}
    bulk = {"sni": "cdn.example", "bytes": 3_000_000, "packets": 2000,
            "duration": 1.5, "tls_version": "TLS 1.3"}
    sensor = {"sni": None, "bytes": 400, "packets": 5, "duration": 10.0,
              "tls_version": None}
    plain = {"sni": "example.com", "bytes": 40_000, "packets": 40,
             "duration": 1.0, "tls_version": "TLS 1.3"}

    assert classify_slice(health) == "urllc"
    assert classify_slice(bulk) == "embb"
    assert classify_slice(sensor) == "mmtc"
    assert classify_slice(plain) == "default"
    # critical slice wins over raw throughput
    assert classify_slice({**bulk, "sni": "ehr.hospital.example"}) == "urllc"


def test_classify_slice_never_raises():
    assert classify_slice({}) == "default"
    assert classify_slice({"bytes": None, "packets": "x",
                           "duration": object()}) == "default"
    assert classify_slice({"bytes": "not-a-number"}) == "default"


def test_slice_policy_differentiates_response():
    # URLLC over-reacts: alert escalates to isolate, everything else holds
    assert apply_slice_policy(2, "urllc") == (
        3, "urllc:+1 critical slice escalates")
    assert apply_slice_policy(3, "urllc")[0] == 3
    assert apply_slice_policy(1, "urllc")[0] == 1
    assert apply_slice_policy(0, "urllc")[0] == 0

    # mMTC mutes only single-flow monitor chatter; real alerts survive
    assert apply_slice_policy(1, "mmtc") == (
        0, "mmtc:-1 sensor chatter muted")
    assert apply_slice_policy(2, "mmtc")[0] == 2
    assert apply_slice_policy(3, "mmtc")[0] == 3

    # eMBB/default are policy-neutral, unknown slices fall back to default
    for level in range(4):
        assert apply_slice_policy(level, "embb")[0] == level
        assert apply_slice_policy(level, "default")[0] == level
        assert apply_slice_policy(level, "nope")[0] == level
    assert apply_slice_policy(2, "nope")[1].startswith("default:")


def test_slice_registry_is_complete():
    assert set(SLICES) == {"urllc", "embb", "mmtc", "default"}
    for sid, pol in SLICES.items():
        assert pol["label"] and pol["policy"]
        assert pol["sensitivity"] in (-1, 0, 1)
        assert pol["max_rtt_ms"] > 0


# -- MEC micro-detector ------------------------------------------------------


def test_micro_detector_requires_training():
    micro = MicroDetector()
    assert not micro.trained
    assert micro.digest() is None
    with pytest.raises(EdgeError):
        micro.score(np.zeros(N_FEATURES))
    with pytest.raises(EdgeError):
        MicroDetector().fit(np.zeros((5, N_FEATURES)))


def test_micro_detector_scores():
    X = benign_matrix()
    micro = MicroDetector()
    info = micro.fit(X)
    assert info["n_features"] == len(MICRO_FEATURES) == 12
    assert micro.trained

    benign = micro.score(X[0])
    assert 0.0 <= benign <= 100.0

    evil = micro.score(burst_row(X[0]))
    assert evil > benign
    assert micro.predict(burst_row(X[0])) is True

    with pytest.raises(EdgeError):
        micro.score(np.zeros(N_FEATURES - 1))


def test_micro_latency_within_budget():
    X = benign_matrix()
    micro = MicroDetector()
    micro.fit(X)
    bench = micro.benchmark(X)
    assert bench["available"] is True
    assert bench["budget_ms"] == LATENCY_BUDGET_MS
    assert bench["p95_ms"] < LATENCY_BUDGET_MS
    assert bench["within_budget"] is True
    assert micro.last_benchmark_ms == bench


def test_micro_digest_binds_configuration():
    X = benign_matrix()
    a = MicroDetector()
    a.fit(X)
    b = MicroDetector()
    b.fit(X)
    assert a.digest() == b.digest()          # same data -> same digest

    c = MicroDetector()
    c.fit(benign_matrix(seed=99))
    assert c.digest() != a.digest()          # different baseline -> different


# -- NTN link profiles -------------------------------------------------------


def test_ntn_link_profiles_and_timing_scale():
    assert set(LINK_PROFILES) == {"terrestrial", "uav", "leo_satellite",
                                  "geostationary"}
    edge = EdgeSystem()
    assert edge.link == "terrestrial"
    assert edge.timing_scale() == 1.0

    edge.set_link("geostationary")
    assert edge.timing_scale() == pytest.approx(600.0 / 15.0)
    edge.set_link("leo_satellite")
    info = edge.link_info()
    assert info["timing_scale"] > 1.0
    assert info["rtt_ms"] > 0

    with pytest.raises(EdgeError) as exc:
        edge.set_link("warp_drive")
    assert "geostationary" in str(exc.value)   # error lists known profiles


def test_edge_deploy_profiles():
    edge = EdgeSystem()
    with pytest.raises(EdgeError):
        edge.deploy("mec-01", "urllc")          # micro not trained yet

    edge.fit(benign_matrix())
    with pytest.raises(EdgeError):
        edge.deploy("", "urllc")                # node id required

    p1 = edge.deploy("mec-01", "urllc")
    assert p1["features"] == list(MICRO_FEATURES)
    assert p1["digest"] and p1["budget_ms"] == LATENCY_BUDGET_MS
    assert p1["slice"] == "urllc" and p1["link"] == "terrestrial"

    edge.deploy("mec-02", "mmtc")
    edge.deploy("mec-01", "default")            # redeploy replaces, no dupes
    nodes = [d["node"] for d in edge.report()["deployments"]]
    assert sorted(nodes) == ["mec-01", "mec-02"]


def test_edge_report_shape_and_json():
    edge = EdgeSystem()
    edge.fit(benign_matrix())
    edge.deploy("mec-01", "urllc")
    rep = edge.report()
    assert rep["link"]["link"] == "terrestrial"
    assert rep["micro"]["trained"] is True
    assert rep["micro"]["threshold_pct"] > 0
    assert set(rep["link_profiles"]) == set(LINK_PROFILES)
    json.dumps(rep)


def test_edge_persistence(tmp_path):
    import joblib

    path = str(tmp_path / "edge.joblib")
    edge = EdgeSystem()
    edge.fit(benign_matrix())
    edge.deploy("mec-07", "urllc")
    edge.set_link("leo_satellite")
    edge.save(path)

    back = EdgeSystem()
    assert back.load(path) is True
    assert back.micro.trained is True
    assert back.link == "leo_satellite"
    assert [d["node"] for d in back.deployments] == ["mec-07"]
    assert back.micro.digest() == edge.micro.digest()

    assert EdgeSystem().load(str(tmp_path / "missing.joblib")) is False
    joblib.dump({"version": 999}, path)
    assert EdgeSystem().load(path) is False


# -- engine integration ------------------------------------------------------


def test_engine_edge_integration(tmp_path):
    from spectra.demo import make_baseline_pcap, make_suspicious_pcap
    from spectra.pipeline import SpectraEngine

    baseline = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=30)
    suspicious = make_suspicious_pcap(str(tmp_path / "s.pcap"))
    engine = SpectraEngine(model_path=str(tmp_path / "m.joblib"), persist=False)
    info = engine.train_from_pcap(baseline, contamination=0.05)
    assert info["edge"]["latency_ms"]["within_budget"] is True

    engine.start("pcap", path=suspicious)
    import time as _t

    deadline = _t.time() + 30
    while engine.running and _t.time() < deadline:
        _t.sleep(0.05)
    assert not engine.running

    rep = engine.edge_report()
    json.dumps(rep)
    assert rep["micro"]["trained"] is True
    assert sum(rep["slice_counts"].values()) == engine.status["flows"]
    assert set(rep["slices"]) == set(SLICES)

    # NTN switch changes the timing scale the bio layer divides by
    before = engine.bio_report()["timing_scale"]
    engine.edge_set_link("geostationary")
    assert engine.bio_report()["timing_scale"] == pytest.approx(40.0)
    assert before == 1.0
    engine.edge_set_link("terrestrial")

    profile = engine.edge_deploy("mec-9", "urllc")
    assert profile["digest"]
    # sidecar persists link + deployments
    engine.edge_save()
    fresh = SpectraEngine(model_path=str(tmp_path / "m.joblib"), persist=False)
    assert [d["node"] for d in fresh.edge.deployments] == ["mec-9"]


def test_engine_bio_on_satellite_link(tmp_path):
    """Same flow, different link profile -> the SNN judges NTNs fairly."""
    from spectra.pipeline import SpectraEngine
    from spectra.modules.bio import TimingSNN

    # direct SNN-level check is deterministic; engine supplies the wiring
    rng = np.random.default_rng(5)
    X = rng.normal(0.0, 1.0, size=(120, N_FEATURES))
    for name in ("duration_s", "iat_mean_s", "iat_std_s", "iat_min_s",
                 "iat_max_s", "iat_fwd_mean_s", "iat_fwd_std_s",
                 "iat_fwd_mad_s", "packets_per_s"):
        X[:, FEATURE_NAMES.index(name)] = rng.normal(1.0, 0.05, size=120)
    snn = TimingSNN().fit(X)

    slow = X[0].copy()
    for name in ("duration_s", "iat_mean_s", "iat_std_s", "iat_min_s",
                 "iat_max_s", "iat_fwd_mean_s", "iat_fwd_std_s",
                 "iat_fwd_mad_s", "packets_per_s"):
        slow[FEATURE_NAMES.index(name)] = 5.0

    terrestrial = snn.score(slow[None, :], timing_scale=1.0)[0]
    satellite = snn.score(slow[None, :], timing_scale=5.0)[0]
    assert satellite < terrestrial
    engine = SpectraEngine(model_path=str(tmp_path / "m.joblib"), persist=False)
    engine.edge.set_link("geostationary")
    assert engine.edge.timing_scale() == pytest.approx(40.0)


# -- API ---------------------------------------------------------------------


def test_edge_api(tmp_path):
    from fastapi.testclient import TestClient

    from spectra.api.app import app

    client = TestClient(app)

    rep = client.get("/api/edge/report")
    assert rep.status_code == 200
    body = rep.json()
    assert body["link"]["link"] in LINK_PROFILES
    assert set(body["slices"]) == set(SLICES)
    assert "slice_counts" in body

    cls = client.post("/api/edge/slice", json={
        "record": {"sni": "portal.hospital.example", "bytes": 900,
                   "packets": 6, "duration": 1.0, "tls_version": "TLS 1.3"},
        "level": 2,
    })
    assert cls.status_code == 200
    out = cls.json()
    assert out["slice"] == "urllc"
    assert out["adjusted_level"] == 3
    assert out["policy"]["label"]

    assert client.post("/api/edge/link",
                       json={"link": "warp_drive"}).status_code == 400
    ok = client.post("/api/edge/link", json={"link": "terrestrial"})
    assert ok.status_code == 200
    assert ok.json()["link"]["timing_scale"] == 1.0
