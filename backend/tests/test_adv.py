"""Module 3 tests: evasion attacks, threshold-hugging watch, drift (PSI)."""

import time

import numpy as np
from fastapi.testclient import TestClient
from scapy.utils import PcapWriter

from spectra.demo import beacon_flow_packets, make_baseline_pcap, tls_flow_packets
from spectra.features.extractor import N_FEATURES
from spectra.ml.model import SpectraDetector
from spectra.modules.adv import attack, attack_batch, score_boundary, watch
from spectra.modules.adv.watch import ScoreWindow
from spectra.pipeline import SpectraEngine


def _trained_detector(seed=7) -> tuple[SpectraDetector, np.ndarray]:
    rng = np.random.default_rng(seed)
    X = rng.lognormal(mean=2.0, sigma=0.4, size=(300, N_FEATURES))
    det = SpectraDetector(contamination=0.05)
    det.fit(X)
    return det, X


# -- evasion attack ----------------------------------------------------------

def test_greedy_attack_evades_extreme_flow():
    det, X = _trained_detector()
    x = X.mean(axis=0) + 10.0 * X.std(axis=0)

    assert bool(det.predict(x)[0]), "synthetic flow should be flagged"

    report = attack(det, x, max_features=N_FEATURES, max_rounds=8)
    assert report["was_anomalous"] is True
    assert report["evaded"] is True
    assert report["score_after"] < report["score_before"]
    assert report["features_changed"] > 0
    assert report["l1"] > 0 and report["l2"] > 0
    assert report["changes"], "perturbation report must list feature edits"
    assert {c["feature"] for c in report["changes"]} <= set(det.feature_names)
    # the claim is verified against the model, not asserted
    assert not det.predict(np.asarray(report["perturbed"]))[0]


def test_attack_leaves_benign_flows_alone():
    det, X = _trained_detector()
    x = X[0]
    assert not det.predict(x)[0]
    report = attack(det, x, max_features=N_FEATURES, max_rounds=4)
    # never claims evasion for something that was never flagged
    assert report["was_anomalous"] is False
    assert report["evaded"] is False


def test_attack_batch_robustness_stats():
    det, X = _trained_detector()
    extreme = np.vstack([
        X.mean(axis=0) + 10 * X.std(axis=0),
        X.mean(axis=0) + 6 * X.std(axis=0),
        X[:3],
    ])
    result = attack_batch(det, extreme, max_features=N_FEATURES, max_rounds=8)

    assert result["evaluated"] == 5
    assert result["flagged"] >= 1
    assert 0.0 <= result["evasion_rate"] <= 1.0
    assert result["level"] in ("fragile", "hardened",
                               "partially_robust", "no_anomalies")
    assert isinstance(result["most_targeted_features"], list)
    if result["evaded"]:
        assert result["median_l2"] is not None
        assert result["reports"]

    empty = attack_batch(det, X[:0])
    assert empty["flagged"] == 0 and empty["level"] == "no_anomalies"


# -- threshold-hugging watch -------------------------------------------------

def test_boundary_and_insufficient_window():
    assert score_boundary(0.02) == 98.0
    assert score_boundary(0.10) == 90.0
    r = watch([10.0] * 10, contamination=0.1)
    assert r["available"] is False


def test_watch_flags_threshold_hugging():
    # a hard wall of scores parked just below a 90-point boundary
    hugging = [87.0 + (i % 3) for i in range(60)]
    r = watch(hugging, contamination=0.1)
    assert r["suspected"] is True
    assert r["near_miss_rate"] > 0.9
    assert r["reasons"]

    # natural spread below the boundary
    rng = np.random.default_rng(3)
    natural = list(rng.uniform(5, 80, size=80))
    r2 = watch(natural, contamination=0.1)
    assert r2["suspected"] is False
    assert r2["reasons"] == []


def test_score_window_alerts_once_until_reset():
    win = ScoreWindow(contamination=0.1)
    fired = None
    for _ in range(60):
        out = win.add(88.0)
        if out:
            fired = out
            break
    assert fired is not None and fired["suspected"] is True
    assert win.alerted is True
    # no repeat alert while the condition persists
    assert win.add(88.0) is None

    for _ in range(300):  # recover: push the near-miss scores out of the window
        win.add(20.0)
    assert win.alerted is False
    # and it can fire again afterwards
    again = None
    for _ in range(60):
        out = win.add(88.0)
        if out:
            again = out
            break
    assert again is not None


# -- drift (PSI) -------------------------------------------------------------

def test_psi_stable_vs_shifted():
    det, X = _trained_detector()

    stable = det.psi(X)
    assert stable["available"] is True
    assert stable["level"] == "stable"
    assert stable["psi"] < 0.10

    rng = np.random.default_rng(11)
    shifted = X * 8.0 + rng.normal(0, X.std() * 4, size=X.shape).clip(min=0)
    moved = det.psi(shifted)
    assert moved["psi"] > 0.25
    assert moved["level"] == "significant"
    assert moved["features"][0]["psi"] >= moved["features"][-1]["psi"]

    assert det.psi(np.empty((0, N_FEATURES)))["n"] == 0


def test_psi_unavailable_without_baseline():
    det, _ = _trained_detector()
    det._baseline_props = None
    r = det.psi(np.zeros((5, N_FEATURES)))
    assert r["available"] is False


# -- engine + API integration ------------------------------------------------

def _write(path, flows):
    w = PcapWriter(str(path), sync=True)
    for pkts in flows:
        for p in pkts:
            w.write(p)
    w.close()
    return str(path)


def test_engine_phase3_and_api(tmp_path, upload_capture):
    baseline = make_baseline_pcap(str(tmp_path / "baseline.pcap"), n_flows=40)
    # enough scored flows to satisfy the watch's MIN_WINDOW
    window = _write(tmp_path / "window.pcap", [
        tls_flow_packets(sport=41000 + i, sni=f"site{i}.example",
                         start=1_700_000_000.0 + i * 3)
        for i in range(45)
    ])
    suspicious = _write(tmp_path / "susp.pcap", [
        tls_flow_packets(sport=41500, sni="cdn.example"),
        beacon_flow_packets(sport=41501),
        beacon_flow_packets(sport=41502),
    ])

    engine = SpectraEngine(model_path=str(tmp_path / "model.joblib"))
    engine.train_from_pcap(baseline, contamination=0.05)
    engine.start("pcap", path=window)
    deadline = time.time() + 30
    while engine.running and time.time() < deadline:
        time.sleep(0.05)
    assert not engine.running

    # window state accumulated
    assert len(engine._recent_feats) >= 40
    watch_report = engine.evasion_watch()
    assert watch_report["available"] is True
    assert "near_miss_rate" in watch_report

    drift = engine.drift_report()
    assert drift["available"] is True
    assert drift["level"] in ("stable", "moderate", "significant")
    assert drift["window"] >= 40

    # robustness on the live window (structure, whatever the labels)
    rob = engine.robustness()
    assert rob["available"] is True
    assert rob["source"] == "live window"
    assert rob["flagged"] >= 0

    # robustness against a PCAP full of anomalies
    rob_pcap = engine.robustness(pcap=suspicious)
    assert rob_pcap["available"] is True
    assert rob_pcap["source"] == suspicious

    # ---- API ----
    import spectra.api.app as app_module

    app_module.engine.detector = engine.detector
    app_module.engine._recent_feats = engine._recent_feats
    app_module.engine.score_watch = engine.score_watch
    client = TestClient(app_module.app)

    res = client.get("/api/model/drift")
    assert res.status_code == 200
    assert res.json()["available"] is True

    res = client.get("/api/model/evasion")
    assert res.status_code == 200
    assert res.json()["available"] is True

    cap_id = upload_capture(client, suspicious)["capture_id"]
    res = client.post("/api/model/robustness", json={"capture_id": cap_id})
    assert res.status_code == 200
    body = res.json()
    assert body["available"] is True
    assert body["flagged"] >= 1, "suspicious pcap must yield anomalies to attack"
    assert body["evasion_rate"] >= 0.0

    res = client.post("/api/model/robustness", json={"capture_id": 999999})
    assert res.status_code == 404

    res = client.post("/api/model/robustness", json={})
    assert res.status_code == 200
    assert res.json()["source"] == "live window"
