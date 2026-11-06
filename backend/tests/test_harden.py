"""Phase 9B: adversarial-retraining harness (report only).

The harness builds a candidate from the incumbent's own evasion attacks,
compares both under attack, and recommends promotion only when the candidate
is measurably no worse.  It never swaps the session model, so these tests pin
three things: the gate's decisions, that nothing is promoted or leaks feature
vectors, and that every run is audit-chained.  They deliberately do NOT assert
that retraining makes the model harder to evade - the recorded experiment
(HANDOFF_FINDINGS.md, 9B) found that it does not.
"""

from __future__ import annotations

import json
import threading
import time

import numpy as np
import pytest

from spectra.config import Config
from spectra.demo import make_baseline_pcap
from spectra.features.extractor import N_FEATURES
from spectra.pipeline import SpectraEngine
from spectra.services.harden import HardenScheduler, decide
from spectra.services.model import AnalysisBusy


def _metrics(before, after, fp):
    return {"detect_before": before, "detect_after": after, "false_flag_rate": fp}


# -- the gate -------------------------------------------------------------------

def test_gate_blocks_when_candidate_is_not_more_robust():
    promote, reason = decide(_metrics(0.9, 0.30, 0.02), _metrics(0.9, 0.30, 0.02))
    assert promote is False and "robustness" in reason


def test_gate_blocks_when_candidate_detects_less_before_any_attack():
    promote, reason = decide(_metrics(0.9, 0.2, 0.02), _metrics(0.6, 0.8, 0.02))
    assert promote is False and "before" in reason


def test_gate_blocks_when_false_flags_rise():
    promote, reason = decide(_metrics(0.9, 0.2, 0.02), _metrics(0.9, 0.8, 0.09))
    assert promote is False and "false-flag" in reason


def test_gate_recommends_only_a_clear_win():
    promote, reason = decide(_metrics(0.9, 0.2, 0.02), _metrics(0.9, 0.5, 0.02))
    assert promote is True and "separate" in reason     # promotion stays explicit


# -- augmented_fit -----------------------------------------------------------------

def _engine(tmp_path):
    cfg = Config(persist=True)
    cfg.data_dir = str(tmp_path / "data")
    cfg.capture_store_dir = str(tmp_path / "data" / "captures")
    cfg.model_path = str(tmp_path / "data" / "m.joblib")
    cfg.ensure_dirs()
    return SpectraEngine(config=cfg)


def _trained(tmp_path, n_flows=120):
    engine = _engine(tmp_path)
    pcap = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=n_flows)
    engine.train_from_pcap(pcap, contamination=0.05)
    return engine, pcap


def test_augmented_fit_returns_scratch_detector_and_leaves_session_alone(tmp_path):
    engine, _ = _trained(tmp_path)
    rng = np.random.default_rng(0)
    X = np.abs(rng.normal(5, 1, (60, N_FEATURES)))
    attacked = np.abs(rng.normal(5, 1, (10, N_FEATURES)))
    before = (engine.model.detector, engine.model.detector._threshold)

    cand = engine.training.augmented_fit(X, attacked)
    assert cand.is_trained and cand is not engine.model.detector
    assert (engine.model.detector, engine.model.detector._threshold) == before
    assert engine.training.augmented_fit(X).is_trained        # attacked is optional

    with pytest.raises(ValueError):
        engine.training.augmented_fit(X, np.zeros((3, N_FEATURES + 1)))


# -- the service -------------------------------------------------------------------

def test_harden_reports_without_promoting_and_is_audit_chained(tmp_path):
    engine, pcap = _trained(tmp_path)
    incumbent = engine.model.detector
    threshold = incumbent._threshold
    registered = engine.registry.count()

    res = engine.harden.harden(pcap=pcap, actor="tester")
    assert res["available"] is True
    assert isinstance(res["promote"], bool) and res["reason"]
    assert res["promoted"] is False                            # report only
    assert engine.model.detector is incumbent                  # session untouched
    assert incumbent._threshold == threshold
    assert engine.registry.count() == registered              # no candidate registered
    for key in ("incumbent", "candidate"):
        assert set(res[key]) >= {"detect_before", "detect_after", "false_flag_rate"}
    assert res["shadow"]["available"] is True
    # metadata-only / no vectors: neither perturbed rows nor raw features come back
    blob = json.dumps(res)
    assert "perturbed" not in blob and "reports" not in blob

    kinds = [e["kind"] for e in engine.audit_service.entries(limit=50)["items"]]
    assert "model.harden" in kinds and "model.shadow" in kinds
    assert engine.audit_service.verify()["ok"] is True          # chain intact
    harden = next(e for e in engine.audit_service.entries(limit=50)["items"]
                  if e["kind"] == "model.harden")
    assert harden["actor"] == "tester"


def test_harden_refuses_untrained_tiny_and_concurrent_runs(tmp_path):
    engine = _engine(tmp_path)
    assert engine.harden.harden()["available"] is False         # no model, no window

    engine, pcap = _trained(tmp_path)
    assert engine.harden.harden()["available"] is False         # empty live window
    with engine.model.analysis_slot():
        with pytest.raises(AnalysisBusy):
            engine.harden.harden(pcap=pcap)


# -- the API -----------------------------------------------------------------------

def test_api_harden_is_admin_only_and_report_only(client, viewer_client,
                                                  analyst_client, upload_capture,
                                                  tmp_path):
    pcap = make_baseline_pcap(str(tmp_path / "api.pcap"), n_flows=120, seed=3)
    cid = upload_capture(client, pcap)["capture_id"]
    assert client.post("/api/model/train", json={
        "capture_id": cid, "contamination": 0.05}).status_code == 200

    for role_client in (viewer_client, analyst_client):
        assert role_client.post("/api/model/harden",
                                json={"capture_id": cid}).status_code == 403

    active_before = client.get("/api/model/registry").json()["active"]["model_id"]
    res = client.post("/api/model/harden", json={"capture_id": cid})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["promoted"] is False and isinstance(body["promote"], bool)
    assert "/" not in body["source"]                           # no server path
    assert client.get("/api/model/registry").json()["active"]["model_id"] == active_before

    kinds = {e["kind"] for e in client.get("/api/audit/entries?limit=100").json()["items"]}
    assert {"model.harden", "model.shadow"} <= kinds
    assert client.get("/api/audit/verify").json()["ok"] is True

    assert client.post("/api/model/harden", json={"capture_id": 999999}).status_code == 404
    assert client.post("/api/model/harden", json={"capture_id": cid,
                                                  "max_attack_rows": 0}).status_code == 422


# -- the opt-in scheduler -----------------------------------------------------------

def test_scheduler_is_off_by_default_and_runs_when_enabled(tmp_path):
    assert Config().harden_interval_h == 0.0
    engine = _engine(tmp_path)
    assert engine.harden.start_scheduler() is None              # disabled: no thread

    calls = []
    ran = threading.Event()

    def run():
        calls.append(1)
        ran.set()

    sched = HardenScheduler(run, interval_s=0.05)
    sched.start()
    assert ran.wait(2.0)
    sched.stop()
    n = len(calls)
    time.sleep(0.2)
    assert len(calls) == n                                       # stopped means stopped


def test_scheduler_survives_a_failing_run():
    ran = threading.Event()
    state = {"n": 0}

    def run():
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("boom")
        ran.set()

    sched = HardenScheduler(run, interval_s=0.05)
    sched.start()
    assert ran.wait(2.0)                                         # second run happened
    sched.stop()


def test_enabled_scheduler_runs_the_real_harden_on_the_live_window(tmp_path):
    """Config interval -> start_scheduler -> HardenService.harden -> audit chain."""
    cfg = Config(persist=True)
    cfg.data_dir = str(tmp_path / "iso")
    cfg.db_path = str(tmp_path / "iso" / "spectra.db")   # own DB: other tests also write model.harden
    cfg.capture_store_dir = str(tmp_path / "iso" / "captures")
    cfg.model_path = str(tmp_path / "iso" / "m.joblib")
    cfg.ensure_dirs()
    engine = SpectraEngine(config=cfg)
    engine.train_from_pcap(make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=120),
                           contamination=0.05)
    engine.config.harden_interval_h = 0.00003            # ~0.1 s, test only
    rng = np.random.default_rng(0)
    for row in np.abs(rng.normal(5, 1, (12, N_FEATURES))):   # a live window to attack
        engine.alerts.on_scored(row, 1.0)

    sched = engine.harden.start_scheduler()
    assert sched is not None
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            kinds = [e["kind"] for e in engine.audit_service.entries(limit=50)["items"]]
            if "model.harden" in kinds:
                break
            time.sleep(0.05)
    finally:
        sched.stop()
    entry = next(e for e in engine.audit_service.entries(limit=50)["items"]
                 if e["kind"] == "model.harden")
    assert entry["actor"] == "spectra-scheduler"          # the scheduled path, not a person
    assert entry["payload"]["promote"] is False
    assert engine.audit_service.verify()["ok"] is True
