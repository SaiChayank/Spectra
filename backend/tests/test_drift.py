"""Phase 9E: rolling PSI baseline (psi_vs_recent) next to the training PSI.

What these tests pin, and what they deliberately do not: the recent reference
re-baselines after a legitimate step change and flags abrupt change against
recent history, but a *slow* monotonic shift is caught by the training PSI
first - the recent reference absorbs the drift as it happens (recorded
experiment, HANDOFF_FINDINGS.md 9E).  The plan's Done-when ("slow shift trips
psi_vs_recent before psi_vs_train") is therefore NOT asserted; the opposite
ordering is.
"""

from __future__ import annotations

from collections import deque

import numpy as np

from spectra.config import Config
from spectra.features.extractor import N_FEATURES
from spectra.ml.model import SpectraDetector
from spectra.pipeline import SpectraEngine
from spectra.services.alerts import REF_MAX, REF_SAMPLE_EVERY, AlertService


def _detector(seed=7):
    rng = np.random.default_rng(seed)
    X = rng.lognormal(mean=2.0, sigma=0.4, size=(2000, N_FEATURES))
    det = SpectraDetector(contamination=0.05)
    det.fit(X)
    return det, X


def _draw(rng, n, scale=1.0):
    return rng.lognormal(mean=2.0, sigma=0.4, size=(n, N_FEATURES)) * scale


# -- psi_vs: the comparison itself ---------------------------------------------

def test_psi_vs_stable_same_distribution_and_abrupt_change():
    det, _ = _detector()
    rng = np.random.default_rng(1)
    ref, same = _draw(rng, 800), _draw(rng, 500)
    stable = det.psi_vs(ref, same)
    assert stable["available"] is True and stable["level"] == "stable"
    assert stable["psi"] < 0.10 and stable["n_ref"] == 800 and stable["n"] == 500

    jumped = det.psi_vs(ref, _draw(rng, 500, scale=1.8))
    assert jumped["level"] in ("moderate", "significant")
    assert jumped["psi"] > stable["psi"]

    assert det.psi_vs(ref[:0], same)["n_ref"] == 0
    det._baseline_props = None
    assert det.psi_vs(ref, same)["available"] is False


# -- the rolling reference ---------------------------------------------------------

def _alerts():
    cfg = Config(persist=False)
    return AlertService(cfg, events=_Sink(), audit=_Sink(), failures=_Sink(),
                        contamination=0.02, recent_feats=deque(maxlen=1000))


class _Sink:
    """Stands in for EventBus / AuditService / FailureTracker (all unused here)."""
    def emit(self, *a, **k): ...
    def append(self, *a, **k): ...
    def guard(self, name, fn, default=None):
        return fn()
    def record(self, *a, **k): ...


def test_reference_is_sampled_bounded_and_excludes_the_current_window():
    a = _alerts()
    rng = np.random.default_rng(0)
    for _ in range(REF_SAMPLE_EVERY * 10):
        a.on_scored(rng.random(N_FEATURES), 1.0)
    assert len(a.ref_feats) == 10                         # one in REF_SAMPLE_EVERY
    for _ in range(REF_SAMPLE_EVERY * (REF_MAX + 50)):
        a.on_scored(rng.random(N_FEATURES), 1.0)
    assert len(a.ref_feats) == REF_MAX                    # bounded

    # recent window holds the newest 1000 flows; the reference drops their share
    ref = a.reference_matrix()
    assert ref.shape == (REF_MAX - 1000 // REF_SAMPLE_EVERY, N_FEATURES)
    a.reset_session()
    assert a.reference_matrix() is None and len(a.ref_feats) == 0


def test_reference_warms_up_before_it_reports():
    a = _alerts()
    rng = np.random.default_rng(0)
    for _ in range(REF_SAMPLE_EVERY * 50):
        a.on_scored(rng.random(N_FEATURES), 1.0)
    assert a.reference_matrix() is None                   # too little history


# -- engine: both numbers, and what each one is good for ----------------------------

def _engine(tmp_path):
    cfg = Config(persist=False)
    cfg.data_dir = str(tmp_path / "d")
    cfg.capture_store_dir = str(tmp_path / "d" / "c")
    cfg.model_path = str(tmp_path / "d" / "m.joblib")
    cfg.ensure_dirs()
    e = SpectraEngine(config=cfg)
    det, X = _detector()
    e.model.detector = det
    return e, det, X


def _feed(engine, X):
    for row in X:
        engine.alerts.on_scored(row, 1.0)


def test_drift_report_has_both_psis_and_legacy_keys_unchanged(tmp_path):
    engine, det, X = _engine(tmp_path)
    rng = np.random.default_rng(2)
    _feed(engine, _draw(rng, 6000))
    rep = engine.model.drift_report()
    assert rep["available"] is True
    assert {"psi", "level", "n", "window", "features"} <= set(rep)      # legacy
    assert rep["psi_vs_train"] == {"psi": rep["psi"], "level": rep["level"]}
    rec = rep["psi_vs_recent"]
    assert rec["available"] is True and rec["level"] == "stable"
    # alert_level is the worse of the two (the 40-bin training PSI has its own
    # sampling-noise floor, so it can read "moderate" on same-distribution data)
    order = ("stable", "moderate", "significant")
    assert rep["alert_level"] == max(rep["level"], rec["level"], key=order.index)

    fresh, *_ = _engine(tmp_path / "x")
    _feed(fresh, _draw(rng, 100))
    warm = fresh.model.drift_report()["psi_vs_recent"]
    assert warm["available"] is False and "warming" in warm["reason"]


def test_recent_comparison_rebaselines_after_a_legitimate_step_change(tmp_path):
    engine, det, X = _engine(tmp_path)
    rng = np.random.default_rng(3)
    _feed(engine, _draw(rng, 5000, scale=1.8))            # network changed long ago
    rep = engine.model.drift_report()
    assert rep["psi_vs_train"]["level"] in ("moderate", "significant")   # stale vs train
    assert rep["psi_vs_recent"]["level"] == "stable"                     # but settled


def test_recent_comparison_flags_an_abrupt_change_against_recent_history(tmp_path):
    engine, det, X = _engine(tmp_path)
    rng = np.random.default_rng(4)
    _feed(engine, _draw(rng, 5000))
    _feed(engine, _draw(rng, 1000, scale=1.8))            # the last 1000 flows jump
    rep = engine.model.drift_report()
    assert rep["psi_vs_recent"]["level"] in ("moderate", "significant")
    assert rep["alert_level"] in ("moderate", "significant")


def test_alerts_fire_on_either_comparison_and_never_less_than_before(tmp_path):
    engine, *_ = _engine(tmp_path)
    events = []
    engine.subscribe(events.append)
    stable = {"level": "stable"}
    # recent says moderate while train says stable -> still one drift alert
    engine.alerts.note_drift({"available": True, **stable, "psi": 0.01, "n": 500,
                              "alert_level": "moderate"})
    assert [e["type"] for e in events].count("drift") == 1
    assert engine.alerts.drift_level == "moderate"
    # legacy report without alert_level behaves exactly as before
    engine.alerts.note_drift({"available": True, "level": "stable", "psi": 0.0, "n": 5})
    assert engine.alerts.drift_alerted is False


def test_slow_shift_is_caught_by_the_training_psi_first(tmp_path):
    """Recorded finding, not the plan's claim: a recent reference absorbs slow drift."""
    engine, det, X = _engine(tmp_path)
    rng = np.random.default_rng(5)
    _feed(engine, _draw(rng, 5000))
    first = {"train": None, "recent": None}
    for step in range(60):
        _feed(engine, _draw(rng, 400, scale=1.0 + 0.012 * step))   # +1.2 % per step
        rep = engine.model.drift_report()
        if first["train"] is None and rep["psi_vs_train"]["level"] != "stable":
            first["train"] = step
        if (first["recent"] is None and rep["psi_vs_recent"].get("level") not in
                (None, "stable")):
            first["recent"] = step
    assert first["train"] is not None, "the training PSI never noticed the drift"
    assert first["recent"] is None or first["train"] <= first["recent"]


def test_reference_holds_only_numeric_feature_vectors(tmp_path):
    """Metadata-only: the rolling reference stores feature vectors, nothing else."""
    engine, *_ = _engine(tmp_path)
    rng = np.random.default_rng(6)
    _feed(engine, _draw(rng, 400))
    assert all(isinstance(v, np.ndarray) and v.dtype.kind == "f"
               and v.shape == (N_FEATURES,) for v in engine.alerts.ref_feats)


# -- API ------------------------------------------------------------------------------

def test_api_drift_exposes_both_comparisons(tmp_path):
    from fastapi.testclient import TestClient

    import spectra.api.app as app_module

    det, _ = _detector()
    rng = np.random.default_rng(7)
    app_module.engine.model.detector = det
    app_module.engine.alerts.reset_session()
    for row in _draw(rng, 6000):
        app_module.engine.alerts.on_scored(row, 1.0)
    client = TestClient(app_module.app)
    res = client.get("/api/model/drift")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["psi_vs_train"]["level"] in ("stable", "moderate", "significant")
    assert body["psi_vs_recent"]["available"] is True
    assert "alert_level" in body
