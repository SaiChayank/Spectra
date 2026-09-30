"""Tests for the application-service extraction (architectural refactor).

Each service boundary, the domain models and the SpectraEngine compatibility
faucade are pinned here; the rest of the suite (API, modules, end-to-end)
acts as the behavioural regression net.
"""

from __future__ import annotations

import time
from collections import deque

import numpy as np

from spectra.domain import CaptureSession, ModelVersion
from spectra.ml.model import SpectraDetector
from spectra.pipeline import SpectraEngine
from spectra.services import (
    AlertService,
    AuditService,
    CaptureService,
    CorrelationService,
    DetectionService,
    EventBus,
    FailureTracker,
    ModelService,
    SystemService,
    TrainingService,
)


# -- EventBus -----------------------------------------------------------------


def test_eventbus_delivers_and_unsubscribes():
    bus = EventBus()
    seen: list[dict] = []
    unsubscribe = bus.subscribe(seen.append)
    bus.emit({"type": "flow", "data": {"ts": 1.0}})
    assert [e["type"] for e in seen] == ["flow"]
    unsubscribe()
    bus.emit({"type": "flow", "data": {"ts": 2.0}})
    assert len(seen) == 1


def test_eventbus_isolates_failing_listener():
    bus = EventBus()
    seen: list[dict] = []

    def bad(event: dict) -> None:
        raise RuntimeError("boom")

    bus.subscribe(bad)
    bus.subscribe(seen.append)
    bus.emit({"type": "status", "data": {}})  # must not raise
    assert len(seen) == 1


# -- FailureTracker -----------------------------------------------------------


def test_failure_tracker_counts_and_syncs_status():
    status: dict = {"failures": {}}
    tracker = FailureTracker(status)
    tracker.record("pqc", RuntimeError("x"))
    assert status["failures"] == {"pqc": 1}
    assert tracker.counts == {"pqc": 1}
    assert tracker.guard("bio", lambda: 1 / 0, default="d") == "d"
    assert status["failures"]["bio"] == 1
    assert tracker.guard("fine", lambda: 7) == 7
    assert "fine" not in status["failures"]


def test_engine_resilience_facade():
    engine = SpectraEngine(persist=False)
    engine._record_failure("probe", RuntimeError("x"))
    assert engine.status["failures"].get("probe", 0) == 1
    assert engine._guard("probe", lambda: 1 / 0) is None
    assert engine.status["failures"]["probe"] == 2
    assert engine._guard("probe", lambda: "ok") == "ok"


# -- domain models ------------------------------------------------------------


def test_capture_session_lifecycle():
    session = CaptureSession()
    session.begin(mode="pcap", source="b.pcap", started_at=1.0)
    assert session.leaves == [] and session.capture_id is None
    assert session.bpf_filter is None and session.source == "b.pcap"
    session.add_leaf({"ts": 1.0}, cap=2)
    session.add_leaf({"ts": 2.0}, cap=2)
    session.add_leaf({"ts": 3.0}, cap=2)  # over cap: dropped
    assert len(session.leaves) == 2
    session.capture_id = 5
    session.end()
    assert session.capture_id is None
    session.begin(mode="live", source="eth0", started_at=2.0, bpf_filter="tcp")
    assert session.leaves == [] and session.bpf_filter == "tcp"


def test_model_version_from_info():
    mv = ModelVersion.from_info("m.joblib", {
        "trained": True, "trained_at": 12.5, "n_train": 40,
        "n_features": 12, "contamination": 0.05, "threshold": 3.1,
        "version": "1",
    })
    payload = mv.to_dict()
    assert payload == {
        "path": "m.joblib", "trained": True, "trained_at": 12.5,
        "n_train": 40, "n_features": 12, "contamination": 0.05,
        "threshold": 3.1, "version": "1",
    }


# -- service wiring -----------------------------------------------------------


def test_engine_exposes_all_services():
    engine = SpectraEngine(persist=False)
    assert isinstance(engine.events, EventBus)
    assert isinstance(engine.failures, FailureTracker)
    assert isinstance(engine.audit_service, AuditService)
    assert isinstance(engine.alerts, AlertService)
    assert isinstance(engine.model, ModelService)
    assert isinstance(engine.correlation, CorrelationService)
    assert isinstance(engine.detection, DetectionService)
    assert isinstance(engine.capture, CaptureService)
    assert isinstance(engine.training, TrainingService)
    assert isinstance(engine.system, SystemService)
    # one shared status dict + one shared recent window
    assert engine.system.status is engine.status
    assert engine.capture.status is engine.status
    assert engine.detection.status is engine.status
    assert (engine.detection.recent_feats is engine.alerts.recent_feats
            is engine.model.recent_feats)


def test_facade_rebinding_updates_owning_services():
    """Historical ``engine.<attr> = x`` rebinding (used by the API tests)."""
    engine = SpectraEngine(persist=False)

    fresh = SpectraDetector()
    engine.detector = fresh
    assert engine.model.detector is fresh and engine.detector is fresh

    window: deque = deque(maxlen=5)
    engine._recent_feats = window
    assert engine.detection.recent_feats is window
    assert engine.alerts.recent_feats is window
    assert engine.model.recent_feats is window
    assert engine._recent_feats is window

    class FakeStore:
        pass

    fake = FakeStore()
    engine.store = fake
    for svc in (engine.audit_service, engine.correlation, engine.detection,
                engine.capture, engine.training, engine.system):
        assert svc.store is fake
    assert engine.store is fake
    engine.store = None

    engine.bio = object()
    assert engine.detection.bio is engine.bio
    engine.edge = object()
    assert engine.detection.edge is engine.edge
    engine.pqc = object()
    assert engine.detection.pqc is engine.pqc

    watch = engine.alerts.score_watch
    engine.score_watch = watch
    assert engine.alerts.score_watch is watch

    engine.flows = deque(maxlen=3)
    assert engine.detection.flows is engine.flows
    engine.timeline = {"x": 1}
    assert engine.detection.timeline == {"x": 1}


# -- AlertService ------------------------------------------------------------


def test_alert_service_drift_note_emits_once_per_episode():
    engine = SpectraEngine(persist=False)
    events: list[dict] = []
    engine.subscribe(events.append)

    moderate = {"available": True, "level": "moderate", "psi": 1.5, "n": 40}
    engine.alerts.note_drift(moderate)
    engine.alerts.note_drift(moderate)  # same episode: no second alert
    drift_events = [e for e in events if e["type"] == "drift"]
    assert len(drift_events) == 1
    assert engine.alerts.drift_level == "moderate"
    assert engine.alerts.drift_alerted is True

    engine.alerts.note_drift({"available": True, "level": "stable",
                              "psi": 0.1, "n": 40})
    assert engine.alerts.drift_alerted is False
    engine.alerts.note_drift(moderate)  # re-armed: new episode
    assert len([e for e in events if e["type"] == "drift"]) == 2

    engine.alerts.note_drift({"available": False})  # ignored
    assert engine.alerts.drift_level == "moderate"


def test_alert_service_scored_window_and_reset():
    engine = SpectraEngine(persist=False)
    feats = np.zeros(12, dtype=np.float64)
    engine.alerts.on_scored(feats, 50.0)
    assert len(engine.alerts.recent_feats) == 1
    assert list(engine.alerts.score_watch.scores) == [50.0]
    assert engine.alerts.evasion_active is False  # window too small to judge

    engine.alerts.reset_session(contamination=0.05)
    assert engine.alerts.recent_feats == deque()
    assert list(engine.alerts.score_watch.scores) == []
    assert engine.alerts.score_watch.contamination == 0.05


# -- ModelService --------------------------------------------------------------


def test_model_service_unavailable_states(tmp_path):
    engine = SpectraEngine(model_path=str(tmp_path / "m.joblib"), persist=False)
    info = engine.model.info()
    assert info["trained"] is False and "feature_names" in info
    version = engine.model.version()
    assert version.path == str(tmp_path / "m.joblib")
    assert version.trained is False and version.version

    assert engine.model.drift_report() == {"available": False,
                                           "reason": "model not trained"}
    assert engine.model.robustness()["reason"] == "model not trained"
    assert engine.model.shadow()["reason"] == "model not trained"
    assert engine.alerts.evasion_report()["available"] is False


# -- DetectionService -----------------------------------------------------------


def test_detection_pagination_newest_first():
    engine = SpectraEngine(persist=False)
    assert engine.detection.recent_flows(10) == {"count": 0, "items": []}
    engine.detection.flows.append({"ts": 1.0})
    engine.detection.flows.append({"ts": 2.0})
    page = engine.detection.recent_flows(1)
    assert page["count"] == 2
    assert page["items"] == [{"ts": 2.0}]  # newest first, capped
    assert engine.detection.recent_detections(5) == {"count": 0, "items": []}


def test_detection_reset_session_keeps_history():
    engine = SpectraEngine(persist=False)
    engine.detection.flows.append({"ts": 1.0})
    engine.detection.timeline[0] = {"t": 0, "flows": 1, "anomalies": 0,
                                    "score_sum": 1.0}
    engine.detection.counters["protocols"]["TLSv1.3"] += 1
    engine.detection.counters["scores"].append(10.0)
    engine.detection.reset_session()
    assert len(engine.detection.flows) == 1          # history kept
    assert engine.detection.timeline == {}           # per-run buffers cleared
    assert dict(engine.detection.counters["protocols"]) == {}
    assert engine.detection.counters["scores"] == []


# -- CorrelationService / AuditService failure isolation ----------------------


def test_correlation_observe_failures_are_counted(monkeypatch):
    engine = SpectraEngine(persist=False)

    class BrokenGraph:
        def observe(self, record) -> None:
            raise RuntimeError("graph down")

    monkeypatch.setattr(engine.correlation, "graph", BrokenGraph())
    engine.correlation.observe({"ts": 1.0})  # must not raise
    assert engine.status["failures"]["correlation"] == 1


def test_audit_append_failures_are_counted(monkeypatch):
    engine = SpectraEngine(persist=False)

    def broken_append(*args, **kwargs):
        raise RuntimeError("audit down")

    monkeypatch.setattr(engine.audit_service.log, "append", broken_append)
    assert engine.audit_service.append("test.ping", {"ok": True}) is None
    assert engine.status["failures"]["audit"] >= 1


# -- SystemService ---------------------------------------------------------------


def test_system_snapshot_metrics_health():
    engine = SpectraEngine(model_path="definitely-missing-model.joblib",
                           persist=False)
    snap = engine.system.snapshot()
    assert snap["status"] is engine.status
    assert snap["totals"]["flows"] == engine.status["flows"]
    assert snap["model"]["trained"] is False

    text = engine.system.metrics()
    assert "spectra_packets_total 0" in text
    assert "spectra_model_trained 0" in text
    assert "spectra_uptime_seconds" in text
    assert text.endswith("\n")

    health = engine.system.health()
    assert health["ok"] is True and health["service"] == "spectra"
    assert health["database"] in ("enabled", "disabled")


# -- TrainingService + CaptureService integration ---------------------------------


def test_training_service_trains_and_marks_status(tmp_path):
    from spectra.demo import make_baseline_pcap

    baseline = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=30)
    engine = SpectraEngine(model_path=str(tmp_path / "m.joblib"), persist=False)
    events: list[dict] = []
    engine.subscribe(events.append)

    info = engine.training.train_from_pcap(baseline, contamination=0.05)
    assert info["n_train"] >= 10
    assert info["model_path"] == str(tmp_path / "m.joblib")
    assert engine.status["model_trained"] is True
    assert engine.model.is_trained is True
    assert any(e["type"] == "model" for e in events)


def test_capture_service_pcap_roundtrip(tmp_path):
    from spectra.demo import make_baseline_pcap

    baseline = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=30)
    engine = SpectraEngine(model_path=str(tmp_path / "m.joblib"), persist=False)
    engine.training.train_from_pcap(baseline, contamination=0.05)

    engine.capture.start("pcap", path=baseline)
    deadline = time.time() + 30
    while engine.capture.running and time.time() < deadline:
        time.sleep(0.05)
    assert not engine.capture.running
    assert engine.status["flows"] > 0
    # CaptureSession committed evidence for the audit trail
    assert engine.session.leaves
    assert engine.system.snapshot()["totals"]["flows"] == engine.status["flows"]
    # façade parity
    assert engine.running is False
    assert engine.flows is engine.detection.flows
