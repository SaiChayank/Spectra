"""The Spectra engine: composition root + compatibility facade.

The runtime was incrementally split into application services
(``spectra.services``) with clean internal domain models (``spectra.domain``):

    FastAPI routers -> application services -> runtime/domain modules -> persistence

``SpectraEngine`` keeps the historical surface working: the CLI, tests and
older callers use the same attribute/method names, now delegating to the
owning service.  The capture path itself (capture -> flow tracking -> parsing
-> feature extraction -> inference -> persistence/events) runs as bounded
streaming stages built by ``spectra.streaming`` and supervised by
``CaptureService``; scoring and publication are the two detection-service
stages of that runtime.

Wiring below is acyclic - each service only receives objects constructed
before it:

    EventBus / FailureTracker / CaptureSession        (shared leaves)
    AuditService -> AlertService -> ModelService
    CorrelationService + ThreatAlertService (store/events/model identity)
    -> DetectionService -> CaptureService -> CaptureResourceService
    -> TrainingService -> SystemService

Historical rebinding of engine attributes from tests (``engine.detector = ...``)
keeps working: every attribute below is a property whose setter re-points the
owning service (with a fan-out for the two genuinely shared pieces of state,
``store`` and the recent-feature window).
"""

from __future__ import annotations

import logging
import os
from collections import deque
from typing import Callable

from .config import Config, get_config
from .db import RetentionPolicy
from .domain import CaptureSession
from .ml.model import SpectraDetector
from .modules.corr import CorrelationGraph
from .modules.twin import (
    LIBRARY,
    build_topology,
    evaluate_library,
    playbook_from_detections,
    simulate,
    validate_playbook,
)
from .services import (
    AlertService,
    AuditService,
    AuthService,
    CaptureResourceService,
    CaptureService,
    CorrelationService,
    DetectionService,
    EventBus,
    FailureTracker,
    IncidentService,
    ModelService,
    SystemService,
    ThreatAlertService,
    TrainingService,
)
from .store import Store
from .streaming import initial_stream_status

log = logging.getLogger("spectra.engine")

Listener = Callable[[dict], None]


class SpectraEngine:
    def __init__(self, model_path: str | None = None,
                 idle_timeout: float | None = None,
                 config: Config | None = None, store: Store | None = None,
                 persist: bool | None = None):
        self.config = config or get_config()
        self.model_path = model_path or self.config.model_path
        self.idle_timeout = (
            idle_timeout if idle_timeout is not None else self.config.idle_timeout
        )
        should_persist = self.config.persist if persist is None else persist
        if store is not None:
            self._store: Store | None = store
        elif should_persist:
            try:
                self._store = Store(
                    self.config.db_path,
                    max_rows=self.config.max_history_rows,
                    batch_size=self.config.db_batch_size,
                    flush_interval=self.config.db_flush_interval,
                    event_max_rows=self.config.event_max_rows,
                    retention=RetentionPolicy.from_config(self.config),
                )
            except Exception as exc:  # noqa: BLE001 - persistence must not block detection
                log.warning("persistence disabled: %s", exc)
                self._store = None
        else:
            self._store = None

        # Core artifact: loaded once here so every service shares one instance
        # and rebinding ``engine.detector`` stays a single-point operation.
        detector = SpectraDetector()
        if os.path.isfile(self.model_path):
            try:
                detector = SpectraDetector.load(self.model_path)
                log.info("loaded model from %s (%d training flows)",
                         self.model_path, detector.n_train)
            except Exception as exc:  # noqa: BLE001 - a corrupt model must not block startup
                log.warning("could not load model %s: %s", self.model_path, exc)

        # Shared state: one status dict and one recent-feature window, each
        # handed to every service that reads or writes it.
        self.status: dict = {
            "running": False,
            "mode": None,
            "source": None,
            "packets": 0,
            "flows": 0,
            "detections": 0,
            "started_at": None,
            "error": None,
            "model_trained": detector.is_trained,
            "filter": None,
            "persist": self._store is not None,
            # capture-queue telemetry (reset per capture in start())
            "queue": {
                "packets_received": 0,
                "packets_queued": 0,
                "packets_dropped": 0,
                "queue_depth": 0,
                "max_queue_depth": 0,
            },
            # staged streaming telemetry (see spectra.streaming); reset per
            # capture, kept after the session so drops stay inspectable
            "pipeline": initial_stream_status(
                self.config, idle_timeout=self.idle_timeout),
            # cumulative optional-module failure counts (component -> n)
            "failures": {},
        }
        recent_feats: deque = deque(maxlen=1000)
        session = CaptureSession()
        self.session = session   # bound before any listener can fire

        # -- application services (leaf -> root) -----------------------------
        self.events = EventBus()
        self.failures = FailureTracker(self.status)
        # Durable system-event feed: everything except flow/detection events
        # (those are already stored as flow rows) and alert events (those are
        # stored in the alerts table). Low volume by construction -
        # status/evasion/drift/model fire on lifecycle edges, not per packet.
        self.events.subscribe(self._persist_event)
        self.audit_service = AuditService(self._store, self.model_path,
                                          self.failures)
        self.alerts = AlertService(
            self.config, self.events, self.audit_service, self.failures,
            contamination=getattr(detector, "contamination", 0.02),
            recent_feats=recent_feats,
        )
        self.model = ModelService(
            self.config, self.model_path, self.idle_timeout, detector,
            self.alerts, self.events, self.audit_service, self.failures,
            recent_feats,
        )
        self.correlation = CorrelationService(CorrelationGraph(), self._store,
                                              self.failures)
        # Analyst alerts (spectra.services.threat_alerts): correlated verdicts
        # over flagged flows, carrying the scoring model's identity.
        self.threat_alerts = ThreatAlertService(
            self._store, self.config, self.events, self.failures,
            model_info=lambda: {"id": os.path.basename(self.model_path),
                                **self.model.info()},
        )
        self.detection = DetectionService(
            self.status, self.config, self._store, self.model, self.events,
            self.correlation, self.alerts, self.threat_alerts, session,
            self.failures, recent_feats,
        )
        self.capture = CaptureService(
            self.config, self.idle_timeout, self._store, self.events,
            self.failures, self.audit_service, session, self.status,
            self.model, self.detection, self.alerts, self.correlation,
        )
        # Managed capture resources: validated imports into the capture store,
        # id-addressed processing (the API never accepts a filesystem path).
        self.capture_resources = CaptureResourceService(
            self.config, self._store, self.capture, self.events,
        )
        self.training = TrainingService(
            self.config, self.idle_timeout, self._store, self.model,
            self.detection, self.capture, self.audit_service, self.events,
            self.status,
        )
        self.system = SystemService(
            self.status, self.config, self._store, self.model,
            self.detection, self.failures,
        )
        # Local authentication (login/session/user lifecycle) and incident
        # triage. AuthService keeps the construction-time store on purpose -
        # see its docstring: sessions issued by this process must survive the
        # store-rebinding seam that API tests use, so it is NOT part of the
        # fan-out list in the store setter below.
        self.auth = AuthService(self._store, self.config)
        self.incidents = IncidentService(self._store)

    # -- shared state (single owner; setters preserve historical rebinding) ----

    @property
    def store(self) -> Store | None:
        return self._store

    @store.setter
    def store(self, value: Store | None) -> None:
        self._store = value
        # auth is deliberately absent: AuthService stays bound to the store it
        # was constructed with (sessions must not move with test-fixture swaps)
        for name in ("audit_service", "correlation", "threat_alerts",
                     "detection", "capture", "capture_resources", "training",
                     "system", "incidents"):
            svc = getattr(self, name, None)
            if svc is not None:
                svc.store = value

    @property
    def detector(self) -> SpectraDetector:
        return self.model.detector

    @detector.setter
    def detector(self, value: SpectraDetector) -> None:
        self.model.detector = value

    @property
    def _recent_feats(self) -> deque:
        return self.detection.recent_feats

    @_recent_feats.setter
    def _recent_feats(self, value: deque) -> None:
        for name in ("detection", "alerts", "model"):
            svc = getattr(self, name, None)
            if svc is not None:
                svc.recent_feats = value

    @property
    def score_watch(self):
        return self.alerts.score_watch

    @score_watch.setter
    def score_watch(self, value) -> None:
        self.alerts.score_watch = value

    @property
    def _drift_level(self) -> str | None:
        return self.alerts.drift_level

    @_drift_level.setter
    def _drift_level(self, value: str | None) -> None:
        self.alerts.drift_level = value

    @property
    def _drift_alerted(self) -> bool:
        return self.alerts.drift_alerted

    @_drift_alerted.setter
    def _drift_alerted(self, value: bool) -> None:
        self.alerts.drift_alerted = value

    @property
    def flows(self) -> deque:
        return self.detection.flows

    @flows.setter
    def flows(self, value: deque) -> None:
        self.detection.flows = value

    @property
    def detections(self) -> deque:
        return self.detection.detections

    @detections.setter
    def detections(self, value: deque) -> None:
        self.detection.detections = value

    @property
    def timeline(self) -> dict:
        return self.detection.timeline

    @timeline.setter
    def timeline(self, value: dict) -> None:
        self.detection.timeline = value

    @property
    def _counters(self) -> dict:
        return self.detection.counters

    @_counters.setter
    def _counters(self, value: dict) -> None:
        self.detection.counters = value

    @property
    def pqc(self):
        return self.detection.pqc

    @pqc.setter
    def pqc(self, value) -> None:
        self.detection.pqc = value

    @property
    def bio(self):
        return self.detection.bio

    @bio.setter
    def bio(self, value) -> None:
        self.detection.bio = value

    @property
    def edge(self):
        return self.detection.edge

    @edge.setter
    def edge(self, value) -> None:
        self.detection.edge = value

    @property
    def graph(self) -> CorrelationGraph:
        return self.correlation.graph

    @graph.setter
    def graph(self, value: CorrelationGraph) -> None:
        self.correlation.graph = value

    @property
    def audit(self):
        return self.audit_service.log

    @audit.setter
    def audit(self, value) -> None:
        self.audit_service.log = value

    @property
    def tee(self):
        return self.model.tee

    @tee.setter
    def tee(self, value) -> None:
        self.model.tee = value

    # -- events -----------------------------------------------------------------

    def subscribe(self, listener: Listener) -> Callable[[], None]:
        return self.events.subscribe(listener)

    def _emit(self, event: dict) -> None:
        self.events.emit(event)

    def _persist_event(self, event: dict) -> None:
        """Durably record one system event (bus listener, never raises).

        ``flow``/``detection`` events are skipped - they are already stored as
        flow rows - and so are ``alert``/``alert_updated`` events, whose
        durable copy is the alerts table. The store therefore only sees the
        low-volume lifecycle feed (status, evasion, drift, model). The bus
        isolates listener errors, but failures are recorded here too so they
        show up in ``status``.
        """
        store = self._store
        if store is None:
            return
        etype = str(event.get("type", ""))
        if etype in ("flow", "detection", "alert", "alert_updated"):
            return
        try:
            store.record_event(etype, event.get("data") or {},
                               capture_id=self.session.capture_id)
        except Exception as exc:  # noqa: BLE001 - history must never break capture
            self._record_failure("store", exc)

    # -- optional-module resilience ----------------------------------------------

    def _record_failure(self, component: str, exc: BaseException) -> None:
        """Count and structurally log an optional-module failure (never raises)."""
        self.failures.record(component, exc)

    def _guard(self, component: str, fn: Callable, default=None):
        """Run an optional-module callable; failures become ``default``."""
        return self.failures.guard(component, fn, default)

    # -- history hydration ---------------------------------------------------------

    def hydrate_graph(self) -> int:
        """Rebuild the correlation graph from persisted flow history."""
        return self.correlation.hydrate()

    # -- capture control -------------------------------------------------------

    @property
    def running(self) -> bool:
        return self.capture.running

    def start(self, mode: str, path: str | None = None,
              iface: str | None = None, bpf_filter: str = "") -> dict:
        return self.capture.start(mode, path=path, iface=iface,
                                  bpf_filter=bpf_filter)

    def stop(self) -> dict:
        return self.capture.stop()

    # -- Module 5: audit trail ---------------------------------------------------

    def audit_entries(self, limit: int = 50, offset: int = 0,
                      kind: str | None = None) -> dict:
        return self.audit_service.entries(limit=limit, offset=offset, kind=kind)

    def audit_head(self) -> dict:
        return self.audit_service.head()

    def audit_verify(self) -> dict:
        return self.audit_service.verify()

    def audit_checkpoint(self) -> dict:
        return self.audit_service.checkpoint()

    def audit_verify_checkpoint(self, seq: int | None = None) -> dict:
        return self.audit_service.verify_checkpoint(seq=seq)

    def audit_proof(self, seq: int, leaf: int) -> dict:
        return self.audit_service.proof(seq, leaf)

    def certify(self, profile: str = "hipaa", since: float | None = None,
                until: float | None = None, min_flows: int = 1,
                disclose: int = 3, bits: int = 32) -> dict:
        """Issue a signed compliance certificate over persisted evidence."""
        return self.audit_service.certify(
            profile=profile, since=since, until=until, min_flows=min_flows,
            disclose=disclose, bits=bits)

    def verify_certificate(self, bundle: dict) -> dict:
        return self.audit_service.verify_certificate(bundle)

    # -- training ------------------------------------------------------------------

    def train_from_pcap(self, path: str, contamination: float | None = None) -> dict:
        """Train the detector on the benign baseline contained in a PCAP."""
        return self.training.train_from_pcap(path, contamination=contamination)

    # -- Module 3: adversarial resilience ------------------------------------------

    def drift_report(self) -> dict:
        """PSI of recent scored flows against the training baseline."""
        return self.model.drift_report()

    def evasion_watch(self) -> dict:
        """Threshold-hugging analysis of the recent score stream."""
        return self.alerts.evasion_report()

    def robustness(self, pcap: str | None = None, max_features: int = 12,
                   max_rounds: int = 6) -> dict:
        """Run evasion attacks against detected flows (PCAP or recent window)."""
        return self.model.robustness(pcap=pcap, max_features=max_features,
                                     max_rounds=max_rounds)

    # -- Module 7: cross-domain correlation -----------------------------------------

    def graph_snapshot(self, ntype: str | None = None,
                       sector: str | None = None, limit: int = 500) -> dict:
        return self.correlation.snapshot(ntype=ntype, sector=sector,
                                         limit=limit)

    def graph_cascade(self, node_id: str, max_depth: int = 4) -> dict:
        return self.correlation.cascade(node_id, max_depth=max_depth)

    # -- Module 1: PQC readiness -------------------------------------------------

    def pqc_snapshot(self, include_roadmap: bool = True,
                     sector: str | None = None) -> dict:
        """Quantum posture of everything seen by this engine."""
        return self.detection.pqc_snapshot(include_roadmap=include_roadmap,
                                           sector=sector)

    # -- Module 4: digital twin ---------------------------------------------------

    def twin_topology(self, min_flows: int = 1) -> dict:
        """Isolated replica of the observed network (zones, assets, edges)."""
        return build_topology(self.correlation.graph, min_flows=min_flows)

    def twin_simulate(self, **kwargs) -> dict:
        topo = self.twin_topology()
        result = simulate(topo, **kwargs)
        result["topology"] = topo["summary"]
        return result

    def twin_playbooks(self) -> dict:
        return {
            "count": len(LIBRARY),
            "items": [
                {"name": name, "description": pb.get("description"),
                 "actions": pb.get("actions"),
                 "thresholds": pb.get("thresholds")}
                for name, pb in sorted(LIBRARY.items())
            ],
        }

    def twin_validate(self, name: str | None = None,
                      playbook: dict | None = None, **kwargs) -> dict:
        """Rehearse one playbook (library name or explicit actions)."""
        topo = self.twin_topology()
        if playbook is None:
            if name is None:
                raise ValueError("provide a playbook name or a playbook dict")
            if name == "auto":
                playbook = self.twin_recommend(validate=False)["playbook"]
            elif name in LIBRARY:
                playbook = LIBRARY[name]
            else:
                raise ValueError(
                    f"unknown playbook {name!r}; library: {sorted(LIBRARY)} or 'auto'"
                )
        return validate_playbook(topo, playbook, **kwargs)

    def twin_evaluate(self, **kwargs) -> dict:
        """Rehearse every library playbook against one scenario and rank them."""
        return evaluate_library(self.twin_topology(), **kwargs)

    def twin_recommend(self, validate: bool = True, **kwargs) -> dict:
        """Playbook generated from the current detections + its rehearsal."""
        playbook = playbook_from_detections(list(self.detections))
        out: dict = {"playbook": playbook, "detections": len(self.detections)}
        if validate:
            try:
                out["rehearsal"] = validate_playbook(
                    self.twin_topology(), playbook, **kwargs)
            except Exception as exc:  # noqa: BLE001 - empty graph etc.
                out["rehearsal"] = {"error": str(exc)}
        return out

    def shadow(self, pcap: str | None = None, contamination: float = 0.05,
               threshold: float = 3.5, retrain: bool = True) -> dict:
        """Module 4 shadow mode: quantify lift over a legacy z-score rule."""
        return self.model.shadow(pcap=pcap, contamination=contamination,
                                 threshold=threshold, retrain=retrain)

    # -- Module 6: bio-inspired detection -------------------------------------------

    def bio_report(self) -> dict:
        """Immune / SNN / swarm state plus live context."""
        return self.detection.bio_report()

    def bio_assess(self, features=None, score: float | None = None,
                   anomaly: bool = False) -> dict:
        """Assess an explicit feature vector (or the latest live flow)."""
        return self.detection.bio_assess(features, score=score,
                                         anomaly=anomaly)

    # -- Module 8: 5G/6G edge ---------------------------------------------------------

    def edge_report(self) -> dict:
        """Slices, micro-detector state, link profiles, deployments."""
        return self.detection.edge_report()

    def edge_set_link(self, name: str) -> dict:
        """Switch the non-terrestrial backhaul profile (NTN support)."""
        return self.detection.edge_set_link(name)

    def edge_deploy(self, node: str, slice_id: str = "default") -> dict:
        """Register a micro-detector deployment on a MEC node."""
        return self.detection.edge_deploy(node, slice_id)

    def edge_save(self) -> str | None:
        """Persist edge state (link profile, deployments) for future runs."""
        return self.detection.edge_save()

    # -- Module 2: confidential computing --------------------------------------------

    def tee_attest(self, nonce: str | None = None) -> dict:
        return self.model.tee_attest(nonce)

    def tee_verify(self, quote: dict, measurement: str | None = None,
                   max_age: float = 600.0, nonce: str | None = None) -> dict:
        return self.model.tee_verify(quote, measurement=measurement,
                                     max_age=max_age, nonce=nonce)

    def tee_infer(self, features) -> dict:
        """Sealed inference: features in, score + signed receipt out."""
        return self.model.tee_infer(features)

    def tee_federate(self, deltas=None, shareholders: int = 3,
                     seed: int = 7) -> dict:
        """Secure aggregation: explicit deltas or the live window's means."""
        return self.model.tee_federate(deltas=deltas,
                                       shareholders=shareholders, seed=seed)

    # -- reporting --------------------------------------------------------------------

    def snapshot(self) -> dict:
        return self.system.snapshot()
