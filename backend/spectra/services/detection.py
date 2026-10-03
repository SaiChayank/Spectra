"""Detection service: the performance-sensitive hot path + analysis reports.

The pipeline *capture -> flow tracking -> parsing -> feature extraction ->
inference* runs in two streaming stages: :meth:`score_flow` (inference
worker) computes the verdict and all module enrichment, :meth:`publish_flow`
(publication worker) records, publishes and persists it.  Attribute access
stays direct, and every optional module is guarded at the boundary so a
failing add-on degrades its own output instead of stopping inference.  This
service also owns the flow-analysis runtime modules (PQC inventory, bio
system, edge runtime) and their read/report facades.
"""

from __future__ import annotations

import logging
import os
from collections import Counter, deque

import numpy as np

from ..config import Config
from ..domain import CaptureSession, FlowRecord  # noqa: F401  (FlowRecord documents output)
from ..features.extractor import extract_features
from ..modules.audit.log import MAX_LEAVES as AUDIT_MAX_LEAVES
from ..modules.bio import RESPONSES, BioSystem
from ..modules.edge import SLICES, EdgeSystem, apply_slice_policy, classify_slice
from ..modules.pqc import PQCInventory, assess_handshake, screen_flows
from ..modules.pqc.roadmap import generate_roadmap
from ..parse.flow import Flow
from ..store import Store
from ..threats import THREAT_WINDOW, classify_threat, unknown_threat
from .alerts import AlertService
from .correlation import CorrelationService
from .events import EventBus
from .model import ModelService
from .resilience import FailureTracker
from .threat_alerts import ThreatAlertService

log = logging.getLogger("spectra.engine")


class DetectionService:
    def __init__(self, status: dict, config: Config, store: Store | None,
                 model: ModelService, events: EventBus,
                 correlation: CorrelationService, alerts: AlertService,
                 threat_alerts: ThreatAlertService, session: CaptureSession,
                 failures: FailureTracker, recent_feats: deque) -> None:
        self.status = status
        self.config = config
        self.store = store
        self._model = model
        self._events = events
        self._correlation = correlation
        self._alerts = alerts
        self.threat_alerts = threat_alerts
        self.session = session
        self.failures = failures
        self.recent_feats = recent_feats

        # Module 1: quantum posture inventory
        self.pqc = PQCInventory()

        # Module 6: bio-inspired layer (immune + SNN + swarm)
        self.bio = BioSystem(contamination=model.contamination)
        self._bio_path = os.path.splitext(model.model_path)[0] + ".bio.joblib"
        try:
            if self.bio.load(self._bio_path):
                log.info("loaded bio state from %s", self._bio_path)
        except Exception as exc:  # noqa: BLE001 - bio must never block startup
            log.warning("bio state not loaded: %s", exc)

        # Module 8: edge runtime (micro-detector, slices, NTN links)
        self.edge = EdgeSystem()
        self._edge_path = os.path.splitext(model.model_path)[0] + ".edge.joblib"
        try:
            self.edge.load(self._edge_path)
        except Exception as exc:  # noqa: BLE001
            log.warning("edge state not loaded: %s", exc)

        # in-memory buffers (read by SystemService.snapshot / twin / history)
        self.flows: deque[dict] = deque(maxlen=config.flow_buffer)
        self.detections: deque[dict] = deque(maxlen=config.detection_buffer)
        self.timeline: dict[int, dict] = {}
        self.counters = self._new_counters()

    @staticmethod
    def _new_counters() -> dict:
        return {
            "protocols": Counter(),
            "tls_versions": Counter(),
            "quic_versions": Counter(),
            "scores": [],
            "slices": Counter(),
        }

    def reset_session(self) -> None:
        """Fresh per-capture buffers; the flow/detection history is kept."""
        self.timeline = {}
        self.counters = self._new_counters()
        self.pqc.reset()

    # -- sidecar paths (used by the training service) ---------------------------

    @property
    def bio_path(self) -> str:
        return self._bio_path

    @property
    def edge_path(self) -> str:
        return self._edge_path

    # -- hot path -------------------------------------------------------------
    #
    # The path runs in two stages of the streaming runtime (see
    # spectra.streaming): ``score_flow`` executes on the inference worker and
    # only computes; ``publish_flow`` runs on the publication worker and owns
    # every side effect (buffers, events, evidence leaves, persistence).  A
    # slow database therefore cannot slow inference down, and both stages stay
    # single-threaded exactly as the old inline loop was.

    def score_flow(self, flow: Flow) -> dict | None:
        """Inference stage: score and enrich one completed flow.

        Returns the payload consumed by :meth:`publish_flow`; no buffer,
        event, evidence or persistence side effect happens here.
        """
        record = flow.record()
        feats = extract_features(flow)
        score: float | None = None
        anomaly = False
        reasons: list[dict] = []

        # Module 1: quantum-risk verdict on this conversation's handshake.
        pqc_assessment = self.failures.guard(
            "pqc",
            lambda: assess_handshake(flow.client_tls, flow.server_tls),
            default=None,
        )
        if pqc_assessment is not None:
            record["pqc"] = pqc_assessment
            if pqc_assessment["applicable"]:
                self.failures.guard(
                    "pqc", lambda: self.pqc.observe(record, pqc_assessment))

        detector = self._model.detector
        if detector.is_trained:
            # one inference pass for score + verdict (see score_and_predict)
            scores, flags = detector.score_and_predict(feats)
            score = float(scores[0])
            anomaly = bool(flags[0])
            if anomaly:
                reasons = detector.explain(feats)

        self.status["flows"] += 1
        self.counters["protocols"][record["proto"]] += 1
        if record["tls_version"]:
            self.counters["tls_versions"][record["tls_version"]] += 1
        if record.get("quic_version"):
            self.counters["quic_versions"][record["quic_version"]] += 1
        if score is not None:
            self.counters["scores"].append(score)
            if len(self.counters["scores"]) > 5000:
                del self.counters["scores"][:2500]
            # Module 3: scored window + score-watch (optional telemetry)
            self._alerts.on_scored(feats, score)

        # Module 8: network-slice tagging (pure policy, never raises)
        try:
            slice_id = classify_slice(record)
        except Exception as exc:  # noqa: BLE001
            self.failures.record("edge_slice", exc)
            slice_id = "default"
        record["slice"] = slice_id
        self.counters["slices"][slice_id] += 1

        # Module 6: immune + SNN + swarm assessment, differentiated by slice
        if self.bio.available and score is not None:
            try:
                if (self.status["flows"] % 200 == 0
                        and len(self.recent_feats) >= 40):
                    self._model.refresh_drift_level()
                out = self.bio.assess(
                    feats, score=score, anomaly=anomaly,
                    drift_level=self._alerts.drift_level,
                    evasion=self._alerts.evasion_active,
                    timing_scale=self.edge.timing_scale(),
                )
                imm = out["immune"]
                new_level, note = apply_slice_policy(imm["level"], slice_id)
                imm["level"] = new_level
                imm["response"] = RESPONSES[new_level]
                imm["slice_policy"] = note
                if new_level >= 2:
                    self.bio.remember(feats, new_level)
                record["immune"] = {
                    "level": new_level,
                    "response": RESPONSES[new_level],
                    "affinity": imm["affinity"],
                    "danger_total": imm["danger_total"],
                    "memory_hit": imm["memory_hit"],
                    "slice_policy": note,
                }
                if out["snn"]["score"] is not None:
                    record["snn_score"] = out["snn"]["score"]
                if out["swarm"].get("available"):
                    record["swarm_flag"] = bool(out["swarm"]["flag"])
            except Exception as exc:  # noqa: BLE001 - bio must never kill capture
                self.failures.record("bio", exc)

        bucket_s = self.config.bucket_seconds
        bucket = int(record["last_ts"] // bucket_s) * bucket_s
        entry = self.timeline.setdefault(
            bucket, {"t": bucket, "flows": 0, "anomalies": 0, "score_sum": 0.0}
        )
        entry["flows"] += 1
        if score is not None:
            entry["score_sum"] += score
        if anomaly:
            entry["anomalies"] += 1

        record["score"] = score
        record["anomaly"] = anomaly
        # ``feats`` rides along so the publication stage can classify the
        # threat (see spectra.threats) without re-extracting the flow.
        return {"record": record, "score": score, "anomaly": anomaly,
                "reasons": reasons, "feats": feats}

    def publish_flow(self, scored: dict) -> None:
        """Publication stage: record, publish and persist one scored flow."""
        record = scored["record"]
        score = scored["score"]
        anomaly = scored["anomaly"]
        reasons = scored["reasons"]

        # Threat classification (spectra.threats): anomalies only, with the
        # context window of *prior* flows — captured before this record joins
        # the buffer — and the verdict lands on the record before it is
        # observed, emitted and persisted.  A classifier failure degrades to
        # an explicit UNKNOWN_ANOMALY instead of stopping publication.
        window = list(self.flows)[-THREAT_WINDOW:] if anomaly else None

        # Module 5: this flow becomes a Merkle leaf of the session's evidence
        self.session.add_leaf(record, AUDIT_MAX_LEAVES)
        self.flows.append(record)

        if anomaly:
            threat = self.failures.guard(
                "threats",
                lambda: classify_threat(record, scored.get("feats"), window),
                default=None,
            )
            record["threat"] = threat if threat is not None else unknown_threat()

            # Analyst alert (spectra.services.threat_alerts): the
            # classification may raise a grouped, persisted, streamed alert —
            # strictly on top of the raw detection, never instead of it.  The
            # alert id is stamped onto the record *before* persistence, so the
            # stored flow row names the alert it produced.  A failure here
            # degrades to "no alert" instead of stopping publication.
            alert = None
            if self.threat_alerts is not None:
                alert = self.failures.guard(
                    "threat_alerts",
                    lambda: self.threat_alerts.observe(
                        record, record["threat"], score=score,
                        capture_id=self.session.capture_id),
                    default=None,
                )
            if alert is not None:
                record["alert_id"] = alert["alert_id"]

        self._correlation.observe(record)
        self._events.emit(
            {"type": "flow", "data": {**record, "score": score,
                                      "anomaly": anomaly}})

        if self.store is not None:
            try:
                self.store.save_flow(
                    record, score, anomaly,
                    reasons=reasons or None,
                    capture_id=self.session.capture_id,
                )
            except Exception as exc:  # noqa: BLE001 - persistence must never kill capture
                self.failures.record("store", exc)

        if anomaly:
            self.status["detections"] += 1
            detection = {
                **record,
                "score": score,
                "reasons": reasons,
                "detected_at": record["last_ts"],
            }
            self.detections.append(detection)
            self._events.emit({"type": "detection", "data": detection})

    def handle_flow(self, flow: Flow) -> None:
        """Score *and* publish one flow in a single call.

        Kept for synchronous callers (offline tooling, tests); the capture
        runtime runs the same two steps as separate streaming stages.
        """
        scored = self.score_flow(flow)
        if scored is not None:
            self.publish_flow(scored)

    # -- read buffers ----------------------------------------------------------

    def recent_flows(self, limit: int = 100) -> dict:
        """Newest-first page of the in-memory flow buffer."""
        items = list(self.flows)[-min(limit, 1000):][::-1]
        return {"count": len(self.flows), "items": items}

    def recent_detections(self, limit: int = 100) -> dict:
        """Newest-first page of the in-memory detection buffer."""
        items = list(self.detections)[-min(limit, 1000):][::-1]
        return {"count": len(self.detections), "items": items}

    # -- Module 1: PQC readiness ------------------------------------------------

    def pqc_snapshot(self, include_roadmap: bool = True,
                     sector: str | None = None) -> dict:
        """Quantum posture of everything seen by this engine."""
        pairs = [
            (r, r["pqc"]) for r in self.flows
            if r.get("pqc") and r["pqc"]["applicable"]
        ]
        findings = screen_flows(pairs)
        summary = self.pqc.summary()
        endpoints = self.pqc.endpoints(limit=200, sector=sector)
        out = {
            "summary": summary,
            "endpoints": endpoints,
            "hndl": findings,
            "model": self._model.info(),
        }
        if include_roadmap:
            out["roadmap"] = generate_roadmap(summary, endpoints, findings, sector)
        return out

    # -- Module 6: bio-inspired detection ---------------------------------------

    def bio_report(self) -> dict:
        """Immune / SNN / swarm state plus live context."""
        out = self.bio.status()
        out["drift_level"] = self._alerts.drift_level
        out["evasion_active"] = self._alerts.evasion_active
        out["timing_scale"] = round(self.edge.timing_scale(), 3)
        return out

    def bio_assess(self, features=None, score: float | None = None,
                   anomaly: bool = False) -> dict:
        """Assess an explicit feature vector (or the latest live flow)."""
        if features is None:
            if not self.recent_feats:
                raise ValueError("no scored flows in the live window - "
                                 "pass an explicit feature vector")
            x = self.recent_feats[-1]
            if score is None and self.counters["scores"]:
                score = float(self.counters["scores"][-1])
        else:
            x = np.asarray(features, dtype=np.float64)
        return self.bio.assess(x, score=score, anomaly=bool(anomaly),
                               drift_level=self._alerts.drift_level,
                               evasion=bool(self._alerts.evasion_active),
                               timing_scale=self.edge.timing_scale())

    # -- Module 8: 5G/6G edge ----------------------------------------------------

    def edge_report(self) -> dict:
        """Slices, micro-detector state, link profiles, deployments."""
        out = self.edge.report()
        out["slices"] = {k: dict(v) for k, v in SLICES.items()}
        out["slice_counts"] = dict(self.counters["slices"])
        return out

    def edge_set_link(self, name: str) -> dict:
        """Switch the non-terrestrial backhaul profile (NTN support)."""
        self.edge.set_link(name)
        return self.edge_report()

    def edge_deploy(self, node: str, slice_id: str = "default") -> dict:
        """Register a micro-detector deployment on a MEC node."""
        return self.edge.deploy(node, slice_id)

    def edge_save(self) -> str | None:
        """Persist edge state (link profile, deployments) for future runs."""
        if self._edge_path:
            self.edge.save(self._edge_path)
        return self._edge_path
