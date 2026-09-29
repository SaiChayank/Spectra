"""The Spectra engine: capture source -> flow tracker -> detector -> events.

Runs the capture loop on a worker thread and publishes events (flows,
detections) to any subscriber, which the API layer forwards over WebSocket.
Completed flows are optionally persisted to SQLite for history/trends.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from collections import Counter, deque
from typing import Callable

import numpy as np

from .capture import CaptureError, CaptureSource, open_source
from .config import Config, get_config
from .features.extractor import extract_features, flows_to_matrix
from .ml.model import SpectraDetector
from .modules.adv import ScoreWindow, attack_batch
from .modules.audit import AuditLog, build_certificate, verify_certificate
from .modules.audit.log import MAX_LEAVES as AUDIT_MAX_LEAVES
from .modules.bio import RESPONSES, BioSystem
from .modules.corr import CorrelationGraph, cascade
from .modules.edge import EdgeSystem, SLICES, apply_slice_policy, classify_slice
from .modules.pqc import PQCInventory, assess_handshake, screen_flows
from .modules.pqc.roadmap import generate_roadmap
from .modules.tee import TeeEnclave, TeeError, federated_round
from .modules.twin import (
    LIBRARY,
    build_topology,
    evaluate_library,
    playbook_from_detections,
    run_shadow,
    simulate,
    validate_playbook,
)
from .parse.flow import Flow, FlowTracker
from .store import Store
from .tools import collect_flows

log = logging.getLogger("spectra.engine")

Listener = Callable[[dict], None]


class SpectraEngine:
    def __init__(self, model_path: str | None = None, idle_timeout: float | None = None,
                 config: Config | None = None, store: Store | None = None,
                 persist: bool | None = None):
        self.config = config or get_config()
        self.model_path = model_path or self.config.model_path
        self.idle_timeout = (
            idle_timeout if idle_timeout is not None else self.config.idle_timeout
        )
        should_persist = self.config.persist if persist is None else persist
        if store is not None:
            self.store: Store | None = store
        elif should_persist:
            try:
                self.store = Store(self.config.db_path, max_rows=self.config.max_history_rows)
            except Exception as exc:  # noqa: BLE001 - persistence must not block detection
                log.warning("persistence disabled: %s", exc)
                self.store = None
        else:
            self.store = None

        self.detector = SpectraDetector()
        if os.path.isfile(self.model_path):
            try:
                self.detector = SpectraDetector.load(self.model_path)
                log.info("loaded model from %s (%d training flows)",
                         self.model_path, self.detector.n_train)
            except Exception as exc:  # noqa: BLE001 - a corrupt model must not block startup
                log.warning("could not load model %s: %s", self.model_path, exc)

        self.flows: deque[dict] = deque(maxlen=self.config.flow_buffer)
        self.detections: deque[dict] = deque(maxlen=self.config.detection_buffer)
        self.timeline: dict[int, dict] = {}
        self.pqc = PQCInventory()
        self.graph = CorrelationGraph()

        # Module 5: hash-chained audit log (memory-backed when persistence is off)
        try:
            self.audit = AuditLog(self.store)
        except Exception as exc:  # noqa: BLE001 - audit must never block startup
            log.warning("audit log disabled: %s", exc)
            self.audit = AuditLog(store=None)
        self._session_leaves: list[dict] = []

        # Module 3: adversarial resilience state
        self.score_watch = ScoreWindow(
            contamination=getattr(self.detector, "contamination", 0.02))
        self._recent_feats: deque[np.ndarray] = deque(maxlen=1000)
        self._drift_alerted = False
        self._drift_level: str | None = None

        # Module 6: bio-inspired layer (immune + SNN + swarm)
        self.bio = BioSystem(
            contamination=getattr(self.detector, "contamination", 0.02))
        self._bio_path = os.path.splitext(self.model_path)[0] + ".bio.joblib"
        try:
            if self.bio.load(self._bio_path):
                log.info("loaded bio state from %s", self._bio_path)
        except Exception as exc:  # noqa: BLE001 - bio must never block startup
            log.warning("bio state not loaded: %s", exc)

        # Module 8: edge runtime (micro-detector, slices, NTN links)
        self.edge = EdgeSystem()
        self._edge_path = os.path.splitext(self.model_path)[0] + ".edge.joblib"
        try:
            self.edge.load(self._edge_path)
        except Exception as exc:  # noqa: BLE001
            log.warning("edge state not loaded: %s", exc)

        # Module 2: TEE attestation over the model artifact
        try:
            self.tee = TeeEnclave(self.model_path)
        except Exception as exc:  # noqa: BLE001 - attestation must not block
            log.warning("tee disabled: %s", exc)
            self.tee = None  # type: ignore[assignment]

        self._listeners: list[Listener] = []
        self._listeners_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._source: CaptureSource | None = None
        self._capture_id: int | None = None

        self.status: dict = {
            "running": False,
            "mode": None,
            "source": None,
            "packets": 0,
            "flows": 0,
            "detections": 0,
            "started_at": None,
            "error": None,
            "model_trained": self.detector.is_trained,
            "filter": None,
            "persist": self.store is not None,
        }
        self._counters = {
            "protocols": Counter(),
            "tls_versions": Counter(),
            "scores": [],
            "slices": Counter(),
        }

    # -- events -------------------------------------------------------------

    def subscribe(self, listener: Listener) -> Callable[[], None]:
        with self._listeners_lock:
            self._listeners.append(listener)

        def unsubscribe() -> None:
            with self._listeners_lock:
                if listener in self._listeners:
                    self._listeners.remove(listener)

        return unsubscribe

    def _emit(self, event: dict) -> None:
        with self._listeners_lock:
            listeners = list(self._listeners)
        for listener in listeners:
            try:
                listener(event)
            except Exception:  # noqa: BLE001 - a bad subscriber must not stop capture
                pass

    # -- history hydration ---------------------------------------------------

    def hydrate_graph(self) -> int:
        """Rebuild the correlation graph from persisted flow history.

        Runs at API startup and again at the start of every capture so the
        cross-domain view keeps prior evidence instead of resetting empty.
        Returns the number of records replayed (0 when persistence is off).
        """
        if self.store is None:
            return 0
        try:
            return self.graph.hydrate(self.store)
        except Exception as exc:  # noqa: BLE001 - hydration must never block capture
            log.warning("graph hydration failed: %s", exc)
            return 0

    # -- Module 5: audit trail ------------------------------------------------

    def _audit_append(self, kind: str, payload: dict, leaves=None) -> dict | None:
        """Append to the audit log; never raises into the capture path."""
        try:
            return self.audit.append(kind, payload, leaves=leaves)
        except Exception:  # noqa: BLE001 - auditing must never kill capture
            log.exception("audit append failed (%s)", kind)
            return None

    def audit_entries(self, limit: int = 50, offset: int = 0,
                      kind: str | None = None) -> dict:
        return {
            "count": self.audit.count(),
            "signing_key": self.audit.pubkey,
            "items": self.audit.entries(limit=limit, offset=offset, kind=kind),
        }

    def audit_head(self) -> dict:
        return self.audit.head()

    def audit_verify(self) -> dict:
        return self.audit.verify()

    def audit_checkpoint(self) -> dict:
        return self.audit.checkpoint()

    def audit_verify_checkpoint(self, seq: int | None = None) -> dict:
        return self.audit.verify_checkpoint(seq=seq)

    def audit_proof(self, seq: int, leaf: int) -> dict:
        proof = self.audit.inclusion_proof(int(seq), int(leaf))
        if proof is None:
            raise ValueError(
                f"no Merkle leaf {leaf} on entry {seq} (entry missing or has no leaves)"
            )
        return proof

    def certify(self, profile: str = "hipaa", since: float | None = None,
                until: float | None = None, min_flows: int = 1,
                disclose: int = 3, bits: int = 32) -> dict:
        """Issue a signed compliance certificate over persisted evidence."""
        if self.store is None:
            raise ValueError("persistence is required to issue certificates")
        return build_certificate(
            self.store, self.audit, profile=profile, since=since, until=until,
            min_flows=min_flows, disclose=disclose, bits=bits,
            model_path=self.model_path,
        )

    def verify_certificate(self, bundle: dict) -> dict:
        return verify_certificate(bundle, log=self.audit,
                                  model_path=self.model_path)

    # -- capture control ----------------------------------------------------

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, mode: str, path: str | None = None, iface: str | None = None,
              bpf_filter: str = "") -> dict:
        if self.running:
            raise CaptureError("a capture is already running - stop it first")
        source = open_source(mode, path=path, iface=iface, bpf_filter=bpf_filter)
        self._source = source
        self._stop.clear()
        self.pqc.reset()
        self.graph.reset()
        self.hydrate_graph()          # keep history-backed nodes across sessions
        self._session_leaves = []
        self._recent_feats.clear()
        self._drift_alerted = False
        self.score_watch = ScoreWindow(
            contamination=getattr(self.detector, "contamination", 0.02))
        if self.store is not None:
            try:
                self._capture_id = self.store.start_capture(mode, path or iface or "live")
            except Exception as exc:  # noqa: BLE001
                log.warning("capture session not recorded: %s", exc)
                self._capture_id = None
        self.status.update({
            "running": True,
            "mode": mode,
            "source": path or iface or "default",
            "packets": 0,
            "flows": 0,
            "detections": 0,
            "started_at": time.time(),
            "error": None,
            "model_trained": self.detector.is_trained,
            "filter": bpf_filter or None,
            "persist": self.store is not None,
        })
        self._counters = {"protocols": Counter(), "tls_versions": Counter(),
                          "scores": [], "slices": Counter()}
        self.timeline = {}
        self._audit_append("capture.start", {
            "mode": mode,
            "source": path or iface or "live",
            "filter": bpf_filter or None,
            "model_trained": self.detector.is_trained,
        })
        self._thread = threading.Thread(
            target=self._run, args=(source,), name="spectra-engine", daemon=True
        )
        self._thread.start()
        self._emit({"type": "status", "data": self.status})
        return self.status

    def stop(self) -> dict:
        self._stop.set()
        if self._source is not None:
            self._source.close()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=10)
        return self.status

    # -- capture loop -------------------------------------------------------

    def _run(self, source: CaptureSource) -> None:
        bucket = self.config.bucket_seconds
        tracker = FlowTracker(idle_timeout=self.idle_timeout, on_complete=self._on_flow)
        last_flush: float | None = None
        try:
            for pkt in source.packets():
                if self._stop.is_set():
                    break
                ts = float(pkt.time)
                tracker.process(pkt, ts)
                if last_flush is None:
                    last_flush = ts
                elif ts - last_flush >= bucket:
                    for expired in tracker.flush_expired(ts):
                        pass  # already emitted via on_complete
                    last_flush = ts
                self.status["packets"] += 1
        except CaptureError as exc:
            self.status["error"] = str(exc)
            log.error("capture error: %s", exc)
        except Exception as exc:  # noqa: BLE001 - keep the failure visible in status
            self.status["error"] = f"capture failed: {exc}"
            log.exception("capture failed")
        finally:
            try:
                list(tracker.flush_all())  # consume: emits trailing open flows
            except Exception:  # noqa: BLE001
                log.exception("flushing remaining flows failed")
            self.status["running"] = False
            if self.store is not None and self._capture_id is not None:
                try:
                    self.store.finish_capture(
                        self._capture_id,
                        packets=self.status["packets"],
                        flows=self.status["flows"],
                        detections=self.status["detections"],
                        error=self.status["error"],
                    )
                except Exception:  # noqa: BLE001
                    log.exception("recording capture finish failed")
            # Module 5: commit this session's flow records (Merkle leaves)
            scores = self._counters["scores"]
            self._audit_append("capture.stop", {
                "mode": self.status["mode"],
                "source": self.status["source"],
                "packets": self.status["packets"],
                "flows": self.status["flows"],
                "detections": self.status["detections"],
                "avg_score": round(float(np.mean(scores)), 2) if scores else None,
                "error": self.status["error"],
                "evidence_records": len(self._session_leaves),
                "evidence_included": min(len(self._session_leaves), AUDIT_MAX_LEAVES),
            }, leaves=self._session_leaves)
            self._capture_id = None
            self._emit({"type": "status", "data": self.status})
            self._source = None
            self._thread = None

    # -- flow handling ------------------------------------------------------

    def _on_flow(self, flow: Flow) -> None:
        record = flow.record()
        feats = extract_features(flow)
        score: float | None = None
        anomaly = False
        reasons: list[dict] = []

        # Module 1: quantum-risk verdict on this conversation's handshake.
        pqc_assessment = assess_handshake(flow.client_tls, flow.server_tls)
        record["pqc"] = pqc_assessment
        if pqc_assessment["applicable"]:
            self.pqc.observe(record, pqc_assessment)

        if self.detector.is_trained:
            score = float(self.detector.score(feats)[0])
            anomaly = bool(self.detector.predict(feats)[0])
            if anomaly:
                reasons = self.detector.explain(feats)

        self.status["flows"] += 1
        self._counters["protocols"][record["proto"]] += 1
        if record["tls_version"]:
            self._counters["tls_versions"][record["tls_version"]] += 1
        if score is not None:
            self._counters["scores"].append(score)
            if len(self._counters["scores"]) > 5000:
                del self._counters["scores"][:2500]
            self._recent_feats.append(feats)
            alert = self.score_watch.add(score)
            if alert is not None:
                log.warning("possible detector evasion: %s", alert)
                self._emit({"type": "evasion", "data": alert})
                self._audit_append("alert", {"alert_type": "evasion", **alert})

        # Module 8: network-slice tagging (pure policy, never raises)
        try:
            slice_id = classify_slice(record)
        except Exception:  # noqa: BLE001
            slice_id = "default"
        record["slice"] = slice_id
        self._counters["slices"][slice_id] += 1

        # Module 6: immune + SNN + swarm assessment, differentiated by slice
        if self.bio.available and score is not None:
            try:
                if (self.status["flows"] % 200 == 0
                        and len(self._recent_feats) >= 40):
                    self._refresh_drift_level()
                out = self.bio.assess(
                    feats, score=score, anomaly=anomaly,
                    drift_level=self._drift_level,
                    evasion=self.score_watch.alerted,
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
            except Exception:  # noqa: BLE001 - bio must never kill capture
                log.exception("bio assessment failed")

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
        # Module 5: this flow becomes a Merkle leaf of the session's evidence
        if len(self._session_leaves) < AUDIT_MAX_LEAVES:
            self._session_leaves.append(record)
        self.flows.append(record)
        try:
            self.graph.observe(record)
        except Exception:  # noqa: BLE001 - correlation must never kill capture
            log.exception("graph update failed")
        self._emit({"type": "flow", "data": {**record, "score": score, "anomaly": anomaly}})

        if self.store is not None:
            try:
                self.store.save_flow(
                    record, score, anomaly,
                    reasons=reasons or None,
                    capture_id=self._capture_id,
                )
            except Exception:  # noqa: BLE001 - persistence must never kill capture
                log.exception("persisting flow failed")

        if anomaly:
            self.status["detections"] += 1
            detection = {
                **record,
                "score": score,
                "reasons": reasons,
                "detected_at": record["last_ts"],
            }
            self.detections.append(detection)
            self._emit({"type": "detection", "data": detection})

    # -- training -----------------------------------------------------------

    def train_from_pcap(self, path: str, contamination: float | None = None) -> dict:
        """Train the detector on the benign baseline contained in a PCAP."""
        if self.running:
            raise CaptureError("stop the active capture before training")
        if contamination is None:
            contamination = self.config.contamination
        flows = collect_flows(path, idle_timeout=self.idle_timeout,
                              bucket=self.config.bucket_seconds)
        if len(flows) < 10:
            raise ValueError(
                f"{path} yielded only {len(flows)} complete flows; need >= 10"
            )
        X = flows_to_matrix(flows)
        self.detector.contamination = contamination
        info = self.detector.fit(X)
        self.detector.save(self.model_path)
        # Modules 6 + 8: fit the bio layer and the edge micro-detector on the
        # same benign baseline, persisting both sidecars next to the model
        try:
            info["bio"] = self.bio.fit(X)
            self.bio.save(self._bio_path)
        except Exception as exc:  # noqa: BLE001 - bio is an add-on layer
            log.warning("bio fit failed: %s", exc)
            info["bio"] = {"error": str(exc)}
        try:
            info["edge"] = self.edge.fit(X)
            self.edge.save(self._edge_path)
        except Exception as exc:  # noqa: BLE001
            log.warning("edge fit failed: %s", exc)
            info["edge"] = {"error": str(exc)}
        if self.tee is not None:
            try:
                # Module 2: attest the freshly retrained artifact
                self.tee.remeasure()
            except Exception:  # noqa: BLE001
                pass
        self.status["model_trained"] = True
        info.update({"model_path": self.model_path, "pcap": path})
        if self.store is not None:
            try:
                self.store.add_model_run(path, info["n_train"], contamination, info)
            except Exception:  # noqa: BLE001
                log.exception("recording model run failed")
        digest = None
        try:
            if os.path.isfile(self.model_path):
                h = hashlib.sha256()
                with open(self.model_path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
                digest = h.hexdigest()
        except OSError:  # pragma: no cover - digest is best effort
            digest = None
        self._audit_append("model.train", {
            "pcap": path,
            "n_train": info["n_train"],
            "contamination": contamination,
            "model_path": self.model_path,
            "model_sha256": digest,
            "n_features": info.get("n_features"),
        })
        self._emit({"type": "model", "data": self.detector.info()})
        return info

    # -- Module 3: adversarial resilience ------------------------------------

    def drift_report(self) -> dict:
        """PSI of recent scored flows against the training baseline."""
        if not self.detector.is_trained:
            return {"available": False, "reason": "model not trained"}
        if not self._recent_feats:
            return {"available": False, "reason": "no scored flows yet"}
        X = np.vstack([np.asarray(f, dtype=np.float64) for f in self._recent_feats])
        report = self.detector.psi(X)
        report["window"] = len(self._recent_feats)
        if report.get("available"):
            # Module 6: the immune layer reads the drift level as a danger axis
            self._drift_level = report.get("level")
            drifted = report.get("level") in ("moderate", "significant")
            if drifted and not self._drift_alerted:
                self._drift_alerted = True
                self._emit({"type": "drift", "data": report})
                self._audit_append("alert", {
                    "alert_type": "drift",
                    "psi": report.get("psi"),
                    "level": report.get("level"),
                    "n": report.get("n"),
                })
            elif not drifted:
                self._drift_alerted = False
        return report

    def evasion_watch(self) -> dict:
        """Threshold-hugging analysis of the recent score stream."""
        return self.score_watch.report()

    def _refresh_drift_level(self) -> None:
        """Recompute the cached drift level feeding the immune danger axis."""
        try:
            X = np.vstack([np.asarray(f, dtype=np.float64)
                           for f in self._recent_feats])
            report = self.detector.psi(X)
            if report.get("available"):
                self._drift_level = report.get("level")
        except Exception:  # noqa: BLE001 - drift cache is best effort
            pass

    def robustness(self, pcap: str | None = None, max_features: int = 12,
                   max_rounds: int = 6) -> dict:
        """Run evasion attacks against detected flows (PCAP or recent window)."""
        if not self.detector.is_trained:
            return {"available": False, "reason": "model not trained"}
        if pcap:
            flows = collect_flows(pcap, idle_timeout=self.idle_timeout)
            X = flows_to_matrix(flows) if flows else np.empty((0, 0))
            source = pcap
        else:
            if not self._recent_feats:
                return {"available": False, "reason": "no scored flows yet"}
            X = np.vstack([np.asarray(f, dtype=np.float64)
                           for f in self._recent_feats])
            source = "live window"
        if len(X) == 0:
            return {"available": False, "reason": "no flows to evaluate"}
        result = attack_batch(self.detector, X, max_features=max_features,
                              max_rounds=max_rounds)
        result["available"] = True
        result["source"] = source
        return result

    # -- Module 7: cross-domain correlation ----------------------------------

    def graph_snapshot(self, ntype: str | None = None, sector: str | None = None,
                       limit: int = 500) -> dict:
        return {
            "summary": self.graph.summary(),
            "nodes": self.graph.nodes_list(ntype=ntype, sector=sector, limit=limit),
            "edges": self.graph.edges_list(limit=min(limit * 4, 5000)),
        }

    def graph_cascade(self, node_id: str, max_depth: int = 4) -> dict:
        return cascade(self.graph, node_id, max_depth=max_depth)

    # -- Module 1: PQC readiness -------------------------------------------

    def pqc_snapshot(self, include_roadmap: bool = True, sector: str | None = None) -> dict:
        """Quantum posture of everything seen by this engine."""
        pairs = [
            (r, r["pqc"]) for r in self.flows if r.get("pqc") and r["pqc"]["applicable"]
        ]
        findings = screen_flows(pairs)
        summary = self.pqc.summary()
        endpoints = self.pqc.endpoints(limit=200, sector=sector)
        out = {
            "summary": summary,
            "endpoints": endpoints,
            "hndl": findings,
            "model": self.detector.info(),
        }
        if include_roadmap:
            out["roadmap"] = generate_roadmap(summary, endpoints, findings, sector)
        return out

    # -- Module 4: digital twin ----------------------------------------------

    def twin_topology(self, min_flows: int = 1) -> dict:
        """Isolated replica of the observed network (zones, assets, edges)."""
        return build_topology(self.graph, min_flows=min_flows)

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
        if not self.detector.is_trained:
            return {"available": False, "reason": "model not trained"}
        if pcap:
            flows = collect_flows(pcap, idle_timeout=self.idle_timeout)
            X = flows_to_matrix(flows) if flows else np.empty((0, 0))
            source = pcap
        else:
            if not self._recent_feats:
                return {"available": False, "reason": "no scored flows yet"}
            X = np.vstack([np.asarray(f, dtype=np.float64)
                           for f in self._recent_feats])
            source = "live window"
        if len(X) == 0:
            return {"available": False, "reason": "no flows to evaluate"}
        candidate = None
        if retrain:
            candidate = SpectraDetector(contamination=contamination,
                                        random_state=42)
            candidate.fit(X)
        result = run_shadow(self.detector, X, candidate=candidate,
                            feature_names=self.detector.feature_names,
                            threshold=threshold)
        result["source"] = source
        return result

    # -- Module 6: bio-inspired detection -----------------------------------

    def bio_report(self) -> dict:
        """Immune / SNN / swarm state plus live context."""
        out = self.bio.status()
        out["drift_level"] = self._drift_level
        out["evasion_active"] = bool(self.score_watch.alerted)
        out["timing_scale"] = round(self.edge.timing_scale(), 3)
        return out

    def bio_assess(self, features=None, score: float | None = None,
                   anomaly: bool = False) -> dict:
        """Assess an explicit feature vector (or the latest live flow)."""
        if features is None:
            if not self._recent_feats:
                raise ValueError("no scored flows in the live window - "
                                 "pass an explicit feature vector")
            x = self._recent_feats[-1]
            if score is None and self._counters["scores"]:
                score = float(self._counters["scores"][-1])
        else:
            x = np.asarray(features, dtype=np.float64)
        return self.bio.assess(x, score=score, anomaly=bool(anomaly),
                               drift_level=self._drift_level,
                               evasion=bool(self.score_watch.alerted),
                               timing_scale=self.edge.timing_scale())

    # -- Module 8: 5G/6G edge -----------------------------------------------

    def edge_report(self) -> dict:
        """Slices, micro-detector state, link profiles, deployments."""
        out = self.edge.report()
        out["slices"] = {k: dict(v) for k, v in SLICES.items()}
        out["slice_counts"] = dict(self._counters["slices"])
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

    # -- Module 2: confidential computing -----------------------------------

    def tee_attest(self, nonce: str | None = None) -> dict:
        if self.tee is None:
            raise TeeError("attestation unavailable in this process")
        return self.tee.quote(nonce)

    def tee_verify(self, quote: dict, measurement: str | None = None,
                   max_age: float = 600.0, nonce: str | None = None) -> dict:
        if self.tee is None:
            raise TeeError("attestation unavailable in this process")
        return self.tee.verify(quote, measurement=measurement,
                               max_age=max_age, nonce=nonce)

    def tee_infer(self, features) -> dict:
        """Sealed inference: features in, score + signed receipt out."""
        if self.tee is None:
            raise TeeError("attestation unavailable in this process")
        return self.tee.infer(self.detector, features)

    def tee_federate(self, deltas=None, shareholders: int = 3,
                     seed: int = 7) -> dict:
        """Secure aggregation: explicit deltas or the live window's means."""
        if deltas is None:
            window = list(self._recent_feats)
            if len(window) < 4:
                raise TeeError("no live window to federate - pass deltas")
            parties = 3
            step = max(1, len(window) // parties)
            groups = [window[i * step:(i + 1) * step]
                      for i in range(parties)]
            groups = [g for g in groups if g]
            deltas = [np.mean([np.asarray(f, dtype=np.float64)
                               for f in g], axis=0).tolist()
                      for g in groups]
        return federated_round(deltas, shareholders=shareholders, seed=seed)

    # -- reporting ----------------------------------------------------------

    def snapshot(self) -> dict:
        scores = self._counters["scores"]
        timeline = sorted(self.timeline.values(), key=lambda e: e["t"])[
            -self.config.timeline_buckets:
        ]
        return {
            "status": self.status,
            "model": self.detector.info(),
            "totals": {
                "packets": self.status["packets"],
                "flows": self.status["flows"],
                "detections": self.status["detections"],
                "anomaly_rate": round(
                    self.status["detections"] / self.status["flows"], 4
                ) if self.status["flows"] else 0.0,
                "avg_score": round(float(np.mean(scores)), 2) if scores else None,
            },
            "protocols": dict(self._counters["protocols"]),
            "tls_versions": dict(self._counters["tls_versions"]),
            "timeline": [
                {
                    "t": e["t"],
                    "flows": e["flows"],
                    "anomalies": e["anomalies"],
                    "avg_score": round(e["score_sum"] / e["flows"], 2) if e["flows"] else 0,
                }
                for e in timeline
            ],
        }
