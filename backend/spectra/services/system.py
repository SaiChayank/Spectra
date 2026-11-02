"""System service: status/health/snapshot/metrics reporting surface.

Also owns the **System Health API** (``GET /api/health/system``): one entry
per subsystem with its state, the reason it is in that state and the
observed numbers, plus the runtime metrics block (rates, saturation, drops,
latencies, error counts). Evaluation rules live in :mod:`spectra.health`
(pure); this class only gathers live values, guarded per section.
"""

from __future__ import annotations

import logging
import os
import time
from typing import TypedDict

import numpy as np

from .. import __version__
from ..config import Config
from ..health import (
    DB_WRITE_P95_MS,
    FLOW_SATURATION,
    INFERENCE_P95_MS,
    QUEUE_SATURATION,
    SUBSYSTEMS,
    WindowRates,
    check_audit,
    check_capture,
    check_database,
    check_events,
    check_flow_tracker,
    check_inference,
    check_model,
    check_module,
    check_quic_parser,
    check_tls_parser,
    overall,
)
from ..store import Store
from .detection import DetectionService
from .model import ModelService
from .resilience import FailureTracker

log = logging.getLogger("spectra.engine")


class _HealthInputs(TypedDict):
    """Everything the metric/subsystem builders read (gathered once per
    report so each section sees one consistent snapshot)."""

    now: float
    stream: dict
    queue: dict
    limits: dict
    packets: int
    flows: int
    dropped_packets: int
    dropped_flows: int
    lag_ms: float
    utilization: float
    active: int
    flow_limit: int
    evicted: int
    evicted_new: int
    dropped_flows_new: int
    db_errors_new: int
    listener_errors_new: int
    ws_drops_new: int
    latency: dict
    trained: bool
    model_id: str
    version: str | int | None
    n_train: int
    trained_at: float | None
    drift: str | None
    model_error: str | None
    db_enabled: bool
    db_error: str | None
    db_stats: dict
    size_bytes: int
    audit_seq: int | None
    audit_entries: int
    audit_error: str | None
    clients: int
    ws_drops: int
    subscribers: int
    emitted: int
    listener_errors: int
    failures: dict
    fail_new: dict
    caps: dict
    caps_new: dict
    tls_flows: int
    quic_flows: int
    crypto: bool
    rates: dict
    capture_error: str | None


class SystemService:
    """Read-only reporting over the shared status dict and detection buffers."""

    def __init__(self, status: dict, config: Config, store: Store | None,
                 model: ModelService, detection: DetectionService,
                 failures: FailureTracker, boot_ts: float | None = None,
                 *, events=None, capability_provider=None) -> None:
        self.status = status
        self.config = config
        self.store = store
        self._model = model
        self._detection = detection
        self.failures = failures
        self.boot_ts = time.time() if boot_ts is None else boot_ts
        #: EventBus (event/websocket telemetry); optional for old callers.
        self._events = events
        #: Engine-supplied live capability probes (module self-descriptions).
        self._capability_provider = capability_provider
        # Health-report bookkeeping: windowed-delta baseline (the first
        # report establishes it, so "since the previous check" never counts
        # process-start history) and the last state per subsystem for
        # structured transition logs.
        self._health_prev: dict | None = None
        self._health_states: dict[str, str] = {}
        self._rates = WindowRates()

    # -- health ----------------------------------------------------------------

    def health(self) -> dict:
        store = self.store
        return {
            "ok": True,
            "service": "spectra",
            "version": __version__,
            "database": "enabled" if store else "disabled",
            "schema_version": getattr(store, "schema_version", None),
            "uptime_s": round(time.time() - self.boot_ts, 1),
        }

    # -- operational health (GET /api/health/system) ---------------------------

    @staticmethod
    def _delta_int(old: int, current: int) -> int:
        """New occurrences since a baseline (a counter reset rebases)."""
        return current - old if current >= old else current

    def _gather_health(self, now: float) -> _HealthInputs:
        """Read one consistent, fully guarded snapshot of every health input.

        A failing probe degrades the section it feeds, never the report:
        model, capabilities, database, audit and event counters are each
        wrapped, and windowed deltas baseline on the first report so
        "since the previous check" never counts process-start history.
        """
        status = self.status
        stream = dict(status.get("pipeline") or {})
        queue = dict(status.get("queue") or {})
        ws = dict(status.get("websocket") or {})
        limits = dict(stream.get("limits") or {})
        failures = dict(self.failures.counts)
        prev = self._health_prev

        # model identity + cached drift (never recompute PSI on a health poll)
        model_error = None
        try:
            info = dict(self._model.info())
        except Exception as exc:  # noqa: BLE001 - health must keep reporting
            info = {"trained": False, "version": None, "n_train": 0,
                    "trained_at": None}
            model_error = f"{type(exc).__name__}: {exc}"
        try:
            drift = self._model.drift_level
        except Exception:  # noqa: BLE001
            drift = None
        model_path = (getattr(self._model, "model_path", None)
                      or self.config.model_path)

        # live module probes (availability + module self-descriptions)
        caps: dict = {}
        try:
            if self._capability_provider is not None:
                caps = dict(self._capability_provider() or {})
        except Exception as exc:  # noqa: BLE001 - outage shows as detail
            log.warning("capability probe failed during health report: %s", exc)
            caps = {}

        # database: write latency/error telemetry + file size
        db_enabled = self.store is not None
        db_error = None
        db_stats: dict = {}
        size_bytes = 0
        if db_enabled:
            try:
                db_stats = dict(self.store.write_stats())
            except Exception as exc:  # noqa: BLE001
                db_error = f"{type(exc).__name__}: {exc}"
            try:
                path = getattr(self.store, "path", "")
                if path and path != ":memory:":
                    size_bytes = os.path.getsize(path)
            except OSError:
                size_bytes = 0

        # audit chain head (head row + count; never a full chain walk)
        audit_seq: int | None = None
        audit_entries = 0
        audit_error = None
        if db_enabled:
            try:
                head = self.store.audit_head()
                audit_seq = int(head.get("seq")) if head else None
                audit_entries = int(self.store.audit_count())
            except Exception as exc:  # noqa: BLE001
                audit_error = f"{type(exc).__name__}: {exc}"

        # event bus + websocket counters (written by spectra.api.app)
        bus = self._events
        clients = int(ws.get("clients", 0) or 0)
        ws_drops = int(ws.get("slow_client_drops", 0) or 0)
        emitted = int(getattr(bus, "emit_count", 0) or 0) \
            if bus is not None else 0
        listener_errors = int(getattr(bus, "listener_errors", 0) or 0) \
            if bus is not None else 0
        subscribers = int(bus.subscriber_count) if bus is not None else 0

        # QUIC payload-decryption capability (optional cryptography package)
        try:
            from ..parse.quic import CRYPTO_AVAILABLE
            crypto = bool(CRYPTO_AVAILABLE)
        except Exception:  # noqa: BLE001 - treat as "cannot decrypt"
            crypto = False

        # windowed rate counters (per-minute rates between health reports)
        packets = int(status.get("packets", 0) or 0)
        flows = int(status.get("flows", 0) or 0)
        dropped_packets = (int(queue.get("packets_dropped", 0) or 0)
                           + int(stream.get("dropped_packets", 0) or 0))
        dropped_flows = int(stream.get("dropped_flows", 0) or 0)
        rate_counters: dict[str, float] = {
            "packets": packets,
            "flows": flows,
            "detections": int(status.get("detections", 0) or 0),
            "packet_drops": dropped_packets,
            "flow_drops": dropped_flows,
            "events": emitted,
            "failures": sum(failures.values()),
        }
        if db_enabled:
            try:
                rate_counters["incidents"] = int(self.store.incident_count())
            except Exception:  # noqa: BLE001 - key omitted from this window
                pass
        self._rates.observe(rate_counters, ts=now)
        rates = self._rates.rates()

        # windowed deltas vs the previous report (first report = baseline)
        if prev is None:
            fail_new = {key: 0 for key in failures}
            caps_new = {key: 0 for key in caps}
            db_errors_new = listener_errors_new = ws_drops_new = 0
            evicted_new = dropped_flows_new = 0
        else:
            old_fail = dict(prev.get("fail") or {})
            fail_new = {
                key: self._delta_int(int(old_fail.get(key, 0)), int(value))
                for key, value in failures.items()
            }
            old_caps = dict(prev.get("caps") or {})
            caps_new = {
                key: self._delta_int(
                    int(old_caps.get(key, 0)),
                    int((value or {}).get("failures") or 0))
                for key, value in caps.items()
            }
            db_errors_new = self._delta_int(
                int(prev.get("db_errors", 0) or 0),
                int(db_stats.get("errors", 0) or 0))
            listener_errors_new = self._delta_int(
                int(prev.get("listener_errors", 0) or 0), listener_errors)
            ws_drops_new = self._delta_int(
                int(prev.get("ws_drops", 0) or 0), ws_drops)
            evicted_new = self._delta_int(
                int(prev.get("evicted", 0) or 0),
                int(stream.get("flows_evicted", 0) or 0))
            dropped_flows_new = self._delta_int(
                int(prev.get("dropped_flows", 0) or 0), dropped_flows)

        counters = self._detection.counters
        pq = stream.get("packet_queue") or {}
        pq_limit = int(pq.get("limit") or 0)
        pq_depth = int(pq.get("depth") or 0)

        return {
            "now": now,
            "stream": stream,
            "queue": queue,
            "limits": limits,
            "packets": packets,
            "flows": flows,
            "dropped_packets": dropped_packets,
            "dropped_flows": dropped_flows,
            "lag_ms": float(stream.get("processing_lag_ms", 0.0) or 0.0),
            "utilization": (pq_depth / pq_limit) if pq_limit else 0.0,
            "active": int(stream.get("active_flows", 0) or 0),
            "flow_limit": int(limits.get("active_flows", 0)
                              or self.config.max_active_flows),
            "evicted": int(stream.get("flows_evicted", 0) or 0),
            "evicted_new": evicted_new,
            "dropped_flows_new": dropped_flows_new,
            "latency": {
                "p50_ms": float(stream.get("inference_latency_p50_ms", 0.0)),
                "p95_ms": float(stream.get("inference_latency_p95_ms", 0.0)),
                "ops": int(stream.get("inference_ops", 0) or 0),
            },
            "trained": bool(info.get("trained")),
            "model_id": os.path.basename(model_path),
            "version": info.get("version"),
            "n_train": int(info.get("n_train", 0) or 0),
            "trained_at": info.get("trained_at"),
            "drift": drift,
            "model_error": model_error,
            "db_enabled": db_enabled,
            "db_error": db_error,
            "db_stats": db_stats,
            "size_bytes": size_bytes,
            "audit_seq": audit_seq,
            "audit_entries": audit_entries,
            "audit_error": audit_error,
            "clients": clients,
            "ws_drops": ws_drops,
            "subscribers": subscribers,
            "emitted": emitted,
            "listener_errors": listener_errors,
            "failures": failures,
            "fail_new": fail_new,
            "caps": caps,
            "caps_new": caps_new,
            "db_errors_new": db_errors_new,
            "listener_errors_new": listener_errors_new,
            "ws_drops_new": ws_drops_new,
            "tls_flows": int(sum(counters.get("tls_versions", {}).values())),
            "quic_flows": int(sum(counters.get("quic_versions", {}).values())),
            "crypto": crypto,
            "rates": rates,
            "capture_error": status.get("error"),
        }

    def _health_metrics(self, p: _HealthInputs) -> dict:
        """Runtime metrics: saturation, drops, latencies, rates, errors."""
        stream, queue = p["stream"], p["queue"]

        def stage(name: str) -> dict:
            st = stream.get(name) or {}
            limit = int(st.get("limit") or 0)
            depth = int(st.get("depth") or 0)
            return {
                "depth": depth,
                "limit": limit,
                "utilization": round(depth / limit, 3) if limit else 0.0,
                "offered": int(st.get("offered", 0) or 0),
                "accepted": int(st.get("accepted", 0) or 0),
                "dropped": int(st.get("dropped", 0) or 0),
            }

        stages = {name: stage(name)
                  for name in ("packet_queue", "flow_queue", "publish_queue")}
        saturation = [name for name, st in stages.items()
                      if st["utilization"] >= QUEUE_SATURATION]
        if p["flow_limit"] and (
                p["active"] / p["flow_limit"]) >= FLOW_SATURATION:
            saturation.append("active_flows")
        db = p["db_stats"]
        rates = p["rates"]
        return {
            "uptime_s": round(p["now"] - self.boot_ts, 1),
            "packets": {
                "captured": p["packets"],
                "dropped": p["dropped_packets"],
                "drop_ratio": (round(p["dropped_packets"] / p["packets"], 5)
                               if p["packets"] else 0.0),
                "rate_pps": float(p["stream"].get("packets_per_sec", 0.0)),
            },
            "flows": {
                "processed": p["flows"],
                "rate_fps": float(p["stream"].get("flows_per_sec", 0.0)),
                "active": p["active"],
                "active_limit": p["flow_limit"],
                "evicted": p["evicted"],
                "dropped": p["dropped_flows"],
            },
            "queues": {
                **stages,
                "live_capture": {
                    "received": int(queue.get("packets_received", 0) or 0),
                    "queued": int(queue.get("packets_queued", 0) or 0),
                    "dropped": int(queue.get("packets_dropped", 0) or 0),
                    "depth": int(queue.get("queue_depth", 0) or 0),
                    "max_depth": int(queue.get("max_queue_depth", 0) or 0),
                },
                "saturation": saturation,
            },
            "inference": {
                "p50_ms": p["latency"]["p50_ms"],
                "p95_ms": p["latency"]["p95_ms"],
                "mean_ms": float(p["stream"].get("inference_latency_ms", 0.0)),
                "max_ms": float(
                    p["stream"].get("inference_latency_max_ms", 0.0)),
                "ops": p["latency"]["ops"],
                "budget_p95_ms": INFERENCE_P95_MS,
            },
            "processing_lag_ms": p["lag_ms"],
            "processing_lag_max_ms": float(
                p["stream"].get("processing_lag_max_ms", 0.0)),
            "database": {
                "enabled": p["db_enabled"],
                "size_bytes": p["size_bytes"],
                "write_p50_ms": float(db.get("write_p50_ms", 0.0)),
                "write_p95_ms": float(db.get("write_p95_ms", 0.0)),
                "write_samples": int(db.get("write_samples", 0) or 0),
                "commits": int(db.get("commits", 0) or 0),
                "flushes": int(db.get("flushes", 0) or 0),
                "staged": int(db.get("staged", 0) or 0),
                "errors": int(db.get("errors", 0) or 0),
                "budget_p95_ms": DB_WRITE_P95_MS,
            },
            # measured between health reports (<= 60s window; 0.0 until the
            # second report establishes a baseline)
            "rates": {
                "packets_per_min": rates.get("packets", 0.0),
                "flows_per_min": rates.get("flows", 0.0),
                "detections_per_min": rates.get("detections", 0.0),
                "incidents_per_min": rates.get("incidents", 0.0),
                "events_per_min": rates.get("events", 0.0),
                "packet_drops_per_min": rates.get("packet_drops", 0.0),
                "flow_drops_per_min": rates.get("flow_drops", 0.0),
                "failures_per_min": rates.get("failures", 0.0),
            },
            "websocket": {
                "clients": p["clients"],
                "subscribers": p["subscribers"],
                "events_emitted": p["emitted"],
                "slow_client_drops": p["ws_drops"],
            },
            "model": {
                "id": p["model_id"],
                "version": p["version"],
                "trained": p["trained"],
                "n_train": p["n_train"],
                "trained_at": p["trained_at"],
                "drift_level": p["drift"],
            },
            "errors": {
                "total": sum(p["failures"].values()),
                "by_component": p["failures"],
                "capture_error": p["capture_error"],
            },
        }

    def _health_subsystems(self, p: _HealthInputs) -> list[dict]:
        """The 14 subsystem entries, in registry order (see spectra.health)."""
        caps, caps_new = p["caps"], p["caps_new"]

        def cap(key: str,
                default: str = "capability probe did not report this "
                               "module") -> tuple[bool, str, int]:
            info = caps.get(key) or {}
            detail = info.get("detail")
            return (bool(info.get("available", False)),
                    str(detail) if detail else default,
                    int(info.get("failures") or 0))

        pqc_a, pqc_d, pqc_f = cap("pqc")
        bio_a, bio_d, bio_f = cap("bio")
        tee_a, tee_d, tee_f = cap("tee")
        twin_a, twin_d, twin_f = cap("twin")
        edge_a, edge_d, edge_f = cap("edge")
        _, dep_d, _ = cap("edge_deployment", default="")
        edge_detail = f"{edge_d}; deployment: {dep_d}" if dep_d else edge_d

        entries = [
            check_capture(
                running=bool(self.status.get("running")),
                mode=self.status.get("mode"),
                source=self.status.get("source"),
                error=p["capture_error"],
                packets=p["packets"], dropped=p["dropped_packets"],
                utilization=p["utilization"], lag_ms=p["lag_ms"]),
            check_flow_tracker(
                active=p["active"], limit=p["flow_limit"],
                evicted=p["evicted"], evicted_new=p["evicted_new"],
                dropped_new=p["dropped_flows_new"],
                parse_errors_new=int(p["fail_new"].get("flow_tracking", 0))),
            check_tls_parser(tls_flows=p["tls_flows"],
                             total_flows=p["flows"]),
            check_quic_parser(crypto_available=p["crypto"],
                              quic_flows=p["quic_flows"]),
            check_inference(
                trained=p["trained"], latency=p["latency"],
                failures_new=int(p["fail_new"].get("inference", 0))),
            check_model(
                trained=p["trained"], model_id=p["model_id"],
                version=p["version"] if p["version"] is not None else "?",
                n_train=p["n_train"], drift_level=p["drift"],
                error=p["model_error"]),
            check_database(
                enabled=p["db_enabled"], error=p["db_error"],
                size_bytes=p["size_bytes"],
                latency={"write_p50_ms": p["db_stats"].get("write_p50_ms",
                                                           0.0),
                         "write_p95_ms": p["db_stats"].get("write_p95_ms",
                                                           0.0)},
                commits=int(p["db_stats"].get("commits", 0) or 0),
                errors_new=p["db_errors_new"]),
            check_events(
                clients=p["clients"], subscribers=p["subscribers"],
                emitted=p["emitted"],
                listener_errors_new=p["listener_errors_new"],
                slow_drops_new=p["ws_drops_new"]),
            check_audit(
                enabled=p["db_enabled"], error=p["audit_error"],
                seq=p["audit_seq"], entries=p["audit_entries"],
                failures_total=int(p["failures"].get("audit", 0))),
            check_module(name="pqc", available=pqc_a, detail=pqc_d,
                         failures_new=int(caps_new.get("pqc", 0)),
                         failures_total=pqc_f),
            check_module(name="bio", available=bio_a, detail=bio_d,
                         failures_new=int(caps_new.get("bio", 0)),
                         failures_total=bio_f),
            check_module(name="tee", available=tee_a, detail=tee_d,
                         failures_new=int(caps_new.get("tee", 0)),
                         failures_total=tee_f, simulated=True),
            check_module(name="edge", available=edge_a, detail=edge_detail,
                         failures_new=int(caps_new.get("edge", 0)),
                         failures_total=edge_f),
            check_module(name="twin", available=twin_a, detail=twin_d,
                         failures_new=int(caps_new.get("twin", 0)),
                         failures_total=twin_f, simulated=True),
        ]
        names = [e["name"] for e in entries]
        expected = [name for name, _ in SUBSYSTEMS]
        if names != expected:  # pragma: no cover - registry drift guard
            log.error("health registry mismatch: got %s", names)
        return entries

    def _log_health_transitions(self, subsystems: list[dict]) -> None:
        """Structurally log state changes (never per-poll state dumps)."""
        for sub in subsystems:
            name, state = sub["name"], sub["state"]
            prior = self._health_states.get(name)
            if prior is not None and prior != state:
                log.info("subsystem health changed", extra={
                    "event": "subsystem_health",
                    "subsystem": name,
                    "from": prior,
                    "to": state,
                    "reason": sub["reason"],
                })
            self._health_states[name] = state

    def health_report(self) -> dict:
        """System Health document: overall + per-subsystem state with a
        reason and evidence, plus the runtime metrics block.

        Read-only, guarded per section, and side-effect free apart from
        the rate/transition bookkeeping it owns.
        """
        now = time.time()
        parts = self._gather_health(now)
        metrics = self._health_metrics(parts)
        subsystems = self._health_subsystems(parts)
        self._log_health_transitions(subsystems)
        state, reason, counts = overall(subsystems)
        self._health_prev = {
            "fail": dict(parts["failures"]),
            "caps": {key: int((value or {}).get("failures") or 0)
                     for key, value in parts["caps"].items()},
            "db_errors": int(parts["db_stats"].get("errors", 0) or 0),
            "listener_errors": parts["listener_errors"],
            "ws_drops": parts["ws_drops"],
            "evicted": parts["evicted"],
            "dropped_flows": parts["dropped_flows"],
        }
        return {
            "ts": now,
            "uptime_s": round(now - self.boot_ts, 1),
            "state": state,
            "reason": reason,
            "counts": counts,
            "subsystems": subsystems,
            "metrics": metrics,
        }

    def interfaces(self) -> dict:
        """List capture interfaces with friendly metadata. Empty until
        Npcap/libpcap is installed. Adapters carrying a real (non-APIPA) IP sort
        first so the default pick in the dashboard is the active NIC."""
        try:
            from scapy.all import conf, get_if_list

            rows: list[tuple[int, str, dict]] = []
            for dev in get_if_list():
                try:
                    iface = conf.ifaces.get(dev)
                except Exception:  # noqa: BLE001 - keep the raw device id usable
                    iface = None
                name = (getattr(iface, "name", None) or dev) if iface else dev
                ip = (getattr(iface, "ip", "") or "") if iface else ""
                if not ip or ip.startswith("127."):
                    rank = 3
                elif ip.startswith("169.254"):
                    rank = 2
                else:
                    rank = 0
                rows.append((rank, dev, {
                    "id": dev,
                    "name": name,
                    "description": (getattr(iface, "description", "") or "")
                    if iface else "",
                    "ip": ip,
                    "mac": (getattr(iface, "mac", "") or "") if iface else "",
                }))
            rows.sort(key=lambda r: r[0])
            return {
                "interfaces": [dev for _, dev, _ in rows],
                "details": [meta for _, _, meta in rows],
            }
        except Exception as exc:  # noqa: BLE001 - live capture unavailable
            return {"interfaces": [], "error": str(exc)}

    # -- snapshots ---------------------------------------------------------------

    def snapshot(self) -> dict:
        detection = self._detection
        scores = detection.counters["scores"]
        timeline = sorted(detection.timeline.values(), key=lambda e: e["t"])[
            -self.config.timeline_buckets:
        ]
        return {
            "status": self.status,
            "model": self._model.info(),
            "totals": {
                "packets": self.status["packets"],
                "flows": self.status["flows"],
                "detections": self.status["detections"],
                "anomaly_rate": round(
                    self.status["detections"] / self.status["flows"], 4
                ) if self.status["flows"] else 0.0,
                "avg_score": round(float(np.mean(scores)), 2) if scores else None,
            },
            "protocols": dict(detection.counters["protocols"]),
            "tls_versions": dict(detection.counters["tls_versions"]),
            "timeline": [
                {
                    "t": e["t"],
                    "flows": e["flows"],
                    "anomalies": e["anomalies"],
                    "avg_score": round(e["score_sum"] / e["flows"], 2)
                    if e["flows"] else 0,
                }
                for e in timeline
            ],
        }

    def metrics(self) -> str:
        """Prometheus text exposition format (text/plain; version 0.0.4)."""
        snap = self.snapshot()
        status = snap["status"]
        totals = snap["totals"]
        model = snap["model"]
        queue = status.get("queue", {})
        # database write latency/errors (guarded: disabled store -> zeros)
        write: dict = {}
        if self.store is not None:
            try:
                write = self.store.write_stats()
            except Exception:  # noqa: BLE001 - metrics must never raise
                write = {}
        ws = status.get("websocket") or {}
        lines = [
            "# TYPE spectra_packets_total counter",
            f"spectra_packets_total {status['packets']}",
            "# TYPE spectra_flows_total counter",
            f"spectra_flows_total {totals['flows']}",
            "# TYPE spectra_detections_total counter",
            f"spectra_detections_total {totals['detections']}",
            "# TYPE spectra_anomaly_rate gauge",
            f"spectra_anomaly_rate {totals['anomaly_rate']}",
            "# TYPE spectra_avg_score gauge",
            f"spectra_avg_score {totals['avg_score'] if totals['avg_score'] is not None else -1}",
            "# TYPE spectra_capture_running gauge",
            f"spectra_capture_running {1 if status['running'] else 0}",
            "# TYPE spectra_model_trained gauge",
            f"spectra_model_trained {1 if model['trained'] else 0}",
            "# TYPE spectra_model_train_flows gauge",
            f"spectra_model_train_flows {model['n_train']}",
            "# TYPE spectra_uptime_seconds gauge",
            f"spectra_uptime_seconds {round(time.time() - self.boot_ts, 1)}",
            # live-capture queue/backpressure telemetry (current capture session)
            "# TYPE spectra_queue_packets_received gauge",
            f"spectra_queue_packets_received {queue.get('packets_received', 0)}",
            "# TYPE spectra_queue_packets_queued gauge",
            f"spectra_queue_packets_queued {queue.get('packets_queued', 0)}",
            "# TYPE spectra_queue_packets_dropped gauge",
            f"spectra_queue_packets_dropped {queue.get('packets_dropped', 0)}",
            "# TYPE spectra_queue_depth gauge",
            f"spectra_queue_depth {queue.get('queue_depth', 0)}",
            "# TYPE spectra_queue_max_depth gauge",
            f"spectra_queue_max_depth {queue.get('max_queue_depth', 0)}",
        ]
        # staged streaming runtime: bounded queues, overload drops and latency
        stream = status.get("pipeline", {}) or {}
        stages = (
            ("packet_queue", "spectra_packet_queue"),
            ("flow_queue", "spectra_flow_queue"),
            ("publish_queue", "spectra_publish_queue"),
        )
        for key, prefix in stages:
            stage = stream.get(key, {}) or {}
            lines += [
                f"# TYPE {prefix}_depth gauge",
                f"{prefix}_depth {stage.get('depth', 0)}",
                f"# TYPE {prefix}_max_depth gauge",
                f"{prefix}_max_depth {stage.get('max_depth', 0)}",
                f"# TYPE {prefix}_limit gauge",
                f"{prefix}_limit {stage.get('limit', 0)}",
                f"# TYPE {prefix}_dropped counter",
                f"{prefix}_dropped {stage.get('dropped', 0)}",
            ]
        lines += [
            "# TYPE spectra_packets_per_second gauge",
            f"spectra_packets_per_second {stream.get('packets_per_sec', 0.0)}",
            "# TYPE spectra_flows_per_second gauge",
            f"spectra_flows_per_second {stream.get('flows_per_sec', 0.0)}",
            "# TYPE spectra_processing_lag_ms gauge",
            f"spectra_processing_lag_ms {stream.get('processing_lag_ms', 0.0)}",
            "# TYPE spectra_inference_latency_ms gauge",
            f"spectra_inference_latency_ms {stream.get('inference_latency_ms', 0.0)}",
            "# TYPE spectra_active_flows gauge",
            f"spectra_active_flows {stream.get('active_flows', 0)}",
            "# TYPE spectra_active_flows_max gauge",
            f"spectra_active_flows_max {stream.get('active_flows_max', 0)}",
            "# TYPE spectra_flow_evictions counter",
            f"spectra_flow_evictions {stream.get('flows_evicted', 0)}",
            "# TYPE spectra_flows_dropped counter",
            f"spectra_flows_dropped {stream.get('dropped_flows', 0)}",
            "# TYPE spectra_stream_overload gauge",
            f"spectra_stream_overload {1 if stream.get('overload') else 0}",
            # health-layer latencies: scoring p50/p95 + database write p95
            "# TYPE spectra_inference_latency_p50_ms gauge",
            f"spectra_inference_latency_p50_ms "
            f"{stream.get('inference_latency_p50_ms', 0.0)}",
            "# TYPE spectra_inference_latency_p95_ms gauge",
            f"spectra_inference_latency_p95_ms "
            f"{stream.get('inference_latency_p95_ms', 0.0)}",
            "# TYPE spectra_db_write_latency_p95_ms gauge",
            f"spectra_db_write_latency_p95_ms {write.get('write_p95_ms', 0.0)}",
            "# TYPE spectra_db_errors counter",
            f"spectra_db_errors {write.get('errors', 0)}",
            # event-websocket telemetry (connected clients, slow-client drops)
            "# TYPE spectra_websocket_clients gauge",
            f"spectra_websocket_clients {ws.get('clients', 0)}",
            "# TYPE spectra_websocket_slow_client_drops counter",
            f"spectra_websocket_slow_client_drops "
            f"{ws.get('slow_client_drops', 0)}",
            # optional-module failure counts (component -> n)
            "# TYPE spectra_pipeline_failures gauge",
        ]
        for proto, n in snap["protocols"].items():
            lines.append(f'spectra_flows_by_proto{{proto="{proto}"}} {n}')
        for component, n in sorted(status.get("failures", {}).items()):
            lines.append(f'spectra_pipeline_failures{{component="{component}"}} {n}')
        return "\n".join(lines) + "\n"
