"""System service: status/health/snapshot/metrics reporting surface."""

from __future__ import annotations

import time

import numpy as np

from .. import __version__
from ..config import Config
from ..store import Store
from .detection import DetectionService
from .model import ModelService
from .resilience import FailureTracker


class SystemService:
    """Read-only reporting over the shared status dict and detection buffers."""

    def __init__(self, status: dict, config: Config, store: Store | None,
                 model: ModelService, detection: DetectionService,
                 failures: FailureTracker, boot_ts: float | None = None) -> None:
        self.status = status
        self.config = config
        self.store = store
        self._model = model
        self._detection = detection
        self.failures = failures
        self.boot_ts = time.time() if boot_ts is None else boot_ts

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
            # optional-module failure counts (component -> n)
            "# TYPE spectra_pipeline_failures gauge",
        ]
        for proto, n in snap["protocols"].items():
            lines.append(f'spectra_flows_by_proto{{proto="{proto}"}} {n}')
        for component, n in sorted(status.get("failures", {}).items()):
            lines.append(f'spectra_pipeline_failures{{component="{component}"}} {n}')
        return "\n".join(lines) + "\n"
