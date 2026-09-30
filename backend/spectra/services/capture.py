"""Capture service: source lifecycle, staged streaming runtime, finalisation.

Owns the capture session end-to-end (Module 0).  The packet path itself runs
in :class:`spectra.streaming.StreamingPipeline` - four bounded stages
(capture -> packet queue -> flow processing -> completed-flow queue ->
inference -> publication queue -> persistence/events) - while this service
stays the session authority: it opens the source, resets the other services
so a capture always starts from a known state, supervises the stages until
they drain, and writes the session's closing evidence to the audit trail.

Overload is explicit and passive: a saturated stage drops internal work under
the policy of its queue (counted in ``status["pipeline"]``), packet
acquisition is never blocked, and no stage ever touches the source traffic.
"""

from __future__ import annotations

import logging
import threading
import time

import numpy as np

from ..capture import CaptureError, CaptureSource, open_source
from ..config import Config
from ..domain import CaptureSession
from ..modules.audit.log import MAX_LEAVES as AUDIT_MAX_LEAVES
from ..store import Store
from ..streaming import StreamingPipeline
from .alerts import AlertService
from .audit import AuditService
from .correlation import CorrelationService
from .detection import DetectionService
from .events import EventBus
from .model import ModelService
from .resilience import FailureTracker

log = logging.getLogger("spectra.engine")


class CaptureService:
    """One capture session at a time: open source, run stages, stop, finalise."""

    def __init__(self, config: Config, idle_timeout: float,
                 store: Store | None, events: EventBus, failures: FailureTracker,
                 audit: AuditService, session: CaptureSession, status: dict,
                 model: ModelService, detection: DetectionService,
                 alerts: AlertService,
                 correlation: CorrelationService) -> None:
        self.config = config
        self.idle_timeout = idle_timeout
        self.store = store
        self._events = events
        self.failures = failures
        self._audit = audit
        self.session = session
        self.status = status
        self._model = model
        self._detection = detection
        self._alerts = alerts
        self._correlation = correlation
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._explicit_stop = False
        self._source: CaptureSource | None = None
        self.pipeline: StreamingPipeline | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, mode: str, path: str | None = None,
              iface: str | None = None, bpf_filter: str = "",
              *, capture_id: int | None = None,
              source_label: str | None = None) -> dict:
        """Open a source and run one capture session.

        ``capture_id`` attaches to an existing managed resource row instead
        of inserting a new session row (the import workflow owns that row);
        ``source_label`` is the name shown in status/audit for managed runs,
        so no server path ever leaks into API responses.
        """
        if self.running:
            raise CaptureError("a capture is already running - stop it first")
        source = open_source(mode, path=path, iface=iface, bpf_filter=bpf_filter)
        self._source = source
        self._stop.clear()
        self._explicit_stop = False
        # per-session resets (pqc/timeline/counters, graph+history, watch)
        self._detection.reset_session()
        self._correlation.reset_session()   # keep history-backed nodes across sessions
        self._alerts.reset_session(
            contamination=self._model.contamination)
        started_at = time.time()
        label = source_label or path or iface or "live"
        status_source = source_label or path or iface or "default"
        self.session.begin(mode=mode, source=label,
                           started_at=started_at, bpf_filter=bpf_filter)
        if self.store is not None:
            try:
                if capture_id is not None:
                    self.store.attach_capture(capture_id, mode=mode,
                                              source=label)
                    self.session.capture_id = capture_id
                else:
                    self.session.capture_id = self.store.start_capture(
                        mode, label)
            except Exception as exc:  # noqa: BLE001
                log.warning("capture session not recorded: %s", exc)
                self.session.capture_id = None
        self.status.update({
            "running": True,
            "mode": mode,
            "source": status_source,
            "packets": 0,
            "flows": 0,
            "detections": 0,
            "started_at": started_at,
            "error": None,
            "model_trained": self._model.is_trained,
            "filter": bpf_filter or None,
            "persist": self.store is not None,
            "queue": dict(source.stats()),   # fresh counters for this session
        })
        # The staged runtime (built before the supervisor starts, so stop()
        # can reach it even if it fires immediately after start()).
        self.pipeline = StreamingPipeline(
            source=source, config=self.config, idle_timeout=self.idle_timeout,
            stop_event=self._stop, status=self.status,
            on_score=self._detection.score_flow,
            on_publish=self._detection.publish_flow,
            on_failure=self.failures.record,
        )
        self._audit.append("capture.start", {
            "mode": mode,
            "source": label,
            "filter": bpf_filter or None,
            "model_trained": self._model.is_trained,
        })
        self._thread = threading.Thread(
            target=self._run, name="spectra-engine", daemon=True
        )
        self._thread.start()
        self._events.emit({"type": "status", "data": self.status})
        return self.status

    def stop(self) -> dict:
        """Signal the stages, release the source, wait for a clean shutdown."""
        self._explicit_stop = True   # the session closes as STOPPED, not COMPLETED
        self._stop.set()
        pipeline = self.pipeline
        if pipeline is not None:
            pipeline.stop()
        elif self._source is not None:
            self._source.close()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=self.config.shutdown_timeout)
        return self.status

    # -- supervision -----------------------------------------------------------

    def _run(self) -> None:
        """Supervisor: run the stages, wait for them to drain, then close out
        the session.  ``status["running"]`` only flips to False once every
        stage has finished, so readers never observe a half-drained session.
        """
        pipeline = self.pipeline
        try:
            if pipeline is not None:
                pipeline.start()
                if not pipeline.wait(timeout=StreamingPipeline.DRAIN_TIMEOUT):
                    log.warning(
                        "stream stages did not drain within %.0fs - forcing stop",
                        StreamingPipeline.DRAIN_TIMEOUT)
                    self.failures.record(
                        "stream",
                        RuntimeError("stage drain timed out "
                                     f"({StreamingPipeline.DRAIN_TIMEOUT:.0f}s)"))
                    pipeline.abort()
                    pipeline.wait(timeout=5.0)
        except BaseException as exc:  # noqa: BLE001 - never lose finalisation
            log.exception("capture supervisor failed")
            try:
                self.failures.record("stream", exc)
            except Exception:  # noqa: BLE001
                pass
        finally:
            self._finalise()

    def _finalise(self) -> None:
        pipeline = self.pipeline
        if pipeline is not None:
            # final telemetry sample: throughput settles to 0, every drop and
            # latency counter keeps its value for /api/status and /api/metrics
            pipeline.refresh(int(self.status.get("packets", 0)), settled=True)
        self.status["running"] = False
        if self.store is not None and self.session.capture_id is not None:
            try:
                self.store.finish_capture(
                    self.session.capture_id,
                    packets=self.status["packets"],
                    flows=self.status["flows"],
                    detections=self.status["detections"],
                    error=self.status["error"],
                    status="STOPPED" if self._explicit_stop else None,
                )
            except Exception:  # noqa: BLE001
                log.exception("recording capture finish failed")
        # Module 5: commit this session's flow records (Merkle leaves)
        scores = self._detection.counters["scores"]
        leaves = self.session.leaves
        self._audit.append("capture.stop", {
            "mode": self.status["mode"],
            "source": self.status["source"],
            "packets": self.status["packets"],
            "flows": self.status["flows"],
            "detections": self.status["detections"],
            "avg_score": round(float(np.mean(scores)), 2)
            if scores else None,
            "error": self.status["error"],
            "evidence_records": len(leaves),
            "evidence_included": min(len(leaves), AUDIT_MAX_LEAVES),
        }, leaves=leaves)
        self.session.end()
        self._events.emit({"type": "status", "data": self.status})
        self._source = None
        self._thread = None
