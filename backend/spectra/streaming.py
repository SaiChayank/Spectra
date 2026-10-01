"""Bounded in-process streaming runtime for the capture pipeline.

Spectra is passive and read-only: these stages only *observe* traffic, never
modify it, never perform inline mitigation, and never block packet
acquisition.  Each stage is an explicit bounded queue with a documented
overload policy, so when a stage cannot keep up the pipeline sheds internal
processing work predictably - and the loss is always counted, never silent.

    capture thread ──▶ packet queue ──▶ flow thread ──▶ completed-flow queue
                       ──▶ inference thread ──▶ publication queue
                       ──▶ persistence / event publication

Overload policies (``status["pipeline"]["*"]["policy"]``):

* ``packet_queue``     ``drop_newest`` - the incoming packet is refused when
  full (cheapest on the acquisition path; the retained window stays
  contiguous).  The sniffer callback never blocks and never waits.
* ``flow_queue``       ``drop_oldest`` - the oldest *completed* flow is
  evicted so inference keeps working on the freshest conversations.
* ``publish_queue``    ``drop_oldest`` - same for persistence/publication, so
  a slow database cannot back pressure into inference.

Limits live in :class:`spectra.config.Config`: ``packet_queue_size``,
``flow_queue_size``, ``publish_queue_size``, ``max_active_flows``,
``flow_max_packets``, ``flow_max_lifetime``, ``idle_timeout`` and
``shutdown_timeout``.

Telemetry lands in ``status["pipeline"]`` (surfaced by ``GET /api/status``)
and in ``/api/metrics``: packet/flow drops, per-queue depths and high-water
marks, processing lag, packets/sec, flows/sec, inference latency, active
flows and flow evictions.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Any, Callable

from .capture.base import CaptureError, CaptureSource
from .config import Config
from .health import LatencyReservoir
from .parse.flow import FlowTracker

log = logging.getLogger("spectra.engine")

DROP_NEWEST = "drop_newest"
DROP_OLDEST = "drop_oldest"
_POLICIES = (DROP_NEWEST, DROP_OLDEST)

EOF: Any = object()   # end-of-stream marker: closed *and* drained


class BoundedBuffer:
    """A bounded FIFO with an explicit overload policy and loss counters.

    ``put`` never blocks: a full buffer either refuses the new item
    (``drop_newest``) or evicts the head (``drop_oldest``) - either way the
    loss increments :attr:`dropped` so overload is measurable.  ``get``
    returns ``None`` on timeout (so idle workers can service telemetry) and
    :data:`EOF` once the buffer is closed and drained.
    """

    def __init__(self, name: str, limit: int, policy: str = DROP_NEWEST) -> None:
        if limit < 1:
            raise ValueError(f"{name}: queue limit must be >= 1, got {limit}")
        if policy not in _POLICIES:
            raise ValueError(f"{name}: unknown overload policy {policy!r}")
        self.name = name
        self.limit = limit
        self.policy = policy
        self._items: deque = deque()
        self._cond = threading.Condition()
        self._closed = False
        self.offered = 0     # items offered to the buffer
        self.accepted = 0    # items actually queued
        self.dropped = 0     # overload/shutdown losses (never silent)
        self.max_depth = 0   # high-water mark

    # -- producer side ---------------------------------------------------------

    def put(self, item: Any) -> bool:
        """Queue ``item``; returns False when it was dropped (never blocks)."""
        with self._cond:
            self.offered += 1
            if self._closed:
                self.dropped += 1    # stream already over: refused, counted
                return False
            if len(self._items) >= self.limit:
                if self.policy == DROP_NEWEST:
                    self.dropped += 1
                    return False
                self._items.popleft()
                self.dropped += 1
            self._items.append(item)
            self.accepted += 1
            if len(self._items) > self.max_depth:
                self.max_depth = len(self._items)
            self._cond.notify()
            return True

    # -- consumer side ---------------------------------------------------------

    def get(self, timeout: float = 0.25) -> Any:
        """Next item, ``None`` on timeout, :data:`EOF` when closed+drained."""
        with self._cond:
            deadline = time.monotonic() + timeout
            while True:
                if self._items:
                    return self._items.popleft()
                if self._closed:
                    return EOF
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._cond.wait(remaining)

    def close(self, purge: bool = False) -> None:
        """End the stream.  ``purge`` also discards pending items, counting
        them as drops (only used when a drain deadline expires)."""
        with self._cond:
            self._closed = True
            if purge and self._items:
                self.dropped += len(self._items)
                self.accepted -= len(self._items)
                self._items.clear()
            self._cond.notify_all()

    # -- telemetry -------------------------------------------------------------

    @property
    def closed(self) -> bool:
        with self._cond:
            return self._closed

    @property
    def qsize(self) -> int:
        with self._cond:
            return len(self._items)

    def stats(self) -> dict:
        with self._cond:
            return {
                "limit": self.limit,
                "policy": self.policy,
                "depth": len(self._items),
                "max_depth": self.max_depth,
                "offered": self.offered,
                "accepted": self.accepted,
                "dropped": self.dropped,
            }


class RateMeter:
    """Lazy sliding-window rate (events/second) over a cumulative counter.

    Sampling is driven by the stage workers at their own pace; a counter that
    stops advancing decays to 0, and a counter that resets (new capture
    session) re-baselines instead of reporting a negative rate.
    """

    MIN_WINDOW = 0.5   # seconds between two meaningful samples

    def __init__(self) -> None:
        self._t: float | None = None
        self._base = 0
        self._rate = 0.0

    def sample(self, cumulative: int) -> float:
        now = time.monotonic()
        if self._t is None or cumulative < self._base:
            self._t, self._base = now, cumulative
            return 0.0
        dt = now - self._t
        if dt < self.MIN_WINDOW:
            return self._rate          # too soon to be meaningful
        self._rate = max(0.0, (cumulative - self._base) / dt)
        self._t, self._base = now, cumulative
        return self._rate


class StreamStats:
    """Mutable telemetry of one capture session, shared by every stage."""

    EMA_ALPHA = 0.1

    def __init__(self, *, packet_queue: BoundedBuffer, flow_queue: BoundedBuffer,
                 publish_queue: BoundedBuffer, tracker: FlowTracker,
                 config: Config, idle_timeout: float) -> None:
        self.packet_queue = packet_queue
        self.flow_queue = flow_queue
        self.publish_queue = publish_queue
        self.tracker = tracker
        self.config = config
        self.idle_timeout = idle_timeout
        self._lag_ms = 0.0
        self._lag_max_ms = 0.0
        self._infer_ms = 0.0
        self._infer_max_ms = 0.0
        # Recent-scoring ring behind the p50/p95 latency percentiles
        # (bounded, so long captures cannot grow memory without limit).
        self._infer_reservoir = LatencyReservoir()
        self.inference_ops = 0
        self.active_flows_max = 0
        self._packet_rate = RateMeter()
        self._flow_rate = RateMeter()

    def note_active_flows(self) -> None:
        """High-water mark of the flow table (O(1); called per packet)."""
        active = len(self.tracker)
        if active > self.active_flows_max:
            self.active_flows_max = active

    def record_lag(self, seconds: float) -> None:
        """Time a packet spent waiting in the packet queue (queue lag)."""
        ms = max(0.0, seconds * 1000.0)
        self._lag_ms += self.EMA_ALPHA * (ms - self._lag_ms)
        if ms > self._lag_max_ms:
            self._lag_max_ms = ms

    def record_inference(self, seconds: float) -> None:
        """Wall-clock cost of scoring one flow (inference latency)."""
        ms = max(0.0, seconds * 1000.0)
        self._infer_ms += self.EMA_ALPHA * (ms - self._infer_ms)
        if ms > self._infer_max_ms:
            self._infer_max_ms = ms
        self._infer_reservoir.observe(ms)
        self.inference_ops += 1

    def limits(self) -> dict:
        return {
            "packet_queue": self.config.packet_queue_size,
            "flow_queue": self.config.flow_queue_size,
            "publish_queue": self.config.publish_queue_size,
            "active_flows": self.config.max_active_flows,
            "flow_packets": self.config.flow_max_packets,
            "flow_lifetime_s": self.config.flow_max_lifetime,
            "idle_timeout_s": self.idle_timeout,
        }

    def snapshot(self, packets_total: int, settled: bool = False) -> dict:
        """One coherent telemetry sample.

        ``settled`` is used after a capture has ended: throughput decays to 0
        while every drop/latency counter keeps its final value.
        """
        pq, fq, pub = (self.packet_queue.stats(), self.flow_queue.stats(),
                       self.publish_queue.stats())
        dropped_flows = fq["dropped"] + pub["dropped"]
        infer = self._infer_reservoir.summary()
        return {
            "packet_queue": pq,
            "flow_queue": fq,
            "publish_queue": pub,
            "dropped_packets": pq["dropped"],
            "dropped_flows": dropped_flows,
            "packets_per_sec": 0.0 if settled
            else round(self._packet_rate.sample(packets_total), 2),
            "flows_per_sec": 0.0 if settled
            else round(self._flow_rate.sample(self.tracker.completed), 2),
            "processing_lag_ms": round(self._lag_ms, 3),
            "processing_lag_max_ms": round(self._lag_max_ms, 3),
            "inference_latency_ms": round(self._infer_ms, 3),
            "inference_latency_max_ms": round(self._infer_max_ms, 3),
            "inference_latency_p50_ms": infer["p50_ms"],
            "inference_latency_p95_ms": infer["p95_ms"],
            "inference_ops": self.inference_ops,
            "active_flows": len(self.tracker),
            "active_flows_max": self.active_flows_max,
            "flows_evicted": self.tracker.evicted,
            "overload": bool(pq["dropped"] or dropped_flows),
            "limits": self.limits(),
        }


def initial_stream_status(config: Config, idle_timeout: float) -> dict:
    """Zeroed ``status["pipeline"]`` block, before any capture has run."""
    empty = {"limit": 0, "policy": "", "depth": 0, "max_depth": 0,
             "offered": 0, "accepted": 0, "dropped": 0}
    return {
        "packet_queue": {**empty, "limit": config.packet_queue_size,
                         "policy": DROP_NEWEST},
        "flow_queue": {**empty, "limit": config.flow_queue_size,
                       "policy": DROP_OLDEST},
        "publish_queue": {**empty, "limit": config.publish_queue_size,
                          "policy": DROP_OLDEST},
        "dropped_packets": 0,
        "dropped_flows": 0,
        "packets_per_sec": 0.0,
        "flows_per_sec": 0.0,
        "processing_lag_ms": 0.0,
        "processing_lag_max_ms": 0.0,
        "inference_latency_ms": 0.0,
        "inference_latency_max_ms": 0.0,
        "inference_latency_p50_ms": 0.0,
        "inference_latency_p95_ms": 0.0,
        "inference_ops": 0,
        "active_flows": 0,
        "active_flows_max": 0,
        "flows_evicted": 0,
        "overload": False,
        "limits": {
            "packet_queue": config.packet_queue_size,
            "flow_queue": config.flow_queue_size,
            "publish_queue": config.publish_queue_size,
            "active_flows": config.max_active_flows,
            "flow_packets": config.flow_max_packets,
            "flow_lifetime_s": config.flow_max_lifetime,
            "idle_timeout_s": idle_timeout,
        },
    }


class StreamingPipeline:
    """The staged capture runtime: four workers over three bounded queues.

    Lifecycle is always the same, so shutdown is deterministic:

    1. ``start()`` spawns the four stage threads.
    2. ``stop()`` (or end of input) closes the source and the packet queue;
       every stage drains in order and closes the queue it feeds, so an EOF
       propagates capture -> flow -> inference -> publication.
    3. ``wait()`` joins the stages; ``abort()`` is the bounded-deadline
       escape hatch that purges pending work instead of hanging forever.

    Stage callbacks (``on_score`` / ``on_publish``) are injected by the
    application layer, so this module depends only on runtime/persistence-free
    primitives and never imports a service (no cycles).
    """

    REFRESH_INTERVAL = 0.25   # seconds between telemetry samples
    DRAIN_TIMEOUT = 30.0      # seconds to drain before a stage is forced down

    def __init__(self, *, source: CaptureSource, config: Config,
                 idle_timeout: float, stop_event: threading.Event, status: dict,
                 on_score: Callable, on_publish: Callable,
                 on_failure: Callable[[str, BaseException], None] | None = None
                 ) -> None:
        self.source = source
        self.config = config
        self.idle_timeout = idle_timeout
        self.stop_event = stop_event
        self.status = status
        self._on_score = on_score
        self._on_publish = on_publish
        self._on_failure = on_failure

        self.packet_queue = BoundedBuffer(
            "packet_queue", config.packet_queue_size, DROP_NEWEST)
        self.flow_queue = BoundedBuffer(
            "flow_queue", config.flow_queue_size, DROP_OLDEST)
        self.publish_queue = BoundedBuffer(
            "publish_queue", config.publish_queue_size, DROP_OLDEST)
        self.tracker = FlowTracker(
            idle_timeout=idle_timeout,
            max_packets=config.flow_max_packets,
            max_active_flows=config.max_active_flows,
            max_lifetime=config.flow_max_lifetime,
            on_complete=self._on_flow_complete,
        )
        self.stats = StreamStats(
            packet_queue=self.packet_queue, flow_queue=self.flow_queue,
            publish_queue=self.publish_queue, tracker=self.tracker,
            config=config, idle_timeout=idle_timeout,
        )
        self._threads: list[threading.Thread] = []
        self._started = False
        self._last_refresh = 0.0
        self.refresh(packets_total=int(status.get("packets", 0)))

    # -- lifecycle -------------------------------------------------------------

    def start(self) -> None:
        """Spawn the stage threads (idempotent)."""
        if self._started:
            return
        self._started = True
        specs = (
            ("spectra-capture", self._capture_stage),
            ("spectra-flow", self._flow_stage),
            ("spectra-infer", self._inference_stage),
            ("spectra-publish", self._publish_stage),
        )
        self._threads = [
            threading.Thread(target=fn, name=name, daemon=True)
            for name, fn in specs
        ]
        for thread in self._threads:
            thread.start()

    def stop(self) -> None:
        """Request a graceful stop: signal stages and release the source."""
        self.stop_event.set()
        try:
            self.source.close()
        except Exception as exc:  # noqa: BLE001 - closing must never raise
            log.warning("closing capture source failed: %s", exc)

    def wait(self, timeout: float) -> bool:
        """Join every stage within ``timeout``; True when all stopped."""
        deadline = time.monotonic() + timeout
        for thread in self._threads:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            thread.join(remaining)
        return not any(t.is_alive() for t in self._threads)

    def abort(self) -> None:
        """Bounded-deadline escape hatch: stop *and* purge pending work."""
        self.stop()
        for buf in (self.packet_queue, self.flow_queue, self.publish_queue):
            buf.close(purge=True)

    def threads_alive(self) -> list[str]:
        return [t.name for t in self._threads if t.is_alive()]

    # -- telemetry -------------------------------------------------------------

    def refresh(self, packets_total: int, settled: bool = False) -> None:
        """Publish a telemetry sample into ``status`` (rate-limited).

        Called by every stage worker (idle workers wake on their get
        timeout), so depths and rates stay live no matter which stage is
        busy.  Failures here can never take a stage down.
        """
        now = time.monotonic()
        if not settled and now - self._last_refresh < self.REFRESH_INTERVAL:
            return
        self._last_refresh = now
        try:
            self.status["queue"].update(self.source.stats())
            self.status["pipeline"] = self.stats.snapshot(
                packets_total, settled=settled)
        except Exception as exc:  # noqa: BLE001 - telemetry is best effort
            self._failure("telemetry", exc)

    def _failure(self, component: str, exc: BaseException) -> None:
        if self._on_failure is not None:
            try:
                self._on_failure(component, exc)
                return
            except Exception:  # noqa: BLE001 - fall back to logging
                pass
        log.error("stream stage failed: component=%s error=%s",
                  component, exc, exc_info=True)

    # -- stages ----------------------------------------------------------------

    def _capture_stage(self) -> None:
        """Read the source and enqueue packets.  Never blocks on a full
        queue: the drop is counted instead (see BoundedBuffer.put)."""
        try:
            if not self.stop_event.is_set():
                for pkt in self.source.packets():
                    if self.stop_event.is_set():
                        break
                    self.status["packets"] += 1
                    self.packet_queue.put((pkt, time.monotonic()))
                    self.refresh(int(self.status["packets"]))
        except CaptureError as exc:
            self.status["error"] = str(exc)
            log.error("capture error: %s", exc)
        except Exception as exc:  # noqa: BLE001 - keep the failure visible
            self.status["error"] = f"capture failed: {exc}"
            log.exception("capture failed")
        finally:
            self.packet_queue.close()   # EOF propagates to the flow stage
            self.refresh(int(self.status.get("packets", 0)), settled=True)

    def _flow_stage(self) -> None:
        """Packet queue -> FlowTracker -> completed-flow queue."""
        tracker = self.tracker
        bucket = self.config.bucket_seconds
        last_flush: float | None = None
        try:
            while True:
                item = self.packet_queue.get()
                if item is EOF:
                    break
                if item is None:            # idle wake-up: service telemetry
                    self.refresh(int(self.status.get("packets", 0)))
                    continue
                pkt, enqueued_at = item
                self.stats.record_lag(time.monotonic() - enqueued_at)
                try:
                    ts = float(pkt.time)
                    tracker.process(pkt, ts)
                    if last_flush is None:
                        last_flush = ts
                    elif ts - last_flush >= bucket:
                        for _ in tracker.flush_expired(ts):
                            pass    # emitted via on_complete
                        last_flush = ts
                except Exception as exc:  # noqa: BLE001 - one bad packet must
                    self._failure("flow_tracking", exc)   # not stop the stage
                self.stats.note_active_flows()
                self.refresh(int(self.status.get("packets", 0)))
        finally:
            try:
                for _ in tracker.flush_all():
                    pass        # trailing open flows -> completed-flow queue
            except Exception as exc:  # noqa: BLE001
                self._failure("flow_tracking", exc)
            self.flow_queue.close()   # EOF propagates to the inference stage
            self.refresh(int(self.status.get("packets", 0)), settled=True)

    def _inference_stage(self) -> None:
        """Completed-flow queue -> scoring (DetectionService.score_flow)."""
        try:
            while True:
                item = self.flow_queue.get()
                if item is EOF:
                    break
                if item is None:
                    self.refresh(int(self.status.get("packets", 0)))
                    continue
                started = time.monotonic()
                scored = None
                try:
                    scored = self._on_score(item)
                except Exception as exc:  # noqa: BLE001 - a failing model or
                    self._failure("inference", exc)   # module sheds this flow,
                finally:                              # not the capture
                    self.stats.record_inference(time.monotonic() - started)
                if scored is not None:
                    self.publish_queue.put(scored)
                self.refresh(int(self.status.get("packets", 0)))
        finally:
            self.publish_queue.close()   # EOF propagates to publication
            self.refresh(int(self.status.get("packets", 0)), settled=True)

    def _publish_stage(self) -> None:
        """Publication queue -> buffers, events, evidence, persistence."""
        try:
            while True:
                item = self.publish_queue.get()
                if item is EOF:
                    break
                if item is None:
                    self.refresh(int(self.status.get("packets", 0)))
                    continue
                try:
                    self._on_publish(item)
                except Exception as exc:  # noqa: BLE001 - persistence must
                    self._failure("publication", exc)   # never kill detection
                self.refresh(int(self.status.get("packets", 0)))
        finally:
            self.refresh(int(self.status.get("packets", 0)), settled=True)

    # -- helper ----------------------------------------------------------------

    def _on_flow_complete(self, flow) -> None:
        """FlowTracker.on_complete: hand a finished flow to inference."""
        self.flow_queue.put(flow)
