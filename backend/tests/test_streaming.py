"""Streaming-runtime tests: bounded stages, overload, shutdown, isolation.

The staged runtime (capture -> packet queue -> flow processing -> completed
flow queue -> inference -> persistence/publication) must stay *passive* and
predictable under load:

* every queue is bounded and its overload policy is explicit,
* overload drops are counted - never silent - and never block acquisition,
* every stage thread stops on shutdown (including mid-capture),
* a slow or failing downstream stage degrades only its own stage.
"""

from __future__ import annotations

import random
import threading
import time

import pytest
from scapy.layers.inet import IP, TCP

from spectra.config import Config
from spectra.demo import BASE, make_baseline_pcap, tls_flow_packets, write_pcap
from spectra.pipeline import SpectraEngine
from spectra.streaming import DROP_NEWEST, DROP_OLDEST, EOF, BoundedBuffer, RateMeter

QUEUE_KEYS = {"limit", "policy", "depth", "max_depth", "offered", "accepted",
              "dropped"}


# -- helpers ------------------------------------------------------------------


def _engine(tmp_path, **cfg_kwargs) -> SpectraEngine:
    """Hermetic engine: fresh config limits, no persistence, no ambient model."""
    return SpectraEngine(config=Config(**cfg_kwargs),
                         model_path=str(tmp_path / "m.joblib"), persist=False)


def _wait(engine: SpectraEngine, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while engine.running and time.time() < deadline:
        time.sleep(0.02)
    assert not engine.running, "capture did not finish in time"


def _syn(port: int, ts: float, src: str = "10.9.0.1", dst: str = "10.9.0.2"):
    pkt = IP(src=src, dst=dst) / TCP(sport=port, dport=443, flags="S", seq=1000)
    pkt.time = ts
    return pkt


def _burst_pcap(path: str, n_flows: int = 30) -> str:
    """TLS conversations that all overlap in time (worst case for the table)."""
    pkts = []
    for i in range(n_flows):
        pkts += tls_flow_packets(src="10.8.0.1", sport=47000 + i,
                                 sni="burst.test", n_data=3,
                                 start=BASE + i * 0.05,
                                 jitter=random.Random(i))
    pkts.sort(key=lambda p: float(p.time))
    return write_pcap(path, pkts)


class _EndlessSource:
    """Fake live source: synthetic packets until closed (never touches a NIC)."""

    name = "endless"

    def __init__(self) -> None:
        self._closed = threading.Event()
        self._n = 0

    def packets(self):
        while not self._closed.is_set():
            pkt = IP(src="10.7.0.1", dst="10.7.0.2") / TCP(
                sport=48000 + self._n % 500, dport=443, flags="A", seq=self._n)
            pkt.time = time.time()
            self._n += 1
            yield pkt
            time.sleep(0.001)

    def stats(self) -> dict:
        return {"packets_received": self._n, "packets_queued": 0,
                "packets_dropped": 0, "queue_depth": 0, "max_queue_depth": 0}

    def close(self) -> None:
        self._closed.set()


# -- bounded buffer (the overload contract) ------------------------------------


def test_bounded_buffer_drop_newest_refuses_excess():
    buf = BoundedBuffer("t", 3, DROP_NEWEST)
    results = [buf.put(i) for i in range(5)]
    assert results == [True, True, True, False, False]   # never blocks
    assert buf.stats() == {"limit": 3, "policy": DROP_NEWEST, "depth": 3,
                           "max_depth": 3, "offered": 5, "accepted": 3,
                           "dropped": 2}
    assert [buf.get(timeout=0.01) for _ in range(3)] == [0, 1, 2]
    assert buf.get(timeout=0.01) is None     # timeout, stream still open


def test_bounded_buffer_drop_oldest_keeps_freshest():
    buf = BoundedBuffer("t", 3, DROP_OLDEST)
    for i in range(5):
        assert buf.put(i)
    assert buf.dropped == 2 and buf.qsize == 3
    assert [buf.get(timeout=0.01) for _ in range(3)] == [2, 3, 4]


def test_bounded_buffer_eof_only_once_closed_and_drained():
    buf = BoundedBuffer("t", 2, DROP_NEWEST)
    buf.put("a")
    buf.close()
    assert buf.get(timeout=0.01) == "a"
    assert buf.get(timeout=0.01) is EOF      # closed *and* drained
    assert buf.put("late") is False          # closed: refused, not queued
    buf.close()                              # idempotent
    assert buf.get(timeout=0.01) is EOF
    st = buf.stats()
    assert st["offered"] == 2 and st["accepted"] == 1 and st["dropped"] == 1
    assert st["accepted"] + st["dropped"] == st["offered"]   # conservation


def test_bounded_buffer_purge_counts_pending_work():
    buf = BoundedBuffer("t", 4, DROP_OLDEST)
    for i in range(3):
        buf.put(i)
    buf.close(purge=True)
    assert buf.stats() == {"limit": 4, "policy": DROP_OLDEST, "depth": 0,
                           "max_depth": 3, "offered": 3, "accepted": 0,
                           "dropped": 3}


def test_bounded_buffer_rejects_invalid_configuration():
    with pytest.raises(ValueError):
        BoundedBuffer("nope", 0)
    with pytest.raises(ValueError):
        BoundedBuffer("nope", 4, "evict_randomly")


def test_rate_meter_rates_decays_and_rebaselines():
    meter = RateMeter()
    assert meter.sample(0) == 0.0
    time.sleep(0.6)
    assert meter.sample(30) == pytest.approx(50.0, rel=0.3)
    time.sleep(0.6)
    assert meter.sample(30) == 0.0           # counter stopped -> decays to 0
    assert meter.sample(5) == 0.0            # counter reset -> re-baseline


# -- flow-table limits ---------------------------------------------------------


def test_flow_tracker_caps_active_flows_and_evicts_least_recently_seen():
    from spectra.parse.flow import FlowTracker

    emitted: list = []
    tracker = FlowTracker(idle_timeout=30.0, on_complete=emitted.append,
                          max_active_flows=3)
    base = BASE
    for port in (5000, 5001, 5002):
        tracker.process(_syn(port, base + 1), base + 1)
    assert len(tracker) == 3 and tracker.evicted == 0

    tracker.process(_syn(5001, base + 2), base + 2)   # re-touch flow 5001
    tracker.process(_syn(5003, base + 3), base + 3)   # table full -> evict LRU

    assert tracker.evicted == 1
    assert len(tracker) <= 3                          # hard memory bound
    assert [f.src_port for f in emitted] == [5000]    # evicted, not discarded
    assert emitted[0].packets_fwd == 1                # and still observable


def test_flow_tracker_max_lifetime_forces_completion():
    from spectra.parse.flow import FlowTracker

    emitted: list = []
    tracker = FlowTracker(idle_timeout=60.0, max_lifetime=10.0,
                          on_complete=emitted.append)
    tracker.process(_syn(5000, BASE), BASE)
    assert list(tracker.flush_expired(BASE + 5.0)) == []   # young + active
    assert tracker.evicted == 0 and len(tracker) == 1

    out = list(tracker.flush_expired(BASE + 11.0))
    assert len(out) == 1 and len(tracker) == 0
    assert tracker.evicted == 1        # ended by the lifetime limit, not idleness
    assert len(emitted) == 1


def test_flow_tracker_per_flow_packet_budget_is_kept():
    from spectra.parse.flow import FlowTracker

    tracker = FlowTracker(max_packets=3)
    ts = BASE
    for seq in range(6):
        tracker.process(_syn(5000, ts), ts)
        ts += 1
    flow = next(iter(tracker.flush_all()))
    assert len(flow.packets) == 3       # metadata budget respected
    assert flow.truncated is True


# -- overload behaviour --------------------------------------------------------


def test_packet_queue_saturation_is_bounded_and_counted(tmp_path, monkeypatch):
    """A consumer slower than the source must shed packets, measurably."""
    import spectra.streaming as streaming
    from spectra.parse.flow import FlowTracker as RealFlowTracker

    class SlowFlowTracker(RealFlowTracker):
        """Deterministic slow consumer, so the packet queue really fills up."""

        def process(self, pkt, ts=None):  # noqa: ANN001 - scapy packet
            time.sleep(0.002)
            return super().process(pkt, ts)

    monkeypatch.setattr(streaming, "FlowTracker", SlowFlowTracker)

    pcap = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=8)
    engine = _engine(tmp_path, packet_queue_size=4)
    engine.start("pcap", path=pcap)
    _wait(engine)

    assert engine.status["error"] is None
    st = engine.status["pipeline"]
    pq = st["packet_queue"]
    assert pq["limit"] == 4 and pq["policy"] == DROP_NEWEST
    assert pq["max_depth"] <= 4                  # bounded: memory stays flat
    assert pq["dropped"] > 0                     # overload visible, not silent
    assert st["dropped_packets"] == pq["dropped"]
    assert st["overload"] is True
    assert pq["offered"] == engine.status["packets"]
    assert pq["accepted"] + pq["dropped"] == pq["offered"]
    assert engine.status["flows"] >= 1           # detection still made progress
    assert engine.capture.pipeline.threads_alive() == []


def test_many_simultaneous_flows_stay_bounded(tmp_path):
    pcap = _burst_pcap(str(tmp_path / "burst.pcap"), n_flows=30)
    engine = _engine(tmp_path, max_active_flows=5, flow_queue_size=256)
    engine.start("pcap", path=pcap)
    _wait(engine)

    assert engine.status["error"] is None
    st = engine.status["pipeline"]
    assert st["active_flows"] <= 5              # table never over the cap
    assert st["active_flows_max"] <= 5           # including the high-water mark
    assert st["flows_evicted"] > 0               # pressure shed explicitly
    assert st["flow_queue"]["max_depth"] <= 256  # completed-flow queue bounded
    assert st["dropped_flows"] == 0              # queue sized for the burst
    assert engine.status["flows"] >= 30          # every flow still got scored


# -- graceful shutdown ---------------------------------------------------------


def test_shutdown_during_capture_stops_every_stage(tmp_path, monkeypatch):
    import spectra.services.capture as capture_mod

    source = _EndlessSource()
    monkeypatch.setattr(capture_mod, "open_source", lambda *a, **k: source)

    engine = _engine(tmp_path)
    engine.start("live", iface="fake0")
    deadline = time.time() + 10
    while engine.status["packets"] < 20 and time.time() < deadline:
        time.sleep(0.01)
    assert engine.status["packets"] >= 20, "fake source produced no packets"

    started = time.time()
    engine.stop()
    elapsed = time.time() - started

    assert elapsed < 5.0                        # stop() is bounded
    assert not engine.running
    assert engine.status["running"] is False
    assert engine.status["error"] is None
    assert engine.capture.pipeline.threads_alive() == []
    assert source._closed.is_set()              # source released

    # the session was closed out properly (evidence written to the audit log)
    kinds = {e["kind"] for e in engine.audit_entries(limit=20)["items"]}
    assert {"capture.start", "capture.stop"} <= kinds

    engine.stop()                               # a second stop is a no-op
    assert not engine.running


def test_stop_immediately_after_start_is_safe(tmp_path, monkeypatch):
    """stop() racing start() must not leave a stage thread behind."""
    import spectra.services.capture as capture_mod

    source = _EndlessSource()
    monkeypatch.setattr(capture_mod, "open_source", lambda *a, **k: source)

    engine = _engine(tmp_path)
    engine.start("live", iface="fake0")
    engine.stop()

    assert not engine.running
    assert engine.status["running"] is False
    assert engine.status["error"] is None
    assert engine.capture.pipeline.threads_alive() == []


# -- stage isolation -----------------------------------------------------------


def test_slow_persistence_does_not_slow_inference(tmp_path):
    from spectra.store import Store

    pcap = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=10)
    store = Store(str(tmp_path / "store.db"))
    engine = SpectraEngine(model_path=str(tmp_path / "m.joblib"), store=store)
    real_save = store.save_flow
    calls: list = []

    def slow_save(*args, **kwargs):
        time.sleep(0.15)
        calls.append(1)
        return real_save(*args, **kwargs)

    store.save_flow = slow_save          # instance attr shadows the method
    engine.start("pcap", path=pcap)
    _wait(engine)

    assert engine.status["error"] is None
    st = engine.status["pipeline"]
    assert engine.status["flows"] >= 10
    assert len(calls) >= 10              # every flow was still persisted
    assert st["dropped_flows"] == 0      # the queue absorbed the slowness
    assert st["publish_queue"]["max_depth"] > 0   # backlog queued, not inline
    # the delay lived in the publication stage: inference stayed fast
    assert st["inference_latency_max_ms"] < 100.0


def test_inference_stage_failure_is_isolated(tmp_path, monkeypatch):
    pcap = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=5)
    engine = _engine(tmp_path)

    def boom(flow):  # noqa: ANN001
        raise RuntimeError("simulated inference outage")

    monkeypatch.setattr(engine.detection, "score_flow", boom)
    engine.start("pcap", path=pcap)
    _wait(engine)

    assert engine.status["error"] is None        # capture survived
    assert engine.status["flows"] == 0           # nothing was scored
    assert engine.status["failures"].get("inference", 0) >= 1
    assert engine.capture.pipeline.threads_alive() == []


def test_publication_stage_failure_is_isolated(tmp_path, monkeypatch):
    pcap = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=5)
    engine = _engine(tmp_path)

    def boom(scored):  # noqa: ANN001
        raise RuntimeError("simulated persistence outage")

    monkeypatch.setattr(engine.detection, "publish_flow", boom)
    engine.start("pcap", path=pcap)
    _wait(engine)

    assert engine.status["error"] is None
    assert engine.status["flows"] >= 5           # inference kept working
    assert engine.status["failures"].get("publication", 0) >= 1
    assert len(engine.detection.flows) == 0      # nothing half-published
    assert engine.status["detections"] == 0


# -- telemetry -----------------------------------------------------------------


def test_stream_telemetry_is_published_and_scrapable(tmp_path):
    pcap = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=6)
    engine = _engine(tmp_path, packet_queue_size=1024)

    before = engine.status["pipeline"]            # present before any capture
    assert before["limits"]["packet_queue"] == 1024
    assert before["dropped_packets"] == 0 and before["overload"] is False

    engine.start("pcap", path=pcap)
    _wait(engine)

    st = engine.status["pipeline"]
    for key in ("packet_queue", "flow_queue", "publish_queue",
                "dropped_packets", "dropped_flows", "packets_per_sec",
                "flows_per_sec", "processing_lag_ms", "inference_latency_ms",
                "inference_ops", "active_flows", "active_flows_max",
                "flows_evicted", "overload", "limits"):
        assert key in st, key

    for name in ("packet_queue", "flow_queue", "publish_queue"):
        stage = st[name]
        assert set(stage) == QUEUE_KEYS
        assert stage["depth"] == 0                            # fully drained
        assert stage["accepted"] + stage["dropped"] == stage["offered"]
        assert stage["policy"] in (DROP_NEWEST, DROP_OLDEST)

    assert st["dropped_packets"] == 0        # file source: no overload
    assert st["dropped_flows"] == 0
    assert st["overload"] is False
    assert st["inference_ops"] >= 1
    assert st["processing_lag_ms"] >= 0.0
    assert st["packets_per_sec"] == 0.0      # settled once the capture ended
    assert engine.status["queue"]["packets_dropped"] == 0

    text = engine.system.metrics()
    for name in ("spectra_packet_queue_depth", "spectra_packet_queue_dropped",
                 "spectra_flow_queue_depth", "spectra_flow_queue_dropped",
                 "spectra_publish_queue_depth", "spectra_publish_queue_dropped",
                 "spectra_packets_per_second", "spectra_flows_per_second",
                 "spectra_processing_lag_ms", "spectra_inference_latency_ms",
                 "spectra_active_flows", "spectra_active_flows_max",
                 "spectra_flow_evictions", "spectra_flows_dropped",
                 "spectra_stream_overload"):
        assert f"{name} " in text, name
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        sample, sep, value = line.rpartition(" ")
        assert sep == " " and sample, line
        float(value)
