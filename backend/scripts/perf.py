#!/usr/bin/env python
"""Spectra performance measurement (hardening-pass verification).

Re-measures the four paths that already carry a documented baseline
(``docs/acceptance-report.md`` section 5) and adds the ones the hardening
review asked to watch that had none: flow-tracking throughput, batched
persistence, the bounded stage-queue hand-off, event-bus fan-out,
in-process API latency and the WebSocket first-message latency.

Hermetic by construction: ``SPECTRA_DATA_DIR`` and ``SPECTRA_MODEL_PATH``
are forced into a throwaway temp directory *before* the first ``spectra``
import, so a run never touches the developer's database, capture store or
model artifact.

    cd backend
    python scripts/perf.py                 # table + baseline comparison
    python scripts/perf.py --json p.json   # machine-readable copy
    python scripts/perf.py --quick         # fewer samples (smoke run)

Exit code 0 when every measurement ran, 1 when any of them raised.
Comparisons are informational: a value more than 20% above its baseline is
marked ``SLOWER`` for follow-up rather than being quietly averaged away.
"""
from __future__ import annotations

import argparse
import atexit
import json
import os
import shutil
import sys
import tempfile
import time

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP_BASE = os.path.join(BACKEND, "demo_pcaps", "baseline.pcap")
PCAP_SUSP = os.path.join(BACKEND, "demo_pcaps", "suspicious.pcap")

# -- hermetic environment: must precede every spectra import -------------------
WORK = tempfile.mkdtemp(prefix="spectra_perf_")
atexit.register(lambda: shutil.rmtree(WORK, ignore_errors=True))
os.environ["SPECTRA_DATA_DIR"] = WORK
os.environ["SPECTRA_MODEL_PATH"] = os.path.join(WORK, "spectra_model.joblib")
os.environ.setdefault("SPECTRA_ADMIN_PASSWORD", "Spectra-Perf-2026!")
os.environ.setdefault("SPECTRA_LOG_LEVEL", "WARNING")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import numpy as np  # noqa: E402  (path + env must be set first)

#: Documented baseline (docs/acceptance-report.md section 5).  ``baseline`` is
#: ``None`` where this run establishes the first number for that path; the flag
#: says whether a *rise* is an improvement (throughput) or a regression (time).
TABLE: tuple[tuple[str, str, str, str, float | None, bool], ...] = (
    ("edge micro detector p50", "ms", "edge_micro", "p50_ms", 0.0098, False),
    ("edge micro detector p95", "ms", "edge_micro", "p95_ms", 0.0189, False),
    ("main detector score p50", "ms", "detector", "score_p50_ms", 0.269, False),
    ("main detector score p95", "ms", "detector", "score_p95_ms", 0.457, False),
    ("main detector explain p50", "ms", "detector", "explain_p50_ms", 0.040, False),
    ("offline scan suspicious.pcap", "s", "scan", "seconds", 0.348, False),
    ("offline scan throughput", "pkt/s", "scan", "packets_per_s", 827.0, True),
    ("flow tracking throughput", "pkt/s", "flow_tracking", "packets_per_s", None, True),
    ("batched persistence", "rows/s", "persistence", "rows_per_s", None, True),
    ("packet-queue hand-off", "us/item", "queue", "us_per_item", None, False),
    ("event-bus fan-out", "us/event", "event_bus", "us_per_event", None, False),
    ("websocket first message p50", "ms", "api_ws", "ws_p50_ms", None, False),
)


# -- helpers --------------------------------------------------------------------

def _pct(samples: list[float], p: float) -> float:
    return round(float(np.percentile(np.asarray(samples), p)), 4)


def _timed(fn, repeats: int) -> list[float]:
    """Wall-clock milliseconds for ``repeats`` calls of ``fn``."""
    out: list[float] = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        out.append((time.perf_counter() - t0) * 1000.0)
    return out


def _flow_row(ts: float) -> tuple:
    """A flow row in exactly the shape ``FlowRepository.enqueue`` stages."""
    return (None, ts, "TCP", "10.8.0.5:51234", "10.9.0.9:443", 1.25, 24,
            4096, "TLSv1.3", "example.com", '["h2"]',
            "a" * 32, "1" * 32, 12.5, 0, None,
            json.dumps({"proto": "TCP", "packets": 24}))


# -- measurements ---------------------------------------------------------------

def bench_edge_micro(X: np.ndarray, quick: bool) -> dict:
    """MEC micro-detector per-flow scoring (12 features)."""
    from spectra.modules.edge import MicroDetector

    micro = MicroDetector()
    fit = micro.fit(X)
    out = micro.benchmark(X, repeats=10 if quick else 50)
    if not out.get("available"):
        raise RuntimeError("micro detector benchmark unavailable")
    return {"train_rows": fit["n_train"], "n": out["n"],
            "p50_ms": out["p50_ms"], "p95_ms": out["p95_ms"],
            "budget_ms": out["budget_ms"],
            "within_budget": out["within_budget"]}


def bench_detector(X: np.ndarray, quick: bool) -> dict:
    """Main Isolation-Forest inference: score() + explain() per flow."""
    from spectra.api.runtime import engine

    detector = engine.model.detector
    if not detector.is_trained:
        raise RuntimeError("detector is not trained")
    detector.score(X[:1])          # warm the per-tree fast path
    detector.explain(X[0])

    samples: list[float] = []
    pass_p50: list[float] = []
    for _ in range(10 if quick else 100):
        batch: list[float] = []
        for i in range(len(X)):
            t0 = time.perf_counter()
            detector.score(X[i:i + 1])      # single-row = the ingest shape
            batch.append((time.perf_counter() - t0) * 1000.0)
        samples.extend(batch)
        pass_p50.append(_pct(batch, 50))
    explains = _timed(lambda: detector.explain(X[0], top=3),
                      50 if quick else 300)
    p50 = _pct(samples, 50)
    return {"n": len(samples),
            "score_p50_ms": p50, "score_p95_ms": _pct(samples, 95),
            # min and median-of-pass-p50 are robust to a single slow pass
            # (background load / CPU clock); p50 stays the comparable figure.
            "score_min_ms": round(float(min(samples)), 4),
            "score_pass_p50_ms": round(float(np.median(pass_p50)), 4),
            "inference_per_s": round(1000.0 / p50) if p50 > 0 else 0,
            "explain_p50_ms": _pct(explains, 50),
            "explain_min_ms": round(float(min(explains)), 4),
            "explain_p95_ms": _pct(explains, 95)}


def bench_scan() -> dict:
    """End-to-end offline scan: read every packet, score, publish, persist."""
    from spectra.api.runtime import engine

    detections: list = []
    unsubscribe = engine.subscribe(
        lambda ev: detections.append(ev) if ev.get("type") == "detection"
        else None)
    packets0 = int(engine.status.get("packets") or 0)
    flows0 = int(engine.status.get("flows") or 0)
    try:
        t0 = time.perf_counter()
        engine.start("pcap", path=PCAP_SUSP)
        while engine.running:
            time.sleep(0.02)
        elapsed = time.perf_counter() - t0
    finally:
        unsubscribe()
    packets = int(engine.status.get("packets") or 0) - packets0
    flows = int(engine.status.get("flows") or 0) - flows0
    return {"seconds": round(elapsed, 3), "packets": packets, "flows": flows,
            "detections": len(detections),
            "packets_per_s": round(packets / elapsed) if elapsed > 0 else 0}


def bench_flow_tracking(quick: bool) -> dict:
    """FlowTracker packet->flow throughput (the hot path of ingest)."""
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    from spectra.parse.flow import FlowTracker

    n_flows = 50 if quick else 200
    pool: list = []

    def _parsed(pkt):
        """Parse back from the wire image.

        A capture source hands the tracker packets whose ``IP.len`` and payload
        bytes are already filled in; rebuilding checksums for every packet would
        time scapy's builder instead of the flow tracker.
        """
        return Ether(bytes(pkt))

    for i in range(n_flows):
        sport = 40000 + i
        c2s = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        s2c = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
        pool.extend((
            _parsed(c2s / IP(src="10.8.0.1", dst="10.9.0.1")
                    / TCP(sport=sport, dport=443, flags="S", seq=1)),
            _parsed(s2c / IP(src="10.9.0.1", dst="10.8.0.1")
                    / TCP(sport=443, dport=sport, flags="SA",
                          seq=1000, ack=2)),
            _parsed(c2s / IP(src="10.8.0.1", dst="10.9.0.1")
                    / TCP(sport=sport, dport=443, flags="A", seq=2, ack=1001)),
            _parsed(c2s / IP(src="10.8.0.1", dst="10.9.0.1")
                    / TCP(sport=sport, dport=443, flags="PA", seq=2, ack=1001)
                    / Raw(load=b"x" * 64)),
        ))

    packets = 10_000 if quick else 50_000
    tracker = FlowTracker()
    t0 = time.perf_counter()
    ts = 1_700_000_000.0
    for i in range(packets):
        tracker.process(pool[i % len(pool)], ts)
        ts += 0.0002        # 10 s of traffic: well inside the 30 s idle timeout
    elapsed = time.perf_counter() - t0
    active = len(tracker)
    completed = len(list(tracker.flush_all()))
    return {"packets": packets, "seconds": round(elapsed, 3),
            "packets_per_s": round(packets / elapsed),
            "active_flows": active, "completed_flows": completed}


def bench_persistence(quick: bool) -> dict:
    """WriteBuffer commit throughput (staged rows -> one transaction)."""
    from spectra.api.runtime import cfg
    from spectra.db.batch import WriteBuffer
    from spectra.store import Store

    rows = 2_000 if quick else 10_000
    store = Store(os.path.join(WORK, "perf_write.db"))
    try:
        buffer = WriteBuffer(store._db, batch_size=cfg.db_batch_size,
                             flush_interval=0.0)
        base = time.time()
        t0 = time.perf_counter()
        for i in range(rows):
            buffer.add("flows", _flow_row(base + i * 0.001))
        committed = buffer.flush()
        elapsed = time.perf_counter() - t0
        written = int(store._db.query(
            "SELECT COUNT(*) AS n FROM flows")[0]["n"])
        if written != rows or committed > rows:
            raise RuntimeError(
                f"staged {rows} rows but {written} landed "
                f"(final batch {committed})")
        return {"rows": rows, "seconds": round(elapsed, 3),
                "rows_per_s": round(rows / elapsed),
                "batch_size": cfg.db_batch_size,
                "transactions": buffer.flush_count}
    finally:
        store.close()


def bench_queue(quick: bool) -> dict:
    """Bounded stage-queue hand-off (put + get round trip)."""
    import queue as queue_mod

    from spectra.api.runtime import cfg

    items = 50_000 if quick else 200_000
    handoff: queue_mod.Queue = queue_mod.Queue(
        maxsize=cfg.packet_queue_size)
    payload = b"x" * 64
    t0 = time.perf_counter()
    for _ in range(items):
        handoff.put(payload)
        handoff.get()
    elapsed = time.perf_counter() - t0
    return {"items": items, "seconds": round(elapsed, 3),
            "items_per_s": round(items / elapsed),
            "us_per_item": round(elapsed / items * 1e6, 4),
            "maxsize": handoff.maxsize}


def bench_event_bus(quick: bool) -> dict:
    """Publish->subscriber fan-out for the highest-volume event type.

    ``flow`` events skip the persistence listener (``_persist_event`` ignores
    flow/detection/alert rows - their durable copy is the flows table), so this
    times the bus and its listeners, not a database write.
    """
    from spectra.api.runtime import engine

    events = 5_000 if quick else 20_000
    seen: list = []
    errors0 = int(engine.events.listener_errors)
    unsubscribe = engine.subscribe(seen.append)
    listeners = engine.events.subscriber_count
    payload = {"type": "flow", "data": {"proto": "TCP", "packets": 4}}
    try:
        t0 = time.perf_counter()
        for _ in range(events):
            engine.events.emit(payload)
        elapsed = time.perf_counter() - t0
    finally:
        unsubscribe()
    if len(seen) != events:
        raise RuntimeError(f"bus dropped events: {len(seen)}/{events}")
    errors = int(engine.events.listener_errors) - errors0
    if errors:
        raise RuntimeError(f"{errors} listener errors during the run")
    return {"events": events, "seconds": round(elapsed, 3),
            "events_per_s": round(events / elapsed),
            "us_per_event": round(elapsed / events * 1e6, 4),
            "listeners": listeners}


class _LifespanFree:
    """ASGI wrapper that answers the lifespan protocol itself.

    ``TestClient`` only keeps its portal (and therefore the request path) warm
    inside ``with client:`` - but entering that context runs the app lifespan,
    whose shutdown half closes the store.  This wrapper completes startup and
    shutdown without delegating, so requests can be timed warm while the
    runtime is left exactly as it was.
    """

    def __init__(self, inner) -> None:
        self._inner = inner

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "lifespan":
            await self._inner(scope, receive, send)
            return
        while True:
            kind = (await receive()).get("type")
            if kind == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif kind == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return


def bench_api_ws(quick: bool) -> dict:
    """In-process API latency and WebSocket first-message latency.

    TestClient runs the ASGI app in-process (no socket), so these numbers are
    the request handling itself - route, auth gate, store - plus the httpx
    client's own marshalling, not network cost.
    """
    from fastapi.testclient import TestClient

    from spectra.api.app import app
    from spectra.api.runtime import cfg

    client = TestClient(_LifespanFree(app))
    with client:
        username = os.environ.get("SPECTRA_ADMIN_USERNAME") or cfg.admin_username
        login = client.post("/api/auth/login", json={
            "username": username,
            "password": os.environ["SPECTRA_ADMIN_PASSWORD"]})
        if login.status_code != 200:
            raise RuntimeError(f"admin login failed: "
                               f"{login.status_code} {login.text}")

        paths = ("/api/status", "/api/stats", "/api/capabilities",
                 "/api/health", "/api/history/flows?limit=100")
        repeats = 10 if quick else 30
        endpoints: dict[str, dict] = {}
        for path in paths:
            warm = client.get(path)
            if warm.status_code != 200:
                raise RuntimeError(f"{path} -> {warm.status_code} "
                                   f"{warm.text[:120]}")
            samples = _timed(lambda p=path: client.get(p), repeats)
            endpoints[path] = {"n": repeats, "p50_ms": _pct(samples, 50),
                               "p95_ms": _pct(samples, 95)}

        ws_samples: list[float] = []
        for _ in range(2 if quick else 5):
            t0 = time.perf_counter()
            with client.websocket_connect("/ws/events") as ws:
                ws.receive_json()
            ws_samples.append((time.perf_counter() - t0) * 1000.0)

    return {"endpoints": endpoints,
            "ws_p50_ms": _pct(ws_samples, 50),
            "ws_p95_ms": _pct(ws_samples, 95),
            "ws_n": len(ws_samples)}


# -- reporting ------------------------------------------------------------------

def report(results: dict, errors: dict) -> None:
    print()
    print(f"  {'metric':<32}{'unit':>9}{'baseline':>12}{'measured':>14}{'delta':>16}")
    print("  " + "-" * 83)
    for label, unit, section, key, baseline, higher_is_better in TABLE:
        measured = (results.get(section) or {}).get(key)
        if measured is None:
            continue
        base = f"{baseline:g}" if baseline is not None else "-"
        val = f"{measured:.4f}" if isinstance(measured, float) else f"{measured:g}"
        if baseline:
            delta = (float(measured) - baseline) / baseline * 100.0
            delta_s = f"{delta:+.1f}%"
            regressed = delta > 20.0 if not higher_is_better else delta < -20.0
            if regressed:
                delta_s += " SLOWER"
        else:
            delta_s = "new"
        print(f"  {label:<32}{unit:>9}{base:>12}{val:>14}{delta_s:>16}")

    print("\n  notes:")
    print("    - API/WebSocket figures are in-process (TestClient, no socket);"
          " they measure\n      route + auth + store work, not network cost.")
    print("    - the scan is timed around the pipeline only; `spectra scan` also pays"
          "\n      interpreter + model load + a 0.2 s completion poll (cli.py), so a"
          "\n      negative delta against the 0.348 s CLI baseline is expected.")
    print("    - the sub-millisecond rows (edge/score/explain) move by roughly +-30%"
          "\n      between passes on a desktop (background load, CPU clock); a delta"
          "\n      inside that band is run-to-run noise - compare several runs.")

    scan = results.get("scan") or {}
    if scan:
        print(f"\n  scan detail: {scan.get('packets')} packets -> "
              f"{scan.get('flows')} flows, {scan.get('detections')} "
              f"detections, {scan.get('seconds')} s end to end")
    edge = results.get("edge_micro") or {}
    if edge:
        print(f"  edge budget: p95 {edge.get('p95_ms')} ms vs "
              f"{edge.get('budget_ms')} ms "
              f"({'within' if edge.get('within_budget') else 'OVER'} budget)")
    det = results.get("detector") or {}
    if det:
        print(f"  detector timing detail: n={det.get('n')} "
              f"p50 {det.get('score_p50_ms')} ms, "
              f"median-of-pass p50 {det.get('score_pass_p50_ms')} ms, "
              f"min {det.get('score_min_ms')} ms")

    api = results.get("api_ws") or {}
    if api.get("endpoints"):
        print("\n  API latency (in-process TestClient):")
        for path, stats in api["endpoints"].items():
            print(f"    {path:<34} n={stats['n']:<3} p50 {stats['p50_ms']:.3f} ms"
                  f"   p95 {stats['p95_ms']:.3f} ms")
        print(f"\n  WebSocket first message: p50 {api['ws_p50_ms']:.3f} ms"
              f"  p95 {api['ws_p95_ms']:.3f} ms  (n={api['ws_n']})")

    train = results.get("train") or {}
    if train:
        print(f"\n  offline training of baseline.pcap: {train.get('seconds')} s"
              f" ({train.get('flows')} flows -> {train.get('features')} features)")

    if errors:
        print("\n  ERRORS:")
        for name, detail in errors.items():
            print(f"    {name}: {detail}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Spectra performance measurement")
    parser.add_argument("--json", help="write the raw measurements to this file")
    parser.add_argument("--quick", action="store_true",
                        help="smaller sample counts (smoke run)")
    args = parser.parse_args()

    quick = bool(args.quick)
    results: dict[str, dict] = {}
    errors: dict[str, str] = {}

    def run(name: str, fn) -> None:
        t0 = time.perf_counter()
        try:
            results[name] = fn()
        except Exception as exc:  # noqa: BLE001 - report, then fail at the end
            errors[name] = f"{type(exc).__name__}: {exc}"
            return
        results[name]["wall_s"] = round(time.perf_counter() - t0, 2)

    # shared inputs: the baseline capture drives training, the edge model and
    # the per-flow inference timing
    from spectra.api.runtime import cfg, engine  # noqa: F401
    from spectra.features.extractor import flows_to_matrix
    from spectra.tools import collect_flows

    flows = collect_flows(PCAP_BASE)
    if len(flows) < 10:
        raise SystemExit(f"baseline capture yielded {len(flows)} flows - "
                         f"need >= 10 to train")
    X = flows_to_matrix(flows)

    t0 = time.perf_counter()
    try:
        engine.train_from_pcap(PCAP_BASE, contamination=0.05)
        results["train"] = {"seconds": round(time.perf_counter() - t0, 2),
                            "flows": int(len(flows)),
                            "features": int(X.shape[1])}
    except Exception as exc:  # noqa: BLE001
        errors["train"] = f"{type(exc).__name__}: {exc}"

    run("edge_micro", lambda: bench_edge_micro(X, quick))
    run("detector", lambda: bench_detector(X, quick))
    run("scan", bench_scan)
    run("flow_tracking", lambda: bench_flow_tracking(quick))
    run("persistence", lambda: bench_persistence(quick))
    run("queue", lambda: bench_queue(quick))
    run("event_bus", lambda: bench_event_bus(quick))
    run("api_ws", lambda: bench_api_ws(quick))

    print(f"Spectra performance measurement  (data dir: {WORK})")
    report(results, errors)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"results": results, "errors": errors},
                      fh, indent=2, default=str)
        print(f"\n  wrote {args.json}")

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
