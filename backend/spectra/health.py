"""Operational health model: states, thresholds, telemetry helpers, evaluators.

Pure stdlib module - no engine, service or FastAPI imports - so every health
decision is unit-testable in isolation and ``spectra.db`` /
``spectra.services`` can import the telemetry helpers without cycles.

Subsystem states (one per subsystem in the report):

``HEALTHY``
    Functional; the subsystem is operating within its thresholds.
``DEGRADED``
    Functional but outside a threshold (drops, saturation, latency,
    recent failures). The entry's ``reason`` says which threshold and
    what was observed.
``UNAVAILABLE``
    Not functional right now (no model, no database, disabled module).
``SIMULATED``
    Working exactly as designed, but the underlying integration is a
    local simulation (never hardware-backed / never a real MEC). This is
    informational - a simulated subsystem that starts failing reports
    ``DEGRADED``/``UNAVAILABLE`` instead, so "by design" never masks an
    actual problem.

The overall rollup severity is ``HEALTHY < SIMULATED < DEGRADED <
UNAVAILABLE``: a fleet that only differs by design simulations rolls up
as ``SIMULATED``, never as a failure.
"""

from __future__ import annotations

import math
import threading
import time
from collections import Counter, deque
from typing import Mapping, Sequence

HEALTHY = "HEALTHY"
DEGRADED = "DEGRADED"
UNAVAILABLE = "UNAVAILABLE"
SIMULATED = "SIMULATED"

#: All four states, ordered by rollup severity (worst last).
STATES: tuple[str, ...] = (HEALTHY, SIMULATED, DEGRADED, UNAVAILABLE)
SEVERITY: dict[str, int] = {state: i for i, state in enumerate(STATES)}

# -- thresholds (single source of truth for every DEGRADED rule) ---------------

#: Stage/flow-table utilisation at which a queue counts as saturated.
QUEUE_SATURATION = 0.80
FLOW_SATURATION = 0.80
#: Packet drop ratio (dropped / seen) above which capture is degraded.
DROP_RATIO = 0.001
#: Scoring latency budget: p95 above this marks inference degraded.
INFERENCE_P95_MS = 50.0
#: Database write latency budget: p95 above this marks the store degraded.
DB_WRITE_P95_MS = 100.0
#: Packet-to-stage processing lag budget (EMA, milliseconds).
LAG_MS = 500.0
#: Cached PSI drift levels treated as degraded input distribution.
DRIFT_LEVELS: tuple[str, ...] = ("moderate", "significant")

#: Ordered subsystem registry: stable machine name -> display title.
#: The report always contains every entry, healthy or not; it is also the
#: single source of truth for titles (``entry`` looks them up).
SUBSYSTEMS: tuple[tuple[str, str], ...] = (
    ("capture", "Capture engine"),
    ("flow_tracker", "Flow tracker"),
    ("tls_parser", "TLS parser"),
    ("quic_parser", "QUIC parser"),
    ("inference", "Inference engine"),
    ("model", "Active model"),
    ("database", "Database"),
    ("events", "WebSocket / event bus"),
    ("audit", "Audit chain"),
    ("pqc", "PQC module"),
    ("bio", "Bio module"),
    ("tee", "TEE module"),
    ("edge", "Edge module"),
    ("twin", "Digital twin"),
)

_TITLES: dict[str, str] = dict(SUBSYSTEMS)


def entry(subsystem: str, state: str, reason: str,
          evidence: Mapping[str, object]) -> dict:
    """One subsystem health record: why, in what state, with what numbers."""
    if state not in SEVERITY:
        raise ValueError(f"unknown health state: {state!r}")
    if subsystem not in _TITLES:
        raise ValueError(f"unknown subsystem: {subsystem!r}")
    return {
        "name": subsystem,
        "title": _TITLES[subsystem],
        "state": state,
        "reason": reason,
        "evidence": dict(evidence),
    }


def overall(entries: Sequence[Mapping]) -> tuple[str, str, dict[str, int]]:
    """Roll subsystem states up to one state + a reason listing offenders."""
    counts = Counter(str(e["state"]) for e in entries)
    for state in STATES:
        counts.setdefault(state, 0)
    if not entries:
        return UNAVAILABLE, "no subsystems reported", dict(counts)
    worst = max(entries, key=lambda e: SEVERITY[str(e["state"])])
    state = str(worst["state"])
    if state == HEALTHY:
        return HEALTHY, f"all {len(entries)} subsystems healthy", dict(counts)
    offenders = [e for e in entries if e["state"] == state]
    titles = ", ".join(str(e["title"]) for e in offenders[:3])
    if len(offenders) > 3:
        titles += f" and {len(offenders) - 3} more"
    if state == SIMULATED:
        return (SIMULATED,
                f"{len(offenders)} subsystem(s) simulated by design "
                f"({titles}); operating normally",
                dict(counts))
    return (state,
            f"{len(offenders)} subsystem(s) {state.lower()}: {titles}",
            dict(counts))


# -- telemetry helpers ---------------------------------------------------------

def percentile(values: Sequence[float], p: float) -> float | None:
    """Linear-interpolated percentile (None for an empty sample)."""
    if not values:
        return None
    data = sorted(float(v) for v in values)
    if len(data) == 1:
        return data[0]
    k = (len(data) - 1) * (p / 100.0)
    low, high = math.floor(k), math.ceil(k)
    if low == high:
        return data[int(k)]
    return data[low] + (data[high] - data[low]) * (k - low)


class LatencyReservoir:
    """Bounded ring of recent durations (ms) with percentile summaries.

    Thread-safe: producers (inference worker, database writers) and readers
    (health/metrics endpoints) share one lock; ``total`` keeps counting past
    the ring so lifetime sample counts survive eviction.
    """

    def __init__(self, capacity: int = 1024) -> None:
        self._samples: deque[float] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self.total = 0

    def observe(self, ms: float) -> None:
        with self._lock:
            self._samples.append(max(0.0, float(ms)))
            self.total += 1

    def summary(self) -> dict:
        """p50/p95/mean/max over the ring plus the lifetime sample count."""
        with self._lock:
            data = list(self._samples)
            total = self.total
        if not data:
            return {"p50_ms": 0.0, "p95_ms": 0.0, "mean_ms": 0.0,
                    "max_ms": 0.0, "samples": 0, "total_samples": total}
        p50 = percentile(data, 50) or 0.0
        p95 = percentile(data, 95) or 0.0
        return {
            "p50_ms": round(p50, 3),
            "p95_ms": round(p95, 3),
            "mean_ms": round(sum(data) / len(data), 3),
            "max_ms": round(max(data), 3),
            "samples": len(data),
            "total_samples": total,
        }


class WindowRates:
    """Per-minute rates of monotonic counters between health observations.

    Rates are measured over up to ``window_s`` between consecutive reports
    (or the whole observed span when polling is sparser). A counter that
    decreases is treated as a per-capture reset and rebased on its current
    value instead of producing a negative rate.
    """

    def __init__(self, window_s: float = 60.0, capacity: int = 128) -> None:
        self.window_s = float(window_s)
        self._samples: deque[tuple[float, dict[str, float]]] = deque(
            maxlen=capacity)

    def observe(self, values: Mapping[str, float | int],
                ts: float | None = None) -> None:
        snapshot = {k: float(v) for k, v in values.items()}
        self._samples.append(
            (time.time() if ts is None else float(ts), snapshot))

    def rates(self) -> dict[str, float]:
        """Counter deltas scaled to per-minute rates ({} until 2 samples)."""
        if len(self._samples) < 2:
            return {}
        cur_ts, cur = self._samples[-1]
        base_ts, base = self._samples[0]
        for ts, values in reversed(self._samples):
            if cur_ts - ts > self.window_s:
                break
            base_ts, base = ts, values
        dt = cur_ts - base_ts
        if dt <= 0:
            return {}
        out: dict[str, float] = {}
        for key, value in cur.items():
            prev = base.get(key)
            if prev is None:
                continue
            delta = value - prev if value >= prev else value
            out[key] = round(delta / dt * 60.0, 2)
        return out


# -- subsystem evaluators ------------------------------------------------------
#
# Each evaluator is a pure function: explicit primitives in, one health entry
# out. State rules (worst first):
#   UNAVAILABLE  - the functional part is absent/disabled/broken right now
#   DEGRADED     - a threshold in THRESHOLDS was crossed or errors were seen
#   SIMULATED    - working, but by-design non-real (tee/twin)
#   HEALTHY      - otherwise (reason still carries the observed numbers)

def check_capture(*, running: bool, mode: str | None, source: str | None,
                  error: str | None, packets: int, dropped: int,
                  utilization: float, lag_ms: float) -> dict:
    """Intake health: capture errors, packet drops, queue saturation, lag."""
    ratio = (dropped / packets) if packets > 0 else 0.0
    evidence = {
        "running": running,
        "mode": mode,
        "source": source,
        "packets": packets,
        "dropped": dropped,
        "drop_ratio": round(ratio, 5),
        "queue_utilization": round(utilization, 3),
        "lag_ms": round(lag_ms, 1),
        "error": error,
    }
    if error:
        return entry("capture", DEGRADED,
                     f"capture error: {error}", evidence)
    if utilization >= QUEUE_SATURATION:
        return entry("capture", DEGRADED,
                     f"intake queue {utilization:.0%} full "
                     f"({dropped} packet(s) dropped)",
                     evidence)
    if lag_ms >= LAG_MS:
        return entry("capture", DEGRADED,
                     f"processing lag {lag_ms:.0f}ms over the "
                     f"{int(LAG_MS)}ms budget (queue backlog)",
                     evidence)
    if packets > 0 and ratio >= DROP_RATIO:
        return entry("capture", DEGRADED,
                     f"{dropped} of {packets} packets dropped "
                     f"({ratio:.2%}; budget {DROP_RATIO:.1%})",
                     evidence)
    if running:
        note = (f"; {dropped} drop(s) below threshold" if dropped else "")
        return entry("capture", HEALTHY,
                     f"{mode or 'live'} capture running on "
                     f"{source or 'source'}; {packets} packet(s){note}",
                     evidence)
    return entry("capture", HEALTHY,
                 f"idle (no capture session); {packets} packet(s) this run",
                 evidence)


def check_flow_tracker(*, active: int, limit: int, evicted: int,
                       evicted_new: int, dropped_new: int,
                       parse_errors_new: int) -> dict:
    """Flow-table health: capacity, LRU/force evictions, parse exceptions."""
    util = (active / limit) if limit > 0 else 0.0
    evidence = {
        "active": active,
        "limit": limit,
        "utilization": round(util, 3),
        "evicted": evicted,
        "evicted_new": evicted_new,
        "dropped_new": dropped_new,
        "parse_errors_new": parse_errors_new,
    }
    reasons: list[str] = []
    state = HEALTHY
    if parse_errors_new > 0:
        state = DEGRADED
        reasons.append(f"{parse_errors_new} flow-parse exception(s) "
                       f"since the previous check")
    if dropped_new > 0:
        state = DEGRADED
        reasons.append(f"{dropped_new} completed flow(s) dropped by a "
                       f"full stage queue")
    if limit > 0 and util >= FLOW_SATURATION:
        state = DEGRADED
        reasons.append(f"flow table {active}/{limit} "
                       f"({util:.0%} of cap)")
    if evicted_new > 0:
        state = DEGRADED
        reasons.append(f"{evicted_new} flow(s) force-evicted at the cap")
    if state == HEALTHY:
        reasons.append(f"{active}/{limit} active flow(s); "
                       f"{evicted} eviction(s) total")
    return entry("flow_tracker", state,
                 "; ".join(reasons), evidence)


def check_tls_parser(*, tls_flows: int, total_flows: int) -> dict:
    """TLS metadata parsing (in-process; shared flow pipeline reports its
    own exceptions under the flow tracker)."""
    evidence = {"tls_flows": tls_flows, "flows": total_flows}
    if tls_flows > 0:
        reason = f"{tls_flows} flow(s) with TLS metadata parsed"
    elif total_flows > 0:
        reason = (f"operational; no TLS handshakes observed in "
                  f"{total_flows} flow(s) yet")
    else:
        reason = "operational; idle (no flows observed yet)"
    return entry("tls_parser", HEALTHY, reason, evidence)


def check_quic_parser(*, crypto_available: bool, quic_flows: int) -> dict:
    """QUIC Initial parsing: payload decryption needs the optional
    ``cryptography`` package - without it only headers are readable."""
    evidence = {"crypto_available": crypto_available, "quic_flows": quic_flows}
    if not crypto_available:
        return entry("quic_parser", DEGRADED,
                     "cryptography package missing - QUIC header inspection "
                     "only (no Initial decryption)",
                     evidence)
    if quic_flows > 0:
        reason = f"{quic_flows} QUIC handshake(s) parsed (Initial decryption available)"
    else:
        reason = "operational; no QUIC traffic observed yet"
    return entry("quic_parser", HEALTHY, reason, evidence)


def check_inference(*, trained: bool, latency: Mapping[str, float],
                    failures_new: int) -> dict:
    """Scoring engine: availability first, then the p95 latency budget."""
    evidence = {
        "trained": trained,
        "p50_ms": latency.get("p50_ms", 0.0),
        "p95_ms": latency.get("p95_ms", 0.0),
        "ops": latency.get("ops", 0),
        "budget_p95_ms": INFERENCE_P95_MS,
        "failures_new": failures_new,
    }
    if not trained:
        return entry("inference", UNAVAILABLE,
                     "no trained model - run 'spectra train' before scoring",
                     evidence)
    if failures_new > 0:
        return entry("inference", DEGRADED,
                     f"{failures_new} scoring failure(s) since the previous "
                     f"check (affected flows were shed)",
                     evidence)
    p95 = float(latency.get("p95_ms", 0.0) or 0.0)
    ops = int(latency.get("ops", 0) or 0)
    if p95 > INFERENCE_P95_MS:
        return entry("inference", DEGRADED,
                     f"p95 {p95:.1f}ms over the {int(INFERENCE_P95_MS)}ms "
                     f"budget (p50 {latency.get('p50_ms', 0.0):.1f}ms, "
                     f"{ops} sample(s))",
                     evidence)
    if ops == 0:
        return entry("inference", HEALTHY,
                     "model ready; no flows scored yet", evidence)
    return entry("inference", HEALTHY,
                 f"p50 {latency.get('p50_ms', 0.0):.1f}ms / p95 {p95:.1f}ms "
                 f"across {ops} scoring op(s)",
                 evidence)


def check_model(*, trained: bool, model_id: str, version: str | int,
                n_train: int, drift_level: str | None,
                error: str | None = None) -> dict:
    """Active model artifact: presence first, then cached PSI drift."""
    evidence = {
        "trained": trained,
        "id": model_id,
        "version": version,
        "n_train": n_train,
        "drift_level": drift_level,
        "error": error,
    }
    if error:
        return entry("model", UNAVAILABLE,
                     f"model artifact unreadable: {error}", evidence)
    if not trained:
        return entry("model", UNAVAILABLE,
                     f"model '{model_id}' is not trained - run 'spectra train'",
                     evidence)
    if drift_level in DRIFT_LEVELS:
        return entry("model", DEGRADED,
                     f"input drift '{drift_level}' vs the training baseline "
                     f"(PSI) - scores may be less reliable",
                     evidence)
    return entry("model", HEALTHY,
                 f"model '{model_id}' v{version} loaded ({n_train} training "
                 f"flow(s)); drift {drift_level or 'stable'}",
                 evidence)


def check_database(*, enabled: bool, error: str | None, size_bytes: int,
                   latency: Mapping[str, float], commits: int,
                   errors_new: int) -> dict:
    """Persistence: presence, write-latency budget, recent errors."""
    evidence = {
        "enabled": enabled,
        "size_bytes": size_bytes,
        "write_p50_ms": latency.get("write_p50_ms", 0.0),
        "write_p95_ms": latency.get("write_p95_ms", 0.0),
        "commits": commits,
        "errors_new": errors_new,
        "budget_p95_ms": DB_WRITE_P95_MS,
        "error": error,
    }
    if not enabled:
        return entry("database", UNAVAILABLE,
                     "persistence disabled - this engine runs without a "
                     "database (evidence and history are memory-only)",
                     evidence)
    if error:
        return entry("database", UNAVAILABLE,
                     f"database unavailable: {error}", evidence)
    p95 = float(latency.get("write_p95_ms", 0.0) or 0.0)
    if errors_new > 0:
        return entry("database", DEGRADED,
                     f"{errors_new} database error(s) since the previous "
                     f"check", evidence)
    if p95 > DB_WRITE_P95_MS:
        return entry("database", DEGRADED,
                     f"write p95 {p95:.1f}ms over the "
                     f"{int(DB_WRITE_P95_MS)}ms budget", evidence)
    size_mb = size_bytes / (1024 * 1024)
    return entry("database", HEALTHY,
                 f"writable; write p95 {p95:.1f}ms; {size_mb:.1f}MB on disk",
                 evidence)


def check_events(*, clients: int, subscribers: int, emitted: int,
                 listener_errors_new: int, slow_drops_new: int) -> dict:
    """Event bus + WebSocket fan-out: delivery failures and slow clients."""
    evidence = {
        "clients": clients,
        "subscribers": subscribers,
        "events_emitted": emitted,
        "listener_errors_new": listener_errors_new,
        "slow_client_drops_new": slow_drops_new,
    }
    if listener_errors_new > 0:
        return entry("events", DEGRADED,
                     f"{listener_errors_new} event delivery failure(s) since "
                     f"the previous check (a listener raised; fan-out "
                     f"continued)",
                     evidence)
    if slow_drops_new > 0:
        return entry("events", DEGRADED,
                     f"slow websocket client(s) dropped {slow_drops_new} "
                     f"event(s) (500-event buffer overflow)",
                     evidence)
    return entry("events", HEALTHY,
                 f"{clients} websocket client(s), {subscribers} listener(s); "
                 f"{emitted} event(s) emitted",
                 evidence)


def check_audit(*, enabled: bool, error: str | None, seq: int | None,
                entries: int, failures_total: int) -> dict:
    """Hash-chain head: readable, present, append failures visible."""
    evidence = {
        "enabled": enabled,
        "seq": seq,
        "entries": entries,
        "failures": failures_total,
        "error": error,
    }
    if not enabled:
        return entry("audit", UNAVAILABLE,
                     "no database - the audit chain is not persisted",
                     evidence)
    if error:
        return entry("audit", UNAVAILABLE,
                     f"audit chain unreadable: {error}", evidence)
    if failures_total > 0:
        return entry("audit", DEGRADED,
                     f"{failures_total} audit append failure(s) since "
                     f"startup - some evidence may be missing from the chain",
                     evidence)
    if seq is None:
        return entry("audit", HEALTHY,
                     "chain empty - no entries recorded yet", evidence)
    return entry("audit", HEALTHY,
                 f"hash chain intact at seq {seq} ({entries} entries)",
                 evidence)


def check_module(*, name: str, available: bool, detail: str,
                 failures_new: int, failures_total: int,
                 simulated: bool = False) -> dict:
    """Advanced-module health from the live capability probe.

    Order: not functional -> UNAVAILABLE; failing right now -> DEGRADED;
    working but non-real by design -> SIMULATED; otherwise HEALTHY. The
    probe's own ``detail`` string is the reason, so the operator sees the
    module's self-description verbatim.
    """
    evidence = {
        "available": available,
        "detail": detail,
        "failures": failures_total,
        "failures_new": failures_new,
        "simulated": simulated,
    }
    if not available:
        return entry(name, UNAVAILABLE, detail or "module unavailable",
                     evidence)
    if failures_new > 0:
        return entry(name, DEGRADED,
                     f"{failures_new} module failure(s) since the previous "
                     f"check - {detail}",
                     evidence)
    if simulated:
        return entry(name, SIMULATED, detail, evidence)
    return entry(name, HEALTHY, detail, evidence)
