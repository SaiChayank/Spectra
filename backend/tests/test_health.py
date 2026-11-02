"""System Health layer: states, evaluators, telemetry, API, logging.

Covers the DoD surfaces directly:
* every subsystem reports one of HEALTHY / DEGRADED / UNAVAILABLE /
  SIMULATED with a *reason* and evidence numbers (why it is unhealthy);
* saturation, drops and error counts are visible in the metrics block;
* the public ``/api/health`` liveness probe stays small and unauthenticated;
* structured JSON logs carry the request id and never a password/token.
"""

from __future__ import annotations

import json
import logging
import os
import time

import pytest

from spectra.health import (
    DEGRADED,
    HEALTHY,
    SEVERITY,
    SIMULATED,
    STATES,
    SUBSYSTEMS,
    UNAVAILABLE,
    LatencyReservoir,
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
    entry,
    overall,
    percentile,
)
from spectra.observability import (
    RequestIdFilter,
    StructuredFormatter,
)
from spectra.services.events import EventBus

ADMIN_PASSWORD = os.environ["SPECTRA_ADMIN_PASSWORD"]  # set by conftest


# -- helpers -------------------------------------------------------------------

def find(body: dict, name: str) -> dict:
    match = [s for s in body["subsystems"] if s["name"] == name]
    assert match, f"subsystem {name!r} missing from report"
    return match[0]


# -- pure evaluators -----------------------------------------------------------

def test_registry_covers_the_fourteen_subsystems():
    assert len(SUBSYSTEMS) == 14
    names = [name for name, _ in SUBSYSTEMS]
    assert len(set(names)) == len(names)
    # every entry() resolves its title from this registry
    sub = entry("capture", HEALTHY, "ok", {})
    assert sub["title"] == "Capture engine"
    with pytest.raises(ValueError):
        entry("not_a_subsystem", HEALTHY, "ok", {})
    with pytest.raises(ValueError):
        entry("capture", "SAD", "ok", {})


def test_capture_states_and_reasons():
    idle = check_capture(running=False, mode=None, source=None, error=None,
                         packets=0, dropped=0, utilization=0.0, lag_ms=0.0)
    assert idle["state"] == HEALTHY and "idle" in idle["reason"]

    err = check_capture(running=True, mode="live", source="eth0",
                        error="sniff failed", packets=10, dropped=0,
                        utilization=0.0, lag_ms=0.0)
    assert err["state"] == DEGRADED
    assert "sniff failed" in err["reason"]

    drops = check_capture(running=True, mode="live", source="eth0",
                          error=None, packets=10_000, dropped=100,
                          utilization=0.0, lag_ms=0.0)
    assert drops["state"] == DEGRADED
    assert "100 of 10000 packets dropped" in drops["reason"]
    assert drops["evidence"]["drop_ratio"] == pytest.approx(0.01)

    sat = check_capture(running=True, mode="live", source="eth0",
                        error=None, packets=10_000, dropped=100,
                        utilization=0.95, lag_ms=1.0)
    assert sat["state"] == DEGRADED and "% full" in sat["reason"]

    lag = check_capture(running=True, mode="pcap", source="b.pcap",
                        error=None, packets=10, dropped=0,
                        utilization=0.1, lag_ms=900.0)
    assert lag["state"] == DEGRADED and "900ms" in lag["reason"]


def test_flow_tracker_states():
    ok = check_flow_tracker(active=10, limit=5000, evicted=0, evicted_new=0,
                            dropped_new=0, parse_errors_new=0)
    assert ok["state"] == HEALTHY and "10/5000" in ok["reason"]

    sat = check_flow_tracker(active=4500, limit=5000, evicted=9, evicted_new=0,
                             dropped_new=0, parse_errors_new=0)
    assert sat["state"] == DEGRADED and "flow table 4500/5000" in sat["reason"]

    evicted = check_flow_tracker(active=10, limit=5000, evicted=9,
                                 evicted_new=3, dropped_new=0,
                                 parse_errors_new=0)
    assert evicted["state"] == DEGRADED and "force-evicted" in evicted["reason"]

    parse = check_flow_tracker(active=10, limit=5000, evicted=0, evicted_new=0,
                               dropped_new=0, parse_errors_new=2)
    assert parse["state"] == DEGRADED and "parse exception" in parse["reason"]


def test_parser_states():
    tls = check_tls_parser(tls_flows=0, total_flows=0)
    assert tls["state"] == HEALTHY and "idle" in tls["reason"]
    active = check_tls_parser(tls_flows=7, total_flows=20)
    assert active["state"] == HEALTHY and "7 flow(s)" in active["reason"]

    # QUIC degradation is a real capability gap: no cryptography package.
    from spectra.parse.quic import CRYPTO_AVAILABLE
    quic = check_quic_parser(crypto_available=CRYPTO_AVAILABLE, quic_flows=0)
    if CRYPTO_AVAILABLE:
        assert quic["state"] == HEALTHY
    else:
        assert quic["state"] == DEGRADED
        assert "cryptography" in quic["reason"]


def test_inference_states():
    untrained = check_inference(trained=False,
                                latency={"p50_ms": 0.0, "p95_ms": 0.0,
                                         "ops": 0},
                                failures_new=0)
    assert untrained["state"] == UNAVAILABLE

    slow = check_inference(trained=True,
                           latency={"p50_ms": 20.0, "p95_ms": 80.0, "ops": 50},
                           failures_new=0)
    assert slow["state"] == DEGRADED and "80.0ms" in slow["reason"]

    failing = check_inference(trained=True,
                              latency={"p50_ms": 1.0, "p95_ms": 2.0, "ops": 5},
                              failures_new=3)
    assert failing["state"] == DEGRADED and "scoring failure" in failing["reason"]

    ok = check_inference(trained=True,
                         latency={"p50_ms": 2.0, "p95_ms": 5.0, "ops": 99},
                         failures_new=0)
    assert ok["state"] == HEALTHY and "p95 5.0ms" in ok["reason"]

    fresh = check_inference(trained=True,
                            latency={"p50_ms": 0.0, "p95_ms": 0.0, "ops": 0},
                            failures_new=0)
    assert fresh["state"] == HEALTHY and "no flows scored" in fresh["reason"]


def test_model_states():
    untrained = check_model(trained=False, model_id="spectra_model.pkl",
                            version="v1", n_train=0, drift_level=None)
    assert untrained["state"] == UNAVAILABLE and "spectra train" in untrained["reason"]

    drift = check_model(trained=True, model_id="spectra_model.pkl",
                        version="v1", n_train=500, drift_level="significant")
    assert drift["state"] == DEGRADED and "significant" in drift["reason"]

    broken = check_model(trained=False, model_id="m.pkl", version="?",
                         n_train=0, drift_level=None,
                         error="ValueError: corrupt")
    assert broken["state"] == UNAVAILABLE and "unreadable" in broken["reason"]

    ok = check_model(trained=True, model_id="spectra_model.pkl",
                     version="v1", n_train=500, drift_level="stable")
    assert ok["state"] == HEALTHY and "drift stable" in ok["reason"]


def test_database_states():
    disabled = check_database(enabled=False, error=None, size_bytes=0,
                              latency={"write_p50_ms": 0.0,
                                       "write_p95_ms": 0.0},
                              commits=0, errors_new=0)
    assert disabled["state"] == UNAVAILABLE and "persistence disabled" in disabled["reason"]

    broken = check_database(enabled=True, error="StoreError: locked",
                            size_bytes=0,
                            latency={"write_p50_ms": 0.0, "write_p95_ms": 0.0},
                            commits=0, errors_new=0)
    assert broken["state"] == UNAVAILABLE and "StoreError" in broken["reason"]

    slow = check_database(enabled=True, error=None, size_bytes=1024,
                          latency={"write_p50_ms": 40.0, "write_p95_ms": 250.0},
                          commits=5, errors_new=0)
    assert slow["state"] == DEGRADED and "250.0ms" in slow["reason"]

    failing = check_database(enabled=True, error=None, size_bytes=1024,
                             latency={"write_p50_ms": 1.0, "write_p95_ms": 2.0},
                             commits=5, errors_new=4)
    assert failing["state"] == DEGRADED and "4 database error" in failing["reason"]

    ok = check_database(enabled=True, error=None, size_bytes=2 * 1024 * 1024,
                        latency={"write_p50_ms": 1.0, "write_p95_ms": 2.0},
                        commits=5, errors_new=0)
    assert ok["state"] == HEALTHY and "2.0MB" in ok["reason"]


def test_events_and_audit_states():
    ok = check_events(clients=1, subscribers=4, emitted=10,
                      listener_errors_new=0, slow_drops_new=0)
    assert ok["state"] == HEALTHY and "1 websocket client" in ok["reason"]

    listener = check_events(clients=1, subscribers=4, emitted=10,
                            listener_errors_new=2, slow_drops_new=0)
    assert listener["state"] == DEGRADED and "listener raised" in listener["reason"]

    slow = check_events(clients=1, subscribers=4, emitted=10,
                        listener_errors_new=0, slow_drops_new=5)
    assert slow["state"] == DEGRADED and "dropped 5" in slow["reason"]

    assert check_audit(enabled=False, error=None, seq=None, entries=0,
                       failures_total=0)["state"] == UNAVAILABLE
    assert check_audit(enabled=True, error="no such table", seq=None,
                       entries=0, failures_total=0)["state"] == UNAVAILABLE
    failing = check_audit(enabled=True, error=None, seq=9, entries=10,
                          failures_total=2)
    assert failing["state"] == DEGRADED and "append failure" in failing["reason"]
    empty = check_audit(enabled=True, error=None, seq=None, entries=0,
                        failures_total=0)
    assert empty["state"] == HEALTHY and "empty" in empty["reason"]
    intact = check_audit(enabled=True, error=None, seq=9, entries=10,
                         failures_total=0)
    assert intact["state"] == HEALTHY and "seq 9" in intact["reason"]


def test_module_states_and_simulated_semantics():
    unavailable = check_module(name="bio", available=False,
                               detail="not trained - run 'spectra train'",
                               failures_new=0, failures_total=0)
    assert unavailable["state"] == UNAVAILABLE
    assert "spectra train" in unavailable["reason"]

    failing = check_module(name="pqc", available=True, detail="12 assessed",
                           failures_new=2, failures_total=5)
    assert failing["state"] == DEGRADED
    assert "2 module failure" in failing["reason"] and "12 assessed" in failing["reason"]

    # simulated-by-design beats healthy, but a *failing* simulated module
    # reports DEGRADED - by-design must never mask a real problem.
    sim = check_module(name="tee", available=True,
                       detail="local simulated enclave (never hardware-backed)",
                       failures_new=0, failures_total=0, simulated=True)
    assert sim["state"] == SIMULATED
    sim_failing = check_module(name="tee", available=True,
                               detail="local simulated enclave",
                               failures_new=1, failures_total=1,
                               simulated=True)
    assert sim_failing["state"] == DEGRADED

    ok = check_module(name="edge", available=True, detail="link ok",
                      failures_new=0, failures_total=0)
    assert ok["state"] == HEALTHY and ok["reason"] == "link ok"


def test_overall_rollup_severity_and_reasons():
    entries = [entry(name, HEALTHY, "ok", {}) for name, _ in SUBSYSTEMS]
    state, reason, counts = overall(entries)
    assert state == HEALTHY and "14" in reason
    assert counts == {s: 0 for s in STATES} | {HEALTHY: 14}

    # SIMULATED alone never rolls up as a failure...
    sim_entries = [dict(e) for e in entries]
    sim_entries[0]["state"] = SIMULATED
    state, reason, counts = overall(sim_entries)
    assert state == SIMULATED and "simulated by design" in reason
    assert counts[SIMULATED] == 1

    # ...but DEGRADED/UNAVAILABLE dominate, with the offenders named.
    deg_entries = [dict(e) for e in entries]
    deg_entries[1]["state"] = DEGRADED
    deg_entries[2]["state"] = UNAVAILABLE
    deg_entries[1]["title"] = "Flow tracker"
    state, reason, counts = overall(deg_entries)
    assert state == UNAVAILABLE  # worst state wins
    assert counts[UNAVAILABLE] == 1 and counts[DEGRADED] == 1
    assert "1 subsystem(s) unavailable" in reason and "TLS parser" in reason
    assert SEVERITY[UNAVAILABLE] > SEVERITY[DEGRADED] > SEVERITY[SIMULATED] \
        > SEVERITY[HEALTHY]


# -- telemetry helpers ---------------------------------------------------------

def test_percentile_and_reservoir():
    assert percentile([], 95) is None
    assert percentile([7.0], 95) == 7.0
    assert percentile([1.0, 2.0, 3.0, 4.0], 50) == pytest.approx(2.5)
    assert percentile([1.0, 2.0, 3.0, 4.0], 100) == 4.0

    res = LatencyReservoir(capacity=8)
    empty = res.summary()
    assert empty["samples"] == 0 and empty["p95_ms"] == 0.0
    for value in range(100):
        res.observe(float(value))
    summary = res.summary()
    assert summary["samples"] == 8          # bounded ring
    assert summary["total_samples"] == 100  # lifetime count survives eviction
    assert summary["p95_ms"] >= summary["p50_ms"] >= 0.0
    assert summary["max_ms"] == 99.0


def test_window_rates_scaling_and_counter_reset():
    rates = WindowRates(window_s=60.0)
    assert rates.rates() == {}  # no baseline yet

    rates.observe({"packets": 100, "detections": 5}, ts=1000.0)
    assert rates.rates() == {}  # still just one sample
    rates.observe({"packets": 400, "detections": 35}, ts=1030.0)
    out = rates.rates()
    assert out["packets"] == pytest.approx(600.0)   # +300 over 30s
    assert out["detections"] == pytest.approx(60.0)  # +30 over 30s

    # per-capture counter reset rebases instead of going negative
    rates.observe({"packets": 10, "detections": 1}, ts=1031.0)
    out = rates.rates()
    assert out["packets"] >= 0.0 and out["detections"] >= 0.0


def test_event_bus_telemetry():
    bus = EventBus()
    assert bus.subscriber_count == 0 and bus.emit_count == 0
    keep = bus.subscribe(lambda event: None)
    bus.subscribe(lambda event: (_ for _ in ()).throw(RuntimeError("boom")))
    assert bus.subscriber_count == 2
    bus.emit({"type": "test"})
    assert bus.emit_count == 1
    assert bus.listener_errors == 1  # isolated, counted, not raised
    keep()
    assert bus.subscriber_count == 1


def test_store_write_telemetry_and_incident_count(tmp_path):
    from spectra.store import Store

    store = Store(str(tmp_path / "health.db"))
    try:
        before = store.incident_count()
        store.create_incident("health incident", None, "tester")
        assert store.incident_count() == before + 1
        stats = store.write_stats()
        assert stats["write_samples"] >= 1
        assert stats["write_p50_ms"] >= 0.0
        assert stats["write_p95_ms"] >= stats["write_p50_ms"] >= 0.0
        assert stats["errors"] == 0
        assert isinstance(stats["commits"], int)
    finally:
        store.close()


# -- API surface ---------------------------------------------------------------

def test_system_health_endpoint_shape(client):
    res = client.get("/api/health/system")
    assert res.status_code == 200, res.text
    body = res.json()

    assert body["state"] in STATES
    assert body["reason"]
    assert body["uptime_s"] >= 0.0
    assert sum(body["counts"].values()) == 14

    names = [s["name"] for s in body["subsystems"]]
    assert names == [name for name, _ in SUBSYSTEMS]
    for sub in body["subsystems"]:
        assert sub["state"] in STATES
        assert sub["title"] and sub["reason"]
        assert isinstance(sub["evidence"], dict)

    m = body["metrics"]
    for key in ("uptime_s", "packets", "flows", "queues", "inference",
                "processing_lag_ms", "database", "rates", "websocket",
                "model", "errors"):
        assert key in m, key
    assert set(m["packets"]) == {"captured", "dropped", "drop_ratio",
                                 "rate_pps"}
    assert set(m["flows"]) == {"processed", "rate_fps", "active",
                               "active_limit", "evicted", "dropped"}
    for stage in ("packet_queue", "flow_queue", "publish_queue"):
        assert set(m["queues"][stage]) == {"depth", "limit", "utilization",
                                           "offered", "accepted", "dropped"}
    assert set(m["queues"]) == {"packet_queue", "flow_queue",
                                "publish_queue", "live_capture", "saturation"}
    assert isinstance(m["queues"]["saturation"], list)
    assert set(m["inference"]) >= {"p50_ms", "p95_ms", "ops", "budget_p95_ms"}
    assert set(m["database"]) >= {"enabled", "size_bytes", "write_p50_ms",
                                  "write_p95_ms", "errors"}
    assert set(m["rates"]) >= {"detections_per_min", "incidents_per_min",
                               "events_per_min", "packets_per_min"}
    assert set(m["websocket"]) == {"clients", "subscribers",
                                   "events_emitted", "slow_client_drops"}
    assert set(m["model"]) >= {"id", "trained", "drift_level"}
    assert set(m["errors"]) >= {"total", "by_component"}


def test_rates_appear_on_the_second_report(client):
    client.get("/api/health/system")           # baseline sample
    body = client.get("/api/health/system").json()
    for key in ("packets_per_min", "flows_per_min", "detections_per_min",
                "incidents_per_min", "failures_per_min"):
        value = body["metrics"]["rates"][key]
        assert isinstance(value, float) and value >= 0.0


def test_public_liveness_probe_stays_small(raw_client):
    res = raw_client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["ok"] is True and data["service"] == "spectra"
    assert data["database"] in ("enabled", "disabled")
    # the detailed report (db size, subsystems, ...) needs a session
    assert "subsystems" not in data and "metrics" not in data
    assert raw_client.get("/api/health/system").status_code == 401


def test_viewer_can_read_health(viewer_client):
    assert viewer_client.get("/api/health/system").status_code == 200


def test_degraded_subsystem_is_visible_with_why(client):
    """DoD: degraded modules are visible and the reason is identifiable."""
    from spectra.api.app import engine

    status = engine.status
    saved = (status["error"], status["packets"],
             status["queue"]["packets_dropped"],
             status["pipeline"]["packet_queue"]["depth"],
             status["pipeline"]["active_flows"])
    limit = status["pipeline"]["packet_queue"]["limit"]
    flow_limit = status["pipeline"]["limits"]["active_flows"]
    try:
        # 1. capture error surfaces as DEGRADED with the error text
        status["error"] = "simulated capture fault"
        body = client.get("/api/health/system").json()
        cap = find(body, "capture")
        assert cap["state"] == DEGRADED
        assert "simulated capture fault" in cap["reason"]
        assert body["state"] == DEGRADED

        # 2. drops visible with counts and ratio
        status["error"] = None
        status["packets"] = 10_000
        status["queue"]["packets_dropped"] = 100
        status["pipeline"]["packet_queue"]["depth"] = 0
        body = client.get("/api/health/system").json()
        cap = find(body, "capture")
        assert cap["state"] == DEGRADED
        assert "100 of 10000 packets dropped" in cap["reason"]
        assert body["metrics"]["packets"]["dropped"] >= 100
        assert body["metrics"]["packets"]["drop_ratio"] > 0

        # 3. resource saturation visible (queue utilisation + active flows)
        status["queue"]["packets_dropped"] = 0
        status["packets"] = 0
        status["pipeline"]["packet_queue"]["depth"] = int(limit * 0.95)
        status["pipeline"]["active_flows"] = int(flow_limit * 0.95)
        body = client.get("/api/health/system").json()
        saturation = body["metrics"]["queues"]["saturation"]
        assert "packet_queue" in saturation
        assert "active_flows" in saturation
        stage = body["metrics"]["queues"]["packet_queue"]
        assert stage["utilization"] >= 0.8 and stage["limit"] == limit
        assert find(body, "flow_tracker")["state"] == DEGRADED
        assert "flow table" in find(body, "flow_tracker")["reason"]
        assert body["metrics"]["flows"]["active_limit"] == flow_limit
    finally:
        (status["error"], status["packets"],
         status["queue"]["packets_dropped"],
         status["pipeline"]["packet_queue"]["depth"],
         status["pipeline"]["active_flows"]) = saved


def test_websocket_clients_counted_in_health(client):
    from fastapi.testclient import TestClient
    from spectra.api.app import app

    other = TestClient(app)  # second admin session for the polling request
    before = other.get("/api/health/system").json()["metrics"]["websocket"][
        "clients"]
    with client.websocket_connect("/ws/events") as ws:
        ws.receive_json()  # initial status event
        during = other.get("/api/health/system").json()["metrics"]["websocket"]
        assert during["clients"] >= before + 1
    deadline = time.time() + 5.0
    after = before + 1
    while time.time() < deadline and after > before:
        after = other.get("/api/health/system").json()["metrics"]["websocket"][
            "clients"]
        if after <= before:
            break
        time.sleep(0.05)
    assert after <= before  # disconnect released the counter


def test_health_transitions_logged_structurally(caplog):
    from spectra.api.app import engine

    service = engine.system
    saved_states = dict(service._health_states)
    try:
        service._health_states = {}
        service._log_health_transitions(
            [entry("capture", HEALTHY, "ok", {})])
        with caplog.at_level(logging.INFO, logger="spectra.engine"):
            service._log_health_transitions(
                [entry("capture", DEGRADED, "dropped packets", {})])
        record = next(r for r in caplog.records
                      if getattr(r, "event", None) == "subsystem_health")
        assert record.subsystem == "capture"
        assert getattr(record, "from") == HEALTHY and record.to == DEGRADED
        assert record.reason == "dropped packets"
        # no duplicate line when the state does not change
        caplog.clear()
        with caplog.at_level(logging.INFO, logger="spectra.engine"):
            service._log_health_transitions(
                [entry("capture", DEGRADED, "dropped packets", {})])
        assert not [r for r in caplog.records
                    if getattr(r, "event", None) == "subsystem_health"]
    finally:
        service._health_states = saved_states


# -- structured logging + request ids -----------------------------------------

def test_structured_formatter_json_fields_and_redaction():
    record = logging.LogRecord("spectra.engine", logging.INFO, __file__, 1,
                               "login attempt token=abc123 password: hunter2",
                               None, None)
    record.request_id = "rid-42"
    record.subsystem = "capture"
    record.password = "should-never-appear"
    out = StructuredFormatter().format(record)
    data = json.loads(out)
    assert data["request_id"] == "rid-42"
    assert data["level"] == "INFO"
    assert data["logger"] == "spectra.engine"
    assert data["subsystem"] == "capture"
    assert data["ts"].endswith("Z")
    assert "abc123" not in out and "hunter2" not in out
    assert data["password"] == "***"
    assert "***" in data["msg"]


def test_formatter_attaches_request_id_from_context():
    from spectra.observability import REQUEST_ID

    record = logging.LogRecord("spectra.api", logging.INFO, __file__, 1,
                               "hello", None, None)
    token = REQUEST_ID.set("ctx-99")
    try:
        RequestIdFilter().filter(record)
        assert record.request_id == "ctx-99"
        data = json.loads(StructuredFormatter().format(record))
        assert data["request_id"] == "ctx-99"
    finally:
        REQUEST_ID.reset(token)


def test_request_id_header_echo_and_generation(client):
    res = client.get("/api/status")
    generated = res.headers.get("x-request-id")
    assert generated and len(generated) == 16

    echo = client.get("/api/status", headers={"X-Request-ID": "trace-abc.1"})
    assert echo.headers["x-request-id"] == "trace-abc.1"

    hostile = client.get("/api/status",
                         headers={"X-Request-ID": "bad id with spaces"})
    replaced = hostile.headers["x-request-id"]
    assert replaced != "bad id with spaces"
    assert len(replaced) == 16 and " " not in replaced


class _CaptureHandler(logging.Handler):
    """Formats every record through the structured formatter for asserts."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []
        self.setFormatter(StructuredFormatter())
        self.addFilter(RequestIdFilter())

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.lines.append(self.format(record))
        except Exception:  # noqa: BLE001 - test capture must not break
            pass


def test_login_never_logs_the_password(raw_client):
    """DoD: no passwords/session secrets in logs; request id on the response."""
    root = logging.getLogger()
    handler = _CaptureHandler()
    previous_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    try:
        res = raw_client.post("/api/auth/login", json={
            "username": "admin", "password": ADMIN_PASSWORD})
        assert res.status_code == 200, res.text
        assert res.headers.get("x-request-id")
        wrong = ADMIN_PASSWORD + "-wrong"
        rejected = raw_client.post("/api/auth/login", json={
            "username": "admin", "password": wrong})
        assert rejected.status_code == 401
        assert rejected.headers.get("x-request-id")
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)

    blob = "\n".join(handler.lines)
    assert ADMIN_PASSWORD not in blob          # the secret never appears
    assert wrong not in blob                   # nor a rejected attempt's
    assert handler.lines                       # the request itself was logged
    assert "/api/auth/login" in blob
    assert "http_request" in blob


def test_request_log_omits_query_strings(client):
    """The path is logged - never the query (a WS ?token= must not leak)."""
    root = logging.getLogger()
    handler = _CaptureHandler()
    previous_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    try:
        assert client.get("/api/flows?limit=5").status_code == 200
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)

    request_lines = [line for line in handler.lines
                     if '"http_request"' in line]
    assert request_lines, "no structured request log was emitted"
    line = request_lines[-1]
    assert '"/api/flows"' in line
    assert "limit=5" not in line
    data = json.loads(line)
    assert data["method"] == "GET" and data["status"] == 200
    assert data["path"] == "/api/flows"
    assert data["request_id"] and data["duration_ms"] >= 0


def test_configure_logging_is_idempotent():
    from spectra.observability import configure_logging

    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    try:
        configure_logging("INFO")
        first = list(root.handlers)
        assert first                       # a handler exists after setup
        configure_logging("INFO")
        assert root.handlers == first      # second call stacked nothing
        for handler in root.handlers:
            assert isinstance(handler.formatter, StructuredFormatter)
            assert sum(isinstance(f, RequestIdFilter)
                       for f in handler.filters) == 1
    finally:
        for handler in list(root.handlers):
            if handler not in saved_handlers:
                root.removeHandler(handler)
        root.setLevel(saved_level)


def test_serve_never_lets_uvicorn_log_outside_redaction(monkeypatch):
    """``cmd_serve`` must not hand uvicorn its own plain-text handlers.

    The WebSocket handshake line (``/ws/events?token=...``) is emitted by
    ``uvicorn.error``, not the access logger - without ``log_config=None``
    it would print the session token outside the structured formatter's
    redaction. ``access_log=False`` keeps query strings out of access
    lines; both are pinned here as security properties.
    """
    import argparse

    import uvicorn

    import spectra.cli as cli

    seen: dict = {}
    monkeypatch.setattr(uvicorn, "run",
                        lambda app, **kwargs: seen.update(kwargs))

    rc = cli.cmd_serve(argparse.Namespace(host="127.0.0.1", port=8787,
                                          reload=False))
    assert rc == 0
    assert seen["access_log"] is False   # no query strings in access lines
    assert seen["log_config"] is None    # uvicorn keeps no plain handlers
