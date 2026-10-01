"""Investigation layer: bundle, global search, history filters, permissions.

Pure classification first (spectra.entity_search), then the repository
filters/related/search queries on an isolated store, then the service
bundle + search with graph/audit/model wired exactly like the pipeline,
and finally the API surface: routes, pagination envelopes, filter params,
and the permission matrix.

Every service test runs on an isolated temp store; only the API tests
touch the shared session database, and they use unique hosts/domains so
ordering and other tests cannot change their outcomes.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from spectra.api.app import app
from spectra.api.runtime import engine
from spectra.capabilities import CAPABILITIES, capability_contracts
from spectra.config import Config
from spectra.entity_search import (
    ALERT_ID,
    DOMAIN,
    IP,
    JA3,
    JA4,
    MODEL_ID,
    NUMBER,
    TEXT,
    classify,
    ip_host,
    looks_like_domain,
)
from spectra.modules.corr import CorrelationGraph
from spectra.services.audit import AuditService
from spectra.services.events import EventBus
from spectra.services.incidents import IncidentService
from spectra.services.investigation import (
    InvestigationNotFound,
    InvestigationService,
    InvestigationUnavailable,
    InvestigationValidationError,
)
from spectra.services.resilience import FailureTracker
from spectra.services.threat_alerts import ThreatAlertService
from spectra.store import Store

client = TestClient(app)  # session-scoped admin (conftest)

BASE_TS = 1_700_000_000.0

BUNDLE_KEYS = {
    "incident", "notes", "note_count", "timeline", "alerts", "flows",
    "window", "tls", "evidence", "hosts", "domains", "annotations",
    "graph", "twin", "audit", "models", "modules", "generated_at",
}
SEARCH_SECTIONS = {"incidents", "alerts", "flows", "captures",
                   "hosts", "domains", "models"}


# -- helpers (mirroring test_incident_alerts) ---------------------------------

def make_env(tmp_path):
    """Isolated store + alert/incident/investigation services, pipeline-wired."""
    cfg = Config()
    cfg.alert_group_seconds = 600.0
    cfg.incident_window_seconds = 1800.0
    store = Store(str(tmp_path / "investigation.db"))
    bus = EventBus()
    graph = CorrelationGraph()
    failures = FailureTracker({})
    audit = AuditService(store, str(tmp_path / "model.joblib"), failures)
    model_info = lambda: {"id": "spectra_iforest.joblib", "version": "3"}  # noqa: E731
    alerts = ThreatAlertService(store, cfg, bus, failures,
                                model_info=model_info)
    incidents = IncidentService(store, cfg, failures=failures, audit=audit,
                                graph_provider=lambda: graph)
    # Live capability probes: a canned full-status provider so the bundle's
    # module section renders probed values (a raising provider is covered
    # by test_bundle_module_status_degrades_when_probe_fails).
    capability_provider = lambda: {  # noqa: E731
        key: {"available": True, "detail": "test probe", "failures": 0}
        for key in capability_contracts()
    }
    investigation = InvestigationService(
        store, cfg, graph_provider=lambda: graph, model_info=model_info,
        capability_provider=capability_provider)

    def _to_correlator(event: dict) -> None:
        if str(event.get("type", "")) in ("alert", "alert_updated"):
            incidents.observe_alert(event.get("data") or {})

    bus.subscribe(_to_correlator)
    return SimpleNamespace(store=store, bus=bus, graph=graph, cfg=cfg,
                           failures=failures, audit=audit, alerts=alerts,
                           incidents=incidents, investigation=investigation)


@pytest.fixture()
def env(tmp_path):
    e = make_env(tmp_path)
    yield e
    e.store.close()


def rec(src: str, dst: str, ts: float, *, sni: str | None = None,
        proto: str = "TCP", score: float = 97.0, anomaly: bool = True,
        ja3: str | None = None, ja4: str | None = None,
        quic_version: str | None = None, pqc: dict | None = None,
        slice_id: str | None = None, immune: dict | None = None) -> dict:
    """A completed flow record shaped like the publication path."""
    return {
        "src": src, "dst": dst, "proto": proto,
        "start_ts": ts, "last_ts": ts + 10.0,
        "duration": 10.0, "packets": 30, "bytes": 1600,
        "sni": sni, "tls_version": "TLS 1.3" if sni else None,
        "quic_version": quic_version, "alpn": "h2" if sni else None,
        "ja3": ja3, "ja4": ja4, "slice": slice_id,
        "pqc": pqc, "immune": immune,
        "score": score, "anomaly": anomaly,
    }


def verdict(threat_type: str = "C2_BEACONING",
            confidence: float = 0.72) -> dict:
    return {"threat_type": threat_type, "confidence": confidence,
            "supporting": [], "contradicting": []}


def save(env, record: dict, *, reasons: list | None = None) -> None:
    """Persist one flow exactly like the publication path (buffered)."""
    env.store.save_flow(record, record.get("score"), record.get("anomaly"),
                        reasons=reasons)


def seed_incident(env, *, host: str = "10.51.0.1",
                  domain: str = "bundle-c2.example.net"):
    """Three alerts (explicitly linked) + the surrounding flow activity.

    Returns (incident, member alerts). Flow activity: the three alert
    flows (alert back-link stamped), one same-host flow inside the window,
    one same-host flow far outside it, one unrelated endpoint inside it.
    """
    seeds = []
    for i in range(3):
        record = rec(f"{host}:{41000 + i}", f"93.184.216.{34 + i}:443",
                     BASE_TS + 30 * i, sni=domain,
                     ja3="d" * 32, ja4="t13d0916h2_8daaf6152771_b0da82dd1658",
                     quic_version="draft-29" if i == 0 else None,
                     pqc={"level": "harvest_now"}, slice_id="slice-7",
                     immune={"flag": True})
        alert = env.alerts.observe(record, verdict(), score=97.0)
        record["alert_id"] = alert["alert_id"]
        save(env, record, reasons=[{"feature": "iat_std_s", "z_score": 5.0}])
        env.graph.observe(record)
        seeds.append(alert)
    incident = env.incidents.create(
        "bundle beacon cluster", None, "tester",
        alert_ids=[a["alert_id"] for a in seeds], summary="for the bundle")
    env.store.query_flows(limit=1)   # flush the alert flows

    save(env, rec(f"{host}:{41099}", "93.184.216.60:443", BASE_TS + 40),
         )                     # same host, inside the window -> related
    save(env, rec(f"{host}:{41002}", "93.184.216.61:443", BASE_TS + 9000))  # out
    save(env, rec("10.77.0.9:41000", "93.184.216.62:443", BASE_TS + 45))   # other
    env.store.query_flows(limit=1)   # flush the rest
    return incident, seeds


# -- 1. pure classification ---------------------------------------------------

def test_classify_endpoints_and_fingerprints():
    assert classify("10.0.0.1") == [IP]
    assert classify("10.0.0.1:443") == [IP]
    assert classify("fe80::1:443") == [IP]          # port stripped, still IP
    assert classify("[2001:db8::1]:443") == [IP]
    assert classify(" 10.0.0.1  ") == [IP]          # trimmed
    assert DOMAIN not in classify("10.0.0.1")       # IPv4 never a domain

    assert classify("alrt_1a2b3c4d5e6f") == [ALERT_ID]
    assert classify("a" * 32) == [JA3]
    assert classify("t13d0916h2_8daaf6152771_b0da82dd1658") == [JA4]
    assert classify("1234") == [NUMBER]
    assert classify("spectra_iforest.joblib") == [MODEL_ID]


def test_classify_domain_and_text_fallback():
    assert classify("api.example.net") == [DOMAIN]
    assert looks_like_domain("api.example.net")
    assert not looks_like_domain("1.2.3")           # numeric TLD is not a host
    assert classify("C2_BEACONING") == [TEXT]
    assert classify("beacon") == [TEXT]
    assert classify("weird query!!") == [TEXT]      # unknown -> broad, not none
    assert classify("") == [] and classify("   ") == []


def test_ip_host_helper():
    assert ip_host("10.0.0.1:443") == "10.0.0.1"
    assert ip_host("10.0.0.1") == "10.0.0.1"
    assert ip_host("fe80::1:443") == "fe80::1"
    assert ip_host("2001:db8::1") == "2001:db8::1"
    assert ip_host("evil.example.net") is None
    assert ip_host("") is None


# -- 2. repository queries (isolated store) -----------------------------------

def test_flow_query_filter_set(env):
    rows = [
        rec("10.1.0.1:4000", "93.184.216.34:443", BASE_TS, sni="a.example"),
        rec("10.1.0.2:4001", "93.184.216.35:443", BASE_TS + 100,
            proto="UDP"),
        rec("10.1.0.10:4002", "93.184.216.36:443", BASE_TS + 200,
            score=12.0, anomaly=False),
    ]
    for r in rows:
        save(env, r)
    env.store.query_flows(limit=1)   # flush

    assert env.store.query_flows(src="10.1.0.1")["count"] == 1  # not .10
    assert env.store.query_flows(src="10.1.0.1:4000")["count"] == 1
    assert env.store.query_flows(dst="93.184.216.34")["count"] == 1
    assert env.store.query_flows(proto="UDP")["count"] == 1
    assert env.store.query_flows(min_score=50.0)["count"] == 2
    assert env.store.query_flows(max_score=50.0)["count"] == 1
    page = env.store.query_flows(since=BASE_TS + 50, until=BASE_TS + 150)
    assert page["count"] == 1
    assert page["items"][0]["src"] == "10.1.0.2:4001"


def test_related_flows_direct_alert_and_window(env):
    direct = rec("10.2.0.1:1", "93.184.216.34:443", BASE_TS)
    linked = rec("10.2.0.2:2", "93.184.216.35:443", BASE_TS + 20,
                 sni="svc.example")
    linked["alert_id"] = "alrt_linked01"
    windowed = rec("10.2.0.1:9999", "93.184.216.36:443", BASE_TS + 30)
    outside = rec("10.2.0.1:33", "93.184.216.37:443", BASE_TS + 10_000)
    foreign = rec("10.99.0.9:1", "93.184.216.38:443", BASE_TS + 30)
    for r in (direct, linked, windowed, outside, foreign):
        save(env, r)
    items = env.store.query_flows(limit=10)["items"]   # flush + read ids
    by_src = {row["src"]: row["id"] for row in items}

    page = env.store.related_flows(
        flow_ids=[by_src["10.2.0.1:1"]],
        alert_ids=["alrt_linked01"],
        hosts=["10.2.0.1"], snis=["svc.example"],
        since=BASE_TS - 60, until=BASE_TS + 600, limit=50)
    assert page["count"] == 3
    assert {row["src"] for row in page["items"]} == {
        "10.2.0.1:1", "10.2.0.2:2", "10.2.0.1:9999"}

    # pagination keeps the envelope honest
    page = env.store.related_flows(
        flow_ids=[by_src["10.2.0.1:1"]], hosts=["10.2.0.1"],
        since=0, until=1e12, limit=1, offset=1)
    assert page["count"] >= 2 and page["offset"] == 1
    assert len(page["items"]) == 1

    # no anchors at all: an empty page, never a full-table scan
    empty = env.store.related_flows(since=0, until=1e12)
    assert empty == {"count": 0, "offset": 0, "items": []}


def test_flow_search_matchers(env):
    save(env, rec("10.4.0.1:4000", "93.184.216.34:443", BASE_TS,
                  sni="unique-search.example", ja3="c" * 32,
                  ja4="t13d0916h2_8daaf6152771_b0da82dd1658"))
    env.store.query_flows(limit=1)   # flush

    assert env.store.search_flows("10.4.0.1", endpoint=True)["count"] == 1
    assert env.store.search_flows("unique-search.example", sni=True)["count"] == 1
    assert env.store.search_flows("c" * 32, fingerprint=True)["count"] == 1
    assert env.store.search_flows("nope-nowhere", sni=True)["count"] == 0
    # no matcher flags -> explicit empty page, never a scan
    assert env.store.search_flows("10.4.0.1") == {"count": 0, "items": []}


def test_alert_and_incident_filters(env):
    first, _ = seed_incident(env, host="10.52.0.1",
                             domain="filter-c2.example.net")
    alerts = env.store.list_alerts(source="10.52.0.1")
    assert alerts["count"] == 3
    alert_id = alerts["items"][0]["alert_id"]

    assert env.store.list_alerts(severity="HIGH",
                                 source="10.52.0.1")["count"] == 3
    assert env.store.list_alerts(severity="CRITICAL",
                                 source="10.52.0.1")["count"] == 0
    assert env.store.list_alerts(protocol="TCP",
                                 source="10.52.0.1")["count"] == 3
    assert env.store.list_alerts(min_score=50.0,
                                 source="10.52.0.1")["count"] == 3
    assert env.store.list_alerts(max_score=50.0,
                                 source="10.52.0.1")["count"] == 0
    assert env.store.list_alerts(since=BASE_TS - 60,
                                 source="10.52.0.1")["count"] == 3
    assert env.store.list_alerts(until=BASE_TS - 1000,
                                 source="10.52.0.1")["count"] == 0

    # alerts: search matchers
    assert env.store.search_alerts("10.52.0.1", endpoint=True)["count"] == 3
    assert env.store.search_alerts("filter-c2.example.net",
                                   text=True)["count"] == 3
    assert env.store.search_alerts(alert_id, alert_id=True)["count"] == 1
    assert env.store.search_alerts("spectra_iforest", model=True)["count"] == 3
    assert env.store.search_alerts("nothing") == {"count": 0, "items": []}

    # incidents: severity + overlap time range
    assert env.store.list_incidents(severity="HIGH")["count"] == 1
    assert env.store.list_incidents(severity="LOW")["count"] == 0
    page = env.store.list_incidents(since=BASE_TS - 60,
                                    until=BASE_TS + 3600)
    assert first["id"] in [row["id"] for row in page["items"]]
    page = env.store.list_incidents(until=BASE_TS - 1000)
    assert first["id"] not in [row["id"] for row in page["items"]]

    # incidents: id/entity/title search
    hit = env.store.search_incidents(str(first["id"]), exact_id=first["id"])
    assert hit["count"] == 1
    assert env.store.search_incidents("10.52.0.1")["count"] == 1
    assert env.store.search_incidents("bundle beacon cluster",
                                      entity=False)["count"] == 1
    assert env.store.search_incidents("no-such-title", entity=False) == {
        "count": 0, "items": []}


def test_history_offsets_counts_and_time_filters(env):
    # captures: status + offset envelope
    cid = env.store.start_capture("pcap", "probe.pcap")
    page = env.store.list_captures(limit=1, offset=0, status="PROCESSING")
    assert page["count"] >= 1 and page["offset"] == 0
    assert any(row["id"] == cid for row in page["items"])
    assert env.store.list_captures(status="COMPLETED")["count"] == 0

    # model runs: offset + count
    env.store.add_model_run("a.pcap", 10, 0.02, {"auc": 0.9})
    env.store.add_model_run("b.pcap", 20, 0.05, {"auc": 0.8})
    assert env.store.model_run_count() == 2
    top = env.store.model_runs(limit=1, offset=0)
    nxt = env.store.model_runs(limit=1, offset=1)
    assert top[0]["id"] > nxt[0]["id"]

    # events: time range
    env.store.record_event("investigation_probe", {"ok": True},
                           ts=BASE_TS + 500)
    page = env.store.query_events(type="investigation_probe",
                                  since=BASE_TS + 400, until=BASE_TS + 600)
    assert page["count"] == 1
    page = env.store.query_events(type="investigation_probe",
                                  since=BASE_TS + 601)
    assert page["count"] == 0

    # audit: prefix + time + actor filters, with a count that mirrors them
    env.incidents.create("audit probe", None, "tester")  # -> incident.create
    assert env.store.audit_count(kind_prefix="incident.") >= 1
    assert env.store.audit_count(kind_prefix="no.such.") == 0
    assert env.store.audit_count(actor="ghost") == 0
    assert env.store.audit_count(since=1e15) == 0
    rows = env.store.audit_entries(limit=50, kind_prefix="incident.",
                                   actor="tester")
    assert rows and all(r["actor"] == "tester" for r in rows)
    assert env.store.audit_entries(limit=50, kind_prefix="incident.",
                                   since=1e15) == []


# -- 3. the bundle (isolated service) -----------------------------------------

def test_bundle_sections_and_related_flows(env):
    incident, seeds = seed_incident(env)
    bundle = env.investigation.bundle(incident["id"])

    assert set(bundle) == BUNDLE_KEYS
    assert bundle["incident"]["id"] == incident["id"]
    assert bundle["alerts"]["count"] == 3
    assert len(bundle["notes"]) == bundle["note_count"]
    assert [e["kind"] for e in bundle["timeline"]][:1] == ["created"]

    # related = 3 alert flows + same-host in-window flow; never the
    # out-of-window or unrelated-endpoint rows
    srcs = {row["src"] for row in bundle["flows"]["items"]}
    assert bundle["flows"]["count"] == 4
    assert srcs == {"10.51.0.1:41000", "10.51.0.1:41001",
                    "10.51.0.1:41002", "10.51.0.1:41099"}
    assert bundle["window"]["since"] < BASE_TS < bundle["window"]["until"]
    assert bundle["window"]["evidence_rows"] == 4

    # aggregates over the bounded window
    assert bundle["hosts"][0]["host"] == "10.51.0.1"
    assert bundle["hosts"][0]["flows"] == 4
    assert bundle["domains"] == [{
        "domain": "bundle-c2.example.net", "flows": 3, "detections": 3,
        "first_ts": pytest.approx(BASE_TS + 10, abs=1),
        "last_ts": pytest.approx(BASE_TS + 70, abs=1),
    }]
    assert bundle["tls"]["tls_versions"] == {"TLS 1.3": 3}
    assert bundle["tls"]["quic_versions"] == {"draft-29": 1}
    assert bundle["tls"]["alpn"] == {"h2": 3}
    kinds = {f["kind"] for f in bundle["tls"]["fingerprints"]}
    assert kinds == {JA3, JA4}

    # evidence: summary, per-alert verdicts, detector reasons
    assert bundle["evidence"]["summary"].startswith("3 linked alert(s)")
    assert len(bundle["evidence"]["alerts"]) == 3
    assert all(r["reasons"] for r in bundle["evidence"]["flow_reasons"])

    # annotations: PQC / bio / edge from flows *and* member alerts
    counts = bundle["annotations"]["counts"]
    assert counts == {"pqc": 6, "bio": 6, "edge": 6}
    assert all(item["ref"].startswith(("flow:", "alert:"))
               for key in ("pqc", "bio", "edge")
               for item in bundle["annotations"][key])
    assert {item["slice"] for item in bundle["annotations"]["edge"]} == {"slice-7"}


def test_bundle_graph_twin_audit_models(env):
    incident, seeds = seed_incident(env, host="10.53.0.1",
                                    domain="graph-c2.example.net")
    bundle = env.investigation.bundle(incident["id"])

    graph = bundle["graph"]
    assert graph["available"] is True
    node_ids = {node["id"] for node in graph["nodes"]}
    assert "host:10.53.0.1" in node_ids
    assert "domain:graph-c2.example.net" in node_ids
    # anchor-derived candidate ids that the graph never saw are reported
    assert "ip:10.53.0.1" in graph["missing"]
    assert graph["edges"] and graph["truncated"] is False

    twin = bundle["twin"]
    assert twin["available"] is True
    assert "host:10.53.0.1" in {node["id"] for node in twin["nodes"]}
    assert twin["summary"]["nodes"] >= 1

    audit = bundle["audit"]
    assert audit["count"] >= 1
    assert any(item["kind"] == "incident.create" for item in audit["items"])
    assert all(item["payload"].get("id") == incident["id"]
               for item in audit["items"]
               if item["kind"].startswith("incident."))
    assert all(item["entry_hash"] for item in audit["items"])

    models = bundle["models"]
    assert models["current"] == {"id": "spectra_iforest.joblib",
                                 "version": "3"}
    assert "spectra_iforest.joblib@3" in models["versions"]
    assert {row["model_id"] for row in models["alerts"]} == {
        "spectra_iforest.joblib"}


def test_bundle_paging_and_errors(env):
    incident, _ = seed_incident(env, host="10.54.0.1",
                                domain="page-c2.example.net")

    page = env.investigation.bundle(incident["id"], flow_limit=2)
    assert len(page["flows"]["items"]) == 2
    assert page["flows"]["count"] == 4 and page["flows"]["offset"] == 0

    page = env.investigation.bundle(incident["id"], flow_limit=2,
                                    flow_offset=2)
    assert page["flows"]["offset"] == 2
    assert len(page["flows"]["items"]) == 2
    assert page["flows"]["count"] == 4

    with pytest.raises(InvestigationNotFound):
        env.investigation.bundle(999_999_999)

    no_store = InvestigationService(None, Config())
    with pytest.raises(InvestigationUnavailable):
        no_store.bundle(1)
    with pytest.raises(InvestigationUnavailable):
        no_store.search("10.0.0.1")


def test_bundle_module_status_section(env):
    """Every advanced module: maturity, availability, and contribution."""
    incident, _ = seed_incident(env)
    # adversarial context: one robustness observation inside the window
    env.store.record_event("evasion", {"boundary": 1.0}, ts=BASE_TS + 40)
    bundle = env.investigation.bundle(incident["id"])

    modules = bundle["modules"]
    assert modules["scoring_policy"].startswith("No advanced module")
    items = {entry["key"]: entry for entry in modules["items"]}
    assert set(items) == set(capability_contracts())
    for entry in modules["items"]:
        assert entry["status"] in CAPABILITIES
        assert entry["hardware_backed"] is False
        assert entry["affects_alert_scoring"] is False
        assert entry["evidence_only"] is True
        assert entry["available"] is True
        assert entry["detail"] == "test probe"
        assert entry["summary"]

    counts = bundle["annotations"]["counts"]
    assert items["pqc"]["contributed"] == counts["pqc"]
    assert items["bio"]["contributed"] == counts["bio"]
    assert items["edge"]["contributed"] == counts["edge"]
    assert items["adversarial"]["contributed"] >= 1   # the recorded event
    assert items["correlation"]["contributed"] == len(bundle["graph"]["nodes"])
    assert items["audit"]["contributed"] == bundle["audit"]["count"]
    assert items["twin"]["contributed"] == (1 if bundle["twin"]["available"]
                                            else 0)
    # status-only modules contribute no per-alert evidence, by contract
    assert items["tee"]["contributed"] == 0
    assert items["federated"]["contributed"] == 0
    assert items["edge_deployment"]["contributed"] == 0


def test_bundle_module_status_degrades_when_probe_fails(env):
    """A failing capability probe never breaks the bundle."""
    incident, _ = seed_incident(env, host="10.56.0.1",
                                domain="probe-c2.example.net")

    def boom():
        raise RuntimeError("capability probe outage")

    broken = InvestigationService(
        env.store, env.cfg, graph_provider=lambda: env.graph,
        capability_provider=boom)
    bundle = broken.bundle(incident["id"])
    items = {entry["key"]: entry for entry in bundle["modules"]["items"]}
    assert set(items) == set(capability_contracts())
    # unprobed = None ("unknown"), not an error
    assert all(entry["available"] is None
               for entry in bundle["modules"]["items"])
    # contributions still render without live status
    assert items["pqc"]["contributed"] == bundle["annotations"]["counts"]["pqc"]
    assert items["adversarial"]["contributed"] == 0


# -- 4. global search (isolated service) --------------------------------------

def test_search_by_ip_and_domain(env):
    incident, seeds = seed_incident(env)

    res = env.investigation.search("10.51.0.1")
    assert res["query"] == "10.51.0.1" and res["kinds"] == [IP]
    assert set(res["results"]) == SEARCH_SECTIONS
    # search is time-agnostic: every flow on the host, window or not
    assert res["results"]["flows"]["count"] == 5
    assert res["results"]["alerts"]["count"] == 3
    assert res["results"]["incidents"]["count"] == 1
    assert res["results"]["hosts"]["count"] == 1
    assert res["results"]["hosts"]["items"][0]["label"] == "10.51.0.1"
    assert res["count"] == sum(s["count"] for s in res["results"].values())

    res = env.investigation.search("bundle-c2.example.net")
    assert res["kinds"] == [DOMAIN]
    assert res["results"]["flows"]["count"] == 3      # SNI match
    assert res["results"]["alerts"]["count"] == 3     # metadata match
    assert res["results"]["incidents"]["count"] == 1  # affected entity
    assert res["results"]["domains"]["count"] == 1
    assert res["results"]["domains"]["items"][0]["label"] == \
        "bundle-c2.example.net"


def test_search_by_ids_fingerprints_models_and_text(env):
    incident, seeds = seed_incident(env)
    cid = env.store.start_capture("pcap", "search-probe.pcap")

    # alert id
    res = env.investigation.search(seeds[0]["alert_id"])
    assert res["kinds"] == [ALERT_ID]
    assert res["results"]["alerts"]["count"] == 1
    assert res["results"]["flows"]["count"] == 0

    # numeric ids: incident id and capture id both resolve
    res = env.investigation.search(str(incident["id"]))
    assert res["kinds"] == [NUMBER]
    assert res["results"]["incidents"]["count"] == 1
    res = env.investigation.search(str(cid))
    assert res["results"]["captures"]["count"] == 1

    # JA3 fingerprint -> flow rows + alert metadata
    res = env.investigation.search("d" * 32)
    assert res["kinds"] == [JA3]
    assert res["results"]["flows"]["count"] == 3
    assert res["results"]["alerts"]["count"] == 3

    # model identity -> alerts + the current model
    res = env.investigation.search("spectra_iforest.joblib")
    assert res["kinds"] == [MODEL_ID]
    assert res["results"]["alerts"]["count"] == 3
    assert res["results"]["models"]["count"] == 2  # current + distinct pair
    assert res["results"]["models"]["items"][0]["current"] is True

    # free text -> titles, SNIs, threat text
    res = env.investigation.search("bundle")
    assert res["kinds"] == [TEXT]
    assert res["results"]["incidents"]["count"] == 1
    assert res["results"]["flows"]["count"] == 3
    assert res["results"]["domains"]["count"] == 1


def test_search_bounds_and_errors(env):
    incident, _ = seed_incident(env, host="10.55.0.1",
                                domain="bound-c2.example.net")

    # per-section limit is honoured; counts stay complete
    res = env.investigation.search("10.55.0.1", limit=1)
    assert res["limit"] == 1
    assert res["results"]["flows"]["count"] == 5
    assert len(res["results"]["flows"]["items"]) == 1

    # absurd limits clamp to the hard cap, never unbounded
    res = env.investigation.search("10.55.0.1", limit=10_000)
    assert res["limit"] <= 50

    with pytest.raises(InvestigationValidationError):
        env.investigation.search("   ")
    with pytest.raises(InvestigationValidationError):
        env.investigation.search("")


# -- 5. API surface (shared session database) ---------------------------------

def test_api_investigation_requires_authentication_and_role(raw_client,
                                                             viewer_client):
    assert raw_client.get("/api/investigations/1").status_code == 401
    assert raw_client.get("/api/search",
                          params={"q": "10.0.0.1"}).status_code == 401
    assert viewer_client.get("/api/investigations/1").status_code == 403
    assert viewer_client.get("/api/search",
                             params={"q": "10.0.0.1"}).status_code == 403


def _seed_api_flows(host: str, domain: str, *, dst_base: int = 174,
                    count: int = 3):
    """Alert flows on the shared engine, unique to this test.

    ``dst_base`` keeps API tests on disjoint destination hosts: the bus
    auto-attaches new related alerts to any active incident, and correlation
    needs a shared endpoint anchor - disjoint endpoints make each test's
    alerts independent of incidents raised by earlier ones.
    """
    seeds = []
    for i in range(count):
        record = rec(f"{host}:{43000 + i}", f"93.184.216.{dst_base + i}:443",
                     BASE_TS + 60 * i, sni=domain, ja3="e" * 32)
        alert = engine.threat_alerts.observe(record, verdict(), score=97.0)
        record["alert_id"] = alert["alert_id"]
        engine.store.save_flow(record, 97.0, True,
                               reasons=[{"feature": "iat_std_s",
                                         "z_score": 5.0}])
        engine.correlation.graph.observe(record)
        seeds.append(alert)
    engine.store.query_flows(limit=1)   # flush
    return seeds


def test_api_bundle_and_search(analyst_client):
    host, domain = "10.161.0.1", "api-bundle.example.net"
    seeds = _seed_api_flows(host, domain)
    res = analyst_client.post("/api/incidents", json={
        "title": "api bundle incident",
        "alert_ids": [a["alert_id"] for a in seeds],
    })
    assert res.status_code == 200, res.text
    incident_id = res.json()["id"]

    res = analyst_client.get(f"/api/investigations/{incident_id}")
    assert res.status_code == 200, res.text
    bundle = res.json()
    assert set(bundle) == BUNDLE_KEYS
    assert bundle["alerts"]["count"] == 3
    assert bundle["flows"]["count"] >= 3
    assert any(row["src"].startswith(host) for row in bundle["flows"]["items"])
    assert bundle["graph"]["available"] is True

    # paging the related flows
    page = analyst_client.get(f"/api/investigations/{incident_id}",
                              params={"flow_limit": 1, "flow_offset": 0})
    assert page.status_code == 200
    body = page.json()
    assert len(body["flows"]["items"]) == 1
    assert body["flows"]["count"] == bundle["flows"]["count"]

    # unknown incident, bad id
    assert analyst_client.get("/api/investigations/999999999").status_code == 404
    assert analyst_client.get("/api/investigations/abc").status_code == 422

    # global search: IP
    res = analyst_client.get("/api/search", params={"q": host})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["kinds"] == [IP]
    assert set(body["results"]) == SEARCH_SECTIONS
    assert body["results"]["flows"]["count"] >= 3
    assert body["results"]["alerts"]["count"] == 3
    assert body["results"]["incidents"]["count"] >= 1

    # global search: alert id
    res = analyst_client.get("/api/search", params={"q": seeds[0]["alert_id"]})
    assert res.json()["results"]["alerts"]["count"] >= 1

    # global search: domain
    res = analyst_client.get("/api/search", params={"q": domain})
    assert res.json()["kinds"] == [DOMAIN]

    # validation: blank -> 422 (router), whitespace -> 400 (service)
    assert analyst_client.get("/api/search", params={"q": ""}).status_code == 422
    assert analyst_client.get("/api/search",
                              params={"q": "   "}).status_code == 400


def test_api_alert_and_incident_filters(analyst_client):
    host = "10.163.0.1"
    seeds = _seed_api_flows(host, "filter-api.example.net", dst_base=184)
    res = analyst_client.post("/api/incidents", json={
        "title": "api filter incident",
        "alert_ids": [a["alert_id"] for a in seeds],
    })
    assert res.status_code == 200, res.text
    incident_id = res.json()["id"]

    # alerts: endpoint + severity + protocol + score + time
    page = analyst_client.get("/api/alerts", params={"source": host}).json()
    assert page["count"] == 3
    assert all(row["source"].startswith(host) for row in page["items"])
    assert analyst_client.get(
        "/api/alerts", params={"source": host,
                               "severity": "HIGH"}).json()["count"] == 3
    assert analyst_client.get(
        "/api/alerts", params={"source": host,
                               "severity": "CRITICAL"}).json()["count"] == 0
    assert analyst_client.get(
        "/api/alerts", params={"source": host, "protocol": "TCP",
                               "min_score": 50,
                               "since": BASE_TS - 60,
                               "until": BASE_TS + 3600}).json()["count"] == 3
    assert analyst_client.get(
        "/api/alerts", params={"source": host,
                               "until": BASE_TS - 1000}).json()["count"] == 0
    assert analyst_client.get("/api/alerts",
                              params={"severity": "BOGUS"}).status_code == 422

    # incidents: severity + overlap time range
    page = analyst_client.get("/api/incidents",
                              params={"severity": "HIGH"}).json()
    assert incident_id in [row["id"] for row in page["items"]]
    page = analyst_client.get("/api/incidents",
                              params={"severity": "LOW"}).json()
    assert incident_id not in [row["id"] for row in page["items"]]
    page = analyst_client.get(
        "/api/incidents", params={"since": BASE_TS - 60,
                                  "until": BASE_TS + 3600}).json()
    assert incident_id in [row["id"] for row in page["items"]]
    page = analyst_client.get(
        "/api/incidents", params={"until": BASE_TS - 1000}).json()
    assert incident_id not in [row["id"] for row in page["items"]]


def test_api_history_filters_and_pagination(analyst_client):
    # flows: endpoint + proto + score + time, all bounded by count/offset
    save(engine, rec("10.164.0.1:44000", "93.184.216.190:443", BASE_TS + 700))
    save(engine, rec("10.164.0.2:44001", "93.184.216.191:443", BASE_TS + 710,
                     proto="UDP", score=12.0, anomaly=False))
    engine.store.query_flows(limit=1)   # flush

    page = analyst_client.get("/api/history/flows",
                              params={"src": "10.164.0.1"}).json()
    assert page["count"] == 1 and page["offset"] == 0
    assert page["items"][0]["src"] == "10.164.0.1:44000"
    page = analyst_client.get("/api/history/flows",
                              params={"proto": "UDP"}).json()
    assert page["count"] >= 1
    assert all(row["proto"] == "UDP" for row in page["items"])
    page = analyst_client.get("/api/history/flows",
                              params={"src": "10.164.0.1",
                                      "min_score": 50,
                                      "since": BASE_TS,
                                      "until": BASE_TS + 800}).json()
    assert page["count"] == 1
    page = analyst_client.get("/api/history/flows",
                              params={"since": 1e15}).json()
    assert page["count"] == 0

    # detections share the filter vocabulary
    page = analyst_client.get("/api/history/detections",
                              params={"src": "10.164.0.1"}).json()
    assert page["count"] == 1
    page = analyst_client.get("/api/history/detections",
                              params={"src": "10.164.0.1",
                                      "max_score": 50}).json()
    assert page["count"] == 0

    # captures: status + offset envelope
    cid = engine.store.start_capture("pcap", "history-probe.pcap")
    page = analyst_client.get("/api/history/captures",
                              params={"status": "PROCESSING"}).json()
    assert page["count"] >= 1
    assert any(row["id"] == cid for row in page["items"])
    page = analyst_client.get("/api/history/captures",
                              params={"status": "FAILED"}).json()
    assert page["count"] == 0
    assert analyst_client.get("/api/history/captures",
                              params={"status": "NOPE"}).status_code == 422

    # model runs: offset + count
    engine.store.add_model_run("hist-a.pcap", 10, 0.02, {"auc": 0.9})
    engine.store.add_model_run("hist-b.pcap", 20, 0.05, {"auc": 0.8})
    top = analyst_client.get("/api/history/model-runs",
                             params={"limit": 1, "offset": 0}).json()
    nxt = analyst_client.get("/api/history/model-runs",
                             params={"limit": 1, "offset": 1}).json()
    assert top["count"] >= 2 and top["offset"] == 0
    assert nxt["offset"] == 1
    assert top["items"][0]["id"] > nxt["items"][0]["id"]

    # events: type + time range
    engine.store.record_event("investigation_api_probe", {"ok": True})
    page = analyst_client.get(
        "/api/history/events",
        params={"type": "investigation_api_probe", "since": 0}).json()
    assert page["count"] == 1
    page = analyst_client.get(
        "/api/history/events",
        params={"type": "investigation_api_probe", "since": 1e15}).json()
    assert page["count"] == 0


def test_api_audit_time_and_actor_filters(analyst_client):
    page = analyst_client.get("/api/audit/entries",
                              params={"since": 0, "limit": 5}).json()
    assert "count" in page and "signing_key" in page
    assert len(page["items"]) <= 5
    page = analyst_client.get("/api/audit/entries",
                              params={"since": 1e15}).json()
    assert page["count"] == 0 and page["items"] == []
    page = analyst_client.get("/api/audit/entries",
                              params={"actor": "ghost-user"}).json()
    assert page["count"] == 0
