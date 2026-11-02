"""The incident layer above alerts: correlation, states, timeline, audit.

Multiple *related* alerts become one incident; unrelated activity never does.
The pure rules (:mod:`spectra.incident_correlation`) are tested first with a
score/signal matrix, then the service (create/correlate/attach, the full
state machine including FALSE_POSITIVE + reopen, rollups, timeline,
persistence, audit), the pipeline wiring (auto-attach on the bus), and the
API surface (routes, filters, permissions, error codes).

Every service test runs on an isolated temp store; only the engine/API tests
touch the shared session database, and they use unique hosts plus explicit
alert-id selections so ordering cannot change their outcomes.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from spectra.api.app import app
from spectra.api.runtime import engine
from spectra.config import Config
from spectra.incident_correlation import (
    MIN_SCORE,
    auto_title,
    cluster,
    related,
    rollup,
)
from spectra.modules.corr import CorrelationGraph
from spectra.pipeline import SpectraEngine
from spectra.services.audit import AuditService
from spectra.services.events import EventBus
from spectra.services.incidents import (
    AlertClaimed,
    IncidentError,
    IncidentNotFound,
    IncidentService,
    IncidentStateError,
    IncidentValidationError,
    LinkedAlertNotFound,
)
from spectra.services.resilience import FailureTracker
from spectra.services.threat_alerts import ThreatAlertService
from spectra.store import Store

client = TestClient(app)  # session-scoped admin (conftest)

BASE_TS = 1_700_000_000.0


# -- helpers -------------------------------------------------------------------


def make_env(tmp_path, *, window: float = 1800.0):
    """Isolated store + alert + incident services, wired like the pipeline.

    The bus carries alert events to ``incidents.observe_alert`` exactly as
    ``SpectraEngine`` subscribes it, so auto-attach is exercised for real.
    """
    cfg = Config()
    cfg.alert_group_seconds = 600.0
    cfg.incident_window_seconds = window
    store = Store(str(tmp_path / "incidents.db"))
    bus = EventBus()
    graph = CorrelationGraph()
    failures = FailureTracker({})
    audit = AuditService(store, str(tmp_path / "model.joblib"), failures)
    alerts = ThreatAlertService(store, cfg, bus, failures,
                                model_info=lambda: {
                                    "id": "spectra_iforest.joblib",
                                    "version": "3"})
    incidents = IncidentService(store, cfg, failures=failures, audit=audit,
                                graph_provider=lambda: graph)
    # Mirror SpectraEngine: the bus carries the event envelope, so the
    # listener extracts the alert exactly like pipeline._incidents_observe_event.
    def _to_correlator(event: dict) -> None:
        if str(event.get("type", "")) in ("alert", "alert_updated"):
            incidents.observe_alert(event.get("data") or {})

    bus.subscribe(_to_correlator)
    return SimpleNamespace(store=store, bus=bus, graph=graph, cfg=cfg,
                           failures=failures, audit=audit, alerts=alerts,
                           incidents=incidents)


def rec(src: str, dst: str, ts: float, *, sni: str | None = None) -> dict:
    """A completed flow record shaped like the publication path."""
    return {
        "src": src, "dst": dst, "proto": "TCP",
        "start_ts": ts, "last_ts": ts + 10.0,
        "duration": 10.0, "packets": 30, "bytes": 1600,
        "sni": sni, "tls_version": "TLS 1.3" if sni else None,
        "quic_version": None, "alpn": "h2" if sni else None,
        "ja3": None, "ja4": None, "slice": None,
        "score": 97.0, "anomaly": True,
    }


def verdict(threat_type: str = "C2_BEACONING",
            confidence: float = 0.72) -> dict:
    return {"threat_type": threat_type, "confidence": confidence,
            "supporting": [], "contradicting": []}


def raise_alert(env, *, src: str, dst: str, ts: float,
                threat_type: str = "C2_BEACONING",
                confidence: float = 0.72, sni: str | None = None,
                score: float = 97.0) -> dict:
    """Observe one flagged flow so a real alert (bus events included) exists."""
    record = rec(src, dst, ts, sni=sni)
    alert = env.alerts.observe(record, verdict(threat_type, confidence),
                               score=score)
    if env.graph is not None and sni:
        env.graph.observe(record)
    return alert


def alertish(**overrides) -> dict:
    """A minimal alert-shaped dict for the pure correlation functions."""
    base = {
        "alert_id": "alrt_base", "source": "10.0.0.5:40000",
        "destination": "1.2.3.4:443", "threat_type": "C2_BEACONING",
        "first_seen": 1000.0, "last_seen": 1010.0, "confidence": 0.8,
        "severity": "HIGH", "occurrences": 1, "status": "OPEN",
        "metadata": {"sni": None},
    }
    base.update(overrides)
    return base


def timeline_kinds(env, incident_id: int) -> list[str]:
    return [e["kind"] for e in env.store.incident_events(incident_id)]


# -- pure correlation rules ----------------------------------------------------

def test_related_requires_anchor_and_score():
    """Gates: anchor AND score >= MIN_SCORE — threat+time alone never merges."""
    a = alertish()
    # same destination anchor + threat + proximity: comfortably related
    b = alertish(alert_id="b", source="10.0.0.6:51111")
    ok, score, signals = related(a, b, window=1800.0)
    assert ok and score >= MIN_SCORE
    assert any(s.startswith("same destination host") for s in signals)
    assert any(s.startswith("same threat type") for s in signals)

    # same threat + proximate in time, but different endpoints: NOT related
    c = alertish(alert_id="c", source="10.9.9.9:1",
                 destination="5.6.7.8:80")
    ok, score, _ = related(a, c, window=1800.0)
    assert not ok and score < MIN_SCORE

    # nothing shared at all (only the proximity point — never enough)
    d = alertish(alert_id="d", source="10.4.4.4:1",
                 destination="6.6.6.6:80", threat_type="TLS_ANOMALY")
    ok, score, _ = related(a, d, window=1800.0)
    assert not ok and score < MIN_SCORE

    # same source anchor still needs one more point across the window
    far = alertish(alert_id="e", first_seen=3000.0, last_seen=3010.0,
                   threat_type="TLS_ANOMALY")
    ok, score, _ = related(a, far, window=1800.0)  # gap 1990s > window
    assert not ok and score == 0.0  # hard temporal gate


def test_related_weak_signals_and_subnets_never_anchor():
    """Shared /24 boosts an anchored pair but cannot anchor on its own."""
    # two different sources in the same /24, different destinations
    a = alertish(alert_id="a", source="10.0.0.5:1")
    b = alertish(alert_id="b", source="10.0.0.6:2",
                 destination="5.6.7.8:80")
    ok, score, _ = related(a, b, window=1800.0)
    assert not ok, "a /24 alone must never anchor an incident"

    # anchored (same source) + different threat + proximate = 3+0+1 = 4
    c = alertish(alert_id="c", destination="5.6.7.8:80",
                 threat_type="TLS_ANOMALY", confidence=0.4)
    ok, score, _ = related(a, c, window=1800.0)
    assert ok and score == 4.0

    # anchored + different threat + shared destination /24 + time: subnet helps
    d = alertish(alert_id="d", source="10.0.0.5:9",
                 destination="1.2.3.9:80", threat_type="TLS_ANOMALY",
                 confidence=0.4, first_seen=1700.0, last_seen=1710.0)
    ok, score, signals = related(a, d, window=1800.0)
    assert ok and any("shared destination subnet" in s for s in signals)

    # repeated beaconing: same destination, different labels, gap beyond the
    # proximity half-window — the beacon signal is what pushes it over.
    beacon = alertish(alert_id="e", occurrences=3)
    other = alertish(alert_id="f", source="10.7.7.7:1",
                     threat_type="TLS_ANOMALY", confidence=0.4,
                     first_seen=2700.0, last_seen=2710.0)
    ok, score, signals = related(beacon, other, window=1800.0)
    assert ok and any("repeated beaconing" in s for s in signals)

    # UNKNOWN labels carry no threat signal (anchor + time must carry it)
    u1 = alertish(alert_id="u1", threat_type="UNKNOWN_ANOMALY")
    u2 = alertish(alert_id="u2", source="10.8.8.8:1",
                  destination="9.9.9.9:80", threat_type="UNKNOWN_ANOMALY",
                  first_seen=2700.0, last_seen=2710.0)
    ok, score, _ = related(u1, u2, window=1800.0)
    assert not ok, "two unknowns sharing no endpoint must not merge"


def test_related_graph_and_sni_signals():
    """SNI identity and direct graph edges are first-class anchors."""
    graph = CorrelationGraph()
    # observed traffic: 10.0.0.5 -> 1.2.3.4 (creates host->ip edge)
    graph.observe({"src": "10.0.0.5:22", "dst": "1.2.3.4:80", "sni": None,
                   "last_ts": 900.0, "bytes": 100, "anomaly": True})

    # graph anchor: A's source is a known interlocutor of B's destination,
    # while no exact endpoint matches (srcs differ, dsts differ).
    a = alertish(alert_id="ga", source="10.0.0.5:40000",
                 destination="9.9.9.9:80")
    b = alertish(alert_id="gb", source="10.7.7.7:1",
                 destination="1.2.3.4:80", first_seen=1200.0,
                 last_seen=1210.0)
    ok, score, signals = related(a, b, window=1800.0, graph=graph)
    assert ok and any(s.startswith("graph-linked") for s in signals)
    # without the graph the same pair stays unmerged
    ok, score, _ = related(a, b, window=1800.0, graph=None)
    assert not ok

    # SNI anchor across different destinations
    s1 = alertish(alert_id="s1", destination="10.0.0.1:443",
                  metadata={"sni": "Portal.Example"})
    s2 = alertish(alert_id="s2", destination="10.0.0.2:443",
                  metadata={"sni": "portal.example."})
    ok, score, signals = related(s1, s2, window=1800.0)
    assert ok and any("same SNI" in s for s in signals)


def test_cluster_groups_related_and_keeps_unrelated_apart():
    """Union-find over the same rules: chains join, strangers stay single."""
    related_pair = [
        alertish(alert_id="a", source="10.0.0.5:1"),
        alertish(alert_id="b", source="10.0.0.6:2"),
    ]
    stranger = alertish(alert_id="c", source="10.9.9.9:1",
                        destination="5.6.7.8:80")
    out_of_window = alertish(alert_id="d", source="10.0.0.5:1",
                             first_seen=5000.0, last_seen=5010.0)
    groups = cluster(related_pair + [stranger, out_of_window], window=1800.0)
    partition = {frozenset(x["alert_id"] for x in g) for g in groups}
    assert partition == {frozenset({"a", "b"}),
                         frozenset({"c"}), frozenset({"d"})}


def test_rollup_derives_incident_fields_deterministically():
    """Severity = ordinal max; confidence/threat belong to the primary."""
    env = SimpleNamespace(
        store=None, bus=None, failures=None, audit=None, cfg=None,
        alerts=ThreatAlertService(None, Config(), None, None,
                                  model_info=lambda: {
                                      "id": "spectra_iforest.joblib",
                                      "version": "3"}),
        graph=CorrelationGraph())
    c2 = raise_alert(env, src="10.20.0.1:1", dst="beacon.example.org:8443",
                     ts=BASE_TS, sni="beacon.example.org")
    exfil = raise_alert(env, src="10.20.0.2:2", dst="drop.example.org:443",
                        ts=BASE_TS + 60, threat_type="DATA_EXFILTRATION_SUSPECTED",
                        confidence=0.95)
    tls = raise_alert(env, src="10.20.0.3:3", dst="odd.example.org:443",
                      ts=BASE_TS + 120, threat_type="TLS_ANOMALY",
                      confidence=0.5, score=50.0)
    assert (c2["severity"], exfil["severity"], tls["severity"]) == \
        ("HIGH", "CRITICAL", "LOW")

    fields = rollup([c2, exfil, tls], graph=env.graph)
    assert fields["alert_count"] == 3
    assert fields["first_seen"] == min(a["first_seen"] for a in (c2, exfil, tls))
    assert fields["last_seen"] == max(a["last_seen"] for a in (c2, exfil, tls))
    # ordinal max, and the most severe member is the primary
    assert fields["severity"] == "CRITICAL"
    assert fields["primary_threat_class"] == "DATA_EXFILTRATION_SUSPECTED"
    assert fields["confidence"] == 0.95  # primary's confidence, not an average
    assert {"10.20.0.1", "10.20.0.2", "10.20.0.3",
            "beacon.example.org"} <= set(fields["affected_entities"])
    assert fields["model_versions"] == ["spectra_iforest.joblib@3"]
    assert fields["related_graph_nodes"]  # observed nodes were found
    assert fields["evidence_summary"].startswith(
        "3 linked alert(s); DATA_EXFILTRATION_SUSPECTED:")

    # empty incidents roll up to zeros, not errors
    empty = rollup([])
    assert empty["alert_count"] == 0 and empty["severity"] is None
    assert "activity" in auto_title([c2, exfil])


# -- service: create / correlate / attach ---------------------------------------

def test_create_from_alerts_links_and_rolls_up(tmp_path):
    env = make_env(tmp_path)
    a = raise_alert(env, src="10.30.0.1:1", dst="c2.example.net:8443",
                    ts=BASE_TS)
    b = raise_alert(env, src="10.30.0.2:2", dst="c2.example.net:8443",
                    ts=BASE_TS + 300)
    c = raise_alert(env, src="10.30.0.3:3", dst="c2.example.net:8443",
                    ts=BASE_TS + 600)

    incident = env.incidents.create("", None, "ana",
                                    alert_ids=[a["alert_id"], b["alert_id"],
                                               c["alert_id"]],
                                    summary="beaconing from the lab")
    assert incident["status"] == "OPEN"
    assert incident["alert_count"] == 3
    assert incident["summary"] == "beaconing from the lab"
    assert incident["severity"] == "HIGH"
    assert incident["primary_threat_class"] == "C2_BEACONING"
    assert incident["confidence"] == pytest.approx(0.72)
    assert incident["first_seen"] == a["first_seen"]
    assert incident["last_seen"] == c["last_seen"]
    assert "c2.example.net" in incident["affected_entities"]
    assert incident["model_versions"] == ["spectra_iforest.joblib@3"]
    assert incident["evidence_summary"].startswith("3 linked alert(s)")
    assert "C2_BEACONING" in incident["title"]  # auto-titled from alerts

    detail = env.incidents.detail(incident["id"])
    assert len(detail["alerts"]) == 3
    assert detail["timeline"][0]["kind"] == "created"
    assert timeline_kinds(env, incident["id"]).count("alert_added") == 3
    # single ownership is enforced by the relation itself
    assert all(env.store.incident_for_alert(x["alert_id"]) == incident["id"]
               for x in (a, b, c))


def test_create_validates_alerts_and_title(tmp_path):
    env = make_env(tmp_path)
    with pytest.raises(LinkedAlertNotFound):
        env.incidents.create("x", None, "ana", alert_ids=["alrt_nope"])
    with pytest.raises(IncidentValidationError):
        env.incidents.create("   ", None, "ana")  # legacy: empty title
    # a detection anchor still validates exactly as before
    with pytest.raises(IncidentError) as missing:
        env.incidents.create("x", 999999, "ana")
    assert missing.value.status_code == 404
    # >200 alerts in one incident is refused (bounded rows)
    with pytest.raises(IncidentValidationError):
        env.incidents.create("x", None, "ana",
                             alert_ids=[f"alrt_{i}" for i in range(201)])


def test_correlate_creates_one_incident_per_cluster(tmp_path):
    env = make_env(tmp_path)
    related_group = [
        raise_alert(env, src=f"10.40.0.{i}:1", dst="cluster.example.net:8443",
                    ts=BASE_TS + 100 * i)
        for i in (1, 2, 3)
    ]
    # two strangers: same threat, close in time, but no anchor between them
    # (different endpoints) nor to the cluster - they must stay unmerged.
    unrelated = [
        raise_alert(env, src=f"10.41.0.{i}:2",
                    dst=f"lonely-{i}.example.net:80",
                    ts=BASE_TS + 100 * i, threat_type="TLS_ANOMALY",
                    confidence=0.5, score=50.0)
        for i in (1, 2)
    ]

    result = env.incidents.correlate("ana")
    assert result["clusters"] == 1
    assert result["considered"] == 5
    assert len(result["created"]) == 1
    incident = result["created"][0]
    assert incident["alert_count"] == 3
    assert {a["alert_id"] for a in env.store.get_incident_alerts(
        incident["id"])} == {a["alert_id"] for a in related_group}
    # the two same-threat strangers are reported, not merged
    assert set(result["ungrouped"]) == {a["alert_id"] for a in unrelated}

    # a second pass finds nothing new to group (idempotent)
    again = env.incidents.correlate("ana")
    assert again["clusters"] == 0 and again["created"] == []
    kinds = {e["kind"] for e in env.store.audit_entries(limit=50)}
    assert "incident.correlate" in kinds


def test_correlate_with_explicit_unrelated_alerts_stays_ungrouped(tmp_path):
    """Even an explicit correlate call refuses to blind-merge strangers."""
    env = make_env(tmp_path)
    a = raise_alert(env, src="10.42.0.1:1", dst="one.example.net:80",
                    ts=BASE_TS, threat_type="TLS_ANOMALY", confidence=0.5,
                    score=50.0)
    b = raise_alert(env, src="10.43.0.2:2", dst="two.example.net:80",
                    ts=BASE_TS + 30, threat_type="TLS_ANOMALY",
                    confidence=0.5, score=50.0)
    result = env.incidents.correlate("ana",
                                     alert_ids=[a["alert_id"], b["alert_id"]])
    assert result["created"] == [] and result["clusters"] == 0
    assert set(result["ungrouped"]) == {a["alert_id"], b["alert_id"]}


# -- service: auto-attach --------------------------------------------------------

def test_auto_attaches_related_new_alert_and_refuses_unrelated(tmp_path):
    env = make_env(tmp_path)
    a = raise_alert(env, src="10.50.0.1:1", dst="wire.example.net:8443",
                    ts=BASE_TS)
    incident = env.incidents.create("wire", None, "ana",
                                    alert_ids=[a["alert_id"]])
    # related: same destination + threat + time -> joins the open incident
    b = raise_alert(env, src="10.50.0.2:2", dst="wire.example.net:8443",
                    ts=BASE_TS + 600)
    assert env.store.incident_for_alert(b["alert_id"]) == incident["id"]
    detail = env.incidents.detail(incident["id"])
    assert detail["alert_count"] == 2
    join = [e for e in detail["timeline"] if e["kind"] == "alert_added"][-1]
    assert join["data"]["source"] == "auto" and join["actor"] == "spectra"
    assert join["data"]["score"] >= MIN_SCORE
    assert "same destination host" in join["data"]["reason"]
    assert detail["last_seen"] == b["last_seen"]  # rollup refreshed
    # unrelated: same threat, no anchor -> stays out
    c = raise_alert(env, src="10.51.0.9:3", dst="elsewhere.example.org:80",
                    ts=BASE_TS + 610)
    assert env.store.incident_for_alert(c["alert_id"]) is None
    assert env.incidents.detail(incident["id"])["alert_count"] == 2
    # correlation never CREATES incidents by itself
    assert env.store.list_incidents()["count"] == 1


def test_auto_attach_skips_closed_incidents_and_resolved_alerts(tmp_path):
    env = make_env(tmp_path)
    a = raise_alert(env, src="10.60.0.1:1", dst="closed.example.net:8443",
                    ts=BASE_TS)
    incident = env.incidents.create("closed", None, "ana",
                                    alert_ids=[a["alert_id"]])
    env.incidents.resolve(incident["id"], "ana")
    # related alert, but the incident is terminal
    b = raise_alert(env, src="10.60.0.2:2", dst="closed.example.net:8443",
                    ts=BASE_TS + 300)
    assert env.store.incident_for_alert(b["alert_id"]) is None

    # a resolved alert never joins an active incident either
    x = raise_alert(env, src="10.61.0.1:1", dst="live.example.net:8443",
                    ts=BASE_TS)
    open_incident = env.incidents.create("live", None, "ana",
                                         alert_ids=[x["alert_id"]])
    w = raise_alert(env, src="10.61.0.2:2", dst="lonely.example.net:8443",
                    ts=BASE_TS + 60)
    assert env.store.incident_for_alert(w["alert_id"]) is None  # unassigned
    env.alerts.resolve(w["alert_id"])  # emits alert_updated (RESOLVED)
    assert env.store.incident_for_alert(w["alert_id"]) is None
    assert env.incidents.detail(open_incident["id"])["alert_count"] == 1


# -- service: state machine ------------------------------------------------------

def test_status_transition_matrix(tmp_path):
    """Every legal edge works; every other edge raises IncidentStateError."""
    env = make_env(tmp_path)
    inc = env.incidents.create("walk", None, "ana")

    # legal walk covering all five states
    assert env.incidents.investigate(inc["id"], "ana")["status"] == \
        "INVESTIGATING"
    assert env.incidents.resolve(inc["id"], "ana")["status"] == "RESOLVED"
    assert env.incidents.reopen(inc["id"], "ana")["status"] == \
        "INVESTIGATING"
    assert env.incidents.mark_false_positive(inc["id"], "ana")["status"] == \
        "FALSE_POSITIVE"
    assert env.incidents.reopen(inc["id"], "ana")["status"] == \
        "INVESTIGATING"
    assert env.incidents.resolve(inc["id"], "ana")["status"] == "RESOLVED"

    # illegal edges
    with pytest.raises(IncidentStateError):
        env.incidents.acknowledge(inc["id"], "ana")      # only from OPEN
    with pytest.raises(IncidentStateError):
        env.incidents.resolve(inc["id"], "ana")          # terminal
    with pytest.raises(IncidentStateError):
        env.incidents.investigate(inc["id"], "ana")      # already resolved
    fresh = env.incidents.create("fresh", None, "ana")
    with pytest.raises(IncidentStateError):
        env.incidents.reopen(fresh["id"], "ana")         # OPEN is not closed

    inc2 = env.incidents.create("ack walk", None, "ana")
    assert env.incidents.acknowledge(inc2["id"], "ana")["status"] == \
        "ACKNOWLEDGED"
    with pytest.raises(IncidentStateError):
        env.incidents.acknowledge(inc2["id"], "ana")      # no double-ack
    assert env.incidents.investigate(inc2["id"], "ana")["status"] == \
        "INVESTIGATING"

    inc3 = env.incidents.create("fp walk", None, "ana")
    env.incidents.mark_false_positive(inc3["id"], "ana")
    with pytest.raises(IncidentStateError) as fp_resolve:
        env.incidents.resolve(inc3["id"], "ana")          # reopen first
    assert "reopen" in str(fp_resolve.value)
    with pytest.raises(IncidentStateError):
        env.incidents.acknowledge(inc3["id"], "ana")


def test_transitions_persist_timeline_and_audit(tmp_path):
    """History is auditable twice over: timeline rows + hash-chained log."""
    env = make_env(tmp_path)
    a = raise_alert(env, src="10.70.0.1:1", dst="hist.example.net:8443",
                    ts=BASE_TS)
    b = raise_alert(env, src="10.70.0.2:2", dst="hist.example.net:8443",
                    ts=BASE_TS + 300)
    inc = env.incidents.create("", None, "ana", alert_ids=[a["alert_id"],
                                                           b["alert_id"]])
    env.incidents.investigate(inc["id"], "ana")
    env.incidents.resolve(inc["id"], "ana")

    events = env.store.incident_events(inc["id"])
    assert [e["kind"] for e in events] == [
        "created", "alert_added", "alert_added",
        "status_changed", "status_changed"]
    changes = [e for e in events if e["kind"] == "status_changed"]
    assert changes[0]["data"] == {"from": "OPEN", "to": "INVESTIGATING",
                                  "action": "investigate"}
    assert changes[1]["data"]["to"] == "RESOLVED"
    assert all(e["actor"] == "ana" for e in events)

    # every state-changing action is in the audit log under its actor
    for kind in ("incident.create", "incident.investigate",
                 "incident.resolve"):
        entries = env.store.audit_entries(limit=20, kind=kind)
        assert entries, f"missing audit kind {kind}"
        assert entries[-1]["actor"] == "ana"

    # persistence: a fresh Store on the same file sees status + history
    fresh = Store(str(tmp_path / "incidents.db"))
    row = fresh.get_incident(inc["id"])
    assert row["status"] == "RESOLVED" and row["alert_count"] == 2
    assert row["updated_by"] == "ana" and row["resolved_by"] == "ana"
    assert len([e for e in fresh.incident_events(inc["id"])
                if e["kind"] == "status_changed"]) == 2
    assert len(fresh.get_incident_alerts(inc["id"])) == 2


def test_false_positive_is_recorded_and_reopened(tmp_path):
    """FALSE_POSITIVE is a real, auditable, reversible assessment."""
    env = make_env(tmp_path)
    inc = env.incidents.create("fp case", None, "ana")
    out = env.incidents.mark_false_positive(inc["id"], "bob")
    assert out["status"] == "FALSE_POSITIVE"
    assert out["updated_by"] == "bob" and out["updated_at"] is not None

    fresh = Store(str(tmp_path / "incidents.db"))
    assert fresh.get_incident(inc["id"])["status"] == "FALSE_POSITIVE"

    back = env.incidents.reopen(inc["id"], "bob")
    assert back["status"] == "INVESTIGATING"
    actions = [e["data"].get("action") for e in
               env.store.incident_events(inc["id"])
               if e["kind"] == "status_changed"]
    assert actions == ["false_positive", "reopen"]
    entries = env.store.audit_entries(limit=10,
                                      kind="incident.false_positive")
    assert entries and entries[-1]["actor"] == "bob"


def test_attach_validations_and_manual_relation(tmp_path):
    env = make_env(tmp_path)
    a = raise_alert(env, src="10.80.0.1:1", dst="own-one.example.net:8443",
                    ts=BASE_TS)
    b = raise_alert(env, src="10.80.0.2:2", dst="own-one.example.net:8443",
                    ts=BASE_TS + 60)
    c = raise_alert(env, src="10.80.0.3:3", dst="own-two.example.net:8443",
                    ts=BASE_TS + 120)
    inc1 = env.incidents.create("one", None, "ana", alert_ids=[a["alert_id"]])
    inc2 = env.incidents.create("two", None, "ana", alert_ids=[b["alert_id"]])

    with pytest.raises(IncidentNotFound):
        env.incidents.attach(999999, [c["alert_id"]], "ana")
    with pytest.raises(LinkedAlertNotFound):
        env.incidents.attach(inc1["id"], ["alrt_missing"], "ana")
    with pytest.raises(AlertClaimed):
        env.incidents.attach(inc1["id"], [b["alert_id"]], "ana")  # inc2 owns it

    detail = env.incidents.attach(inc1["id"], [c["alert_id"]], "ana")
    assert detail["alert_count"] == 2  # a + c
    join = [e for e in detail["timeline"] if e["kind"] == "alert_added"][-1]
    assert join["data"]["source"] == "manual" and join["actor"] == "ana"
    entries = env.store.audit_entries(limit=10, kind="incident.alert_add")
    assert entries and entries[-1]["actor"] == "ana"

    # closed incidents refuse new members until reopened
    env.incidents.resolve(inc1["id"], "ana")
    d = raise_alert(env, src="10.80.0.4:4", dst="free.example.net:80",
                    ts=BASE_TS + 180)
    with pytest.raises(IncidentStateError):
        env.incidents.attach(inc1["id"], [d["alert_id"]], "ana")
    assert env.store.incident_for_alert(d["alert_id"]) is None


def test_notes_appear_in_detail_and_timeline(tmp_path):
    env = make_env(tmp_path)
    inc = env.incidents.create("noted", None, "ana")
    note = env.incidents.add_note(inc["id"], "correlates with edge", "ana")
    assert note["author"] == "ana"
    with pytest.raises(IncidentValidationError):
        env.incidents.add_note(inc["id"], "   ", "ana")

    detail = env.incidents.detail(inc["id"])
    assert detail["note_count"] == 1 and detail["notes"][0]["body"] == \
        "correlates with edge"
    assert detail["alerts"] == [] and detail["timeline"][-1]["kind"] == \
        "note_added"
    assert detail["timeline"][-1]["data"]["note_id"] == note["id"]


# -- pipeline wiring ---------------------------------------------------------------

def test_engine_wires_alert_events_to_incident_correlation(tmp_path):
    """SpectraEngine subscribes the correlator: alerts flow into incidents."""
    engine_e = SpectraEngine(model_path=str(tmp_path / "model.joblib"),
                             idle_timeout=30.0)
    a = engine_e.threat_alerts.observe(
        rec("10.90.0.1:40001", "engine-wire.example.net:8443", BASE_TS),
        verdict(), score=97.0)
    incident = engine_e.incidents.create("wired", None, "tester",
                                         alert_ids=[a["alert_id"]])
    # a later related alert travels bus -> _incidents_observe_event -> attach
    c = engine_e.threat_alerts.observe(
        rec("10.90.0.2:40002", "engine-wire.example.net:8443",
            BASE_TS + 300),
        verdict(), score=95.0)
    assert engine_e.store.incident_for_alert(c["alert_id"]) == incident["id"]
    assert engine_e.incidents.detail(incident["id"])["alert_count"] == 2

    # unrelated alert stays unassigned
    e = engine_e.threat_alerts.observe(
        rec("10.91.0.3:40003", "engine-other.example.org:80", BASE_TS + 310),
        verdict("TLS_ANOMALY", 0.5), score=50.0)
    assert engine_e.store.incident_for_alert(e["alert_id"]) is None
    engine_e.incidents.resolve(incident["id"], "tester")  # tidy the shared db


# -- API surface -------------------------------------------------------------------

def _seed_api(src, dst: str, ts: float, *, threat="C2_BEACONING",
              confidence=0.72, score=97.0) -> dict:
    """Seed one alert on the shared runtime engine (unique hosts per test)."""
    return engine.threat_alerts.observe(
        rec(src, dst, ts), verdict(threat, confidence), score=score)


def test_api_incident_alert_layer_workflow(analyst_client):
    # 1. three related alerts -> one incident from explicit selection
    seeds = [
        _seed_api(f"10.101.0.{i}:4000{i}", "api-incident.example.net:8443",
                  BASE_TS + 60 * i)
        for i in (1, 2, 3)
    ]
    res = analyst_client.post("/api/incidents", json={
        "title": "api beacon cluster",
        "alert_ids": [s["alert_id"] for s in seeds],
        "summary": "grouped by endpoint",
    })
    assert res.status_code == 200, res.text
    inc = res.json()
    assert inc["status"] == "OPEN" and inc["alert_count"] == 3
    assert inc["severity"] == "HIGH" and inc["summary"] == "grouped by endpoint"
    assert inc["note_count"] == 0

    detail = analyst_client.get(f"/api/incidents/{inc['id']}").json()
    assert len(detail["alerts"]) == 3
    assert detail["evidence_summary"].startswith("3 linked alert(s)")
    assert [e["kind"] for e in detail["timeline"]][:4] == [
        "created", "alert_added", "alert_added", "alert_added"]

    # 2. a related alert streams in and auto-joins over the bus
    joined = _seed_api("10.101.0.4:40004", "api-incident.example.net:8443",
                       BASE_TS + 300)
    detail = analyst_client.get(f"/api/incidents/{inc['id']}").json()
    assert detail["alert_count"] == 4
    assert any(e["data"].get("source") == "auto"
               for e in detail["timeline"] if e["kind"] == "alert_added")

    # 3. state machine via the API, incl. the two new states
    assert analyst_client.post(
        f"/api/incidents/{inc['id']}/investigate").json()["status"] == \
        "INVESTIGATING"
    res = analyst_client.post(f"/api/incidents/{inc['id']}/false-positive")
    assert res.status_code == 200 and res.json()["status"] == "FALSE_POSITIVE"
    fp_page = analyst_client.get("/api/incidents?status=FALSE_POSITIVE").json()
    assert any(i["id"] == inc["id"] for i in fp_page["items"])
    assert analyst_client.post(
        f"/api/incidents/{inc['id']}/reopen").json()["status"] == \
        "INVESTIGATING"
    inv_page = analyst_client.get("/api/incidents?status=INVESTIGATING").json()
    assert any(i["id"] == inc["id"] for i in inv_page["items"])
    assert analyst_client.post(
        f"/api/incidents/{inc['id']}/resolve").json()["status"] == "RESOLVED"
    assert analyst_client.post(
        f"/api/incidents/{inc['id']}/resolve").status_code == 409
    assert analyst_client.post(
        f"/api/incidents/{inc['id']}/acknowledge").status_code == 409
    assert analyst_client.post(
        f"/api/incidents/{inc['id']}/investigate").status_code == 409
    # closed incidents refuse membership
    late = _seed_api("10.101.0.5:40005", "api-incident.example.net:8443",
                     BASE_TS + 400)
    res = analyst_client.post(f"/api/incidents/{inc['id']}/alerts",
                              json={"alert_ids": [late["alert_id"]]})
    assert res.status_code == 409 and "reopen" in res.json()["detail"]

    # 4. correlate endpoint: analyst-selected related pair -> one incident
    pair = [
        _seed_api(f"10.102.0.{i}:4000{i}", "api-pair.example.net:8443",
                  BASE_TS + 120 * i)
        for i in (1, 2)
    ]
    extra = _seed_api("10.102.0.3:40003", "api-pair.example.net:8443",
                      BASE_TS + 240)  # left unassigned for the attach step
    res = analyst_client.post("/api/incidents/correlate",
                              json={"alert_ids": [p["alert_id"]
                                                  for p in pair]})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["clusters"] == 1 and len(body["created"]) == 1
    inc2 = body["created"][0]
    assert inc2["alert_count"] == 2 and inc2["status"] == "OPEN"

    # 5. acknowledge + attach + note on the correlated incident
    assert analyst_client.post(
        f"/api/incidents/{inc2['id']}/acknowledge").json()["status"] == \
        "ACKNOWLEDGED"
    res = analyst_client.post(f"/api/incidents/{inc2['id']}/alerts",
                              json={"alert_ids": [extra["alert_id"]]})
    assert res.status_code == 200 and res.json()["alert_count"] == 3
    # claimed / unknown alerts surface as 409 / 404
    res = analyst_client.post(f"/api/incidents/{inc2['id']}/alerts",
                              json={"alert_ids": [seeds[0]["alert_id"]]})
    assert res.status_code == 409
    assert "already belongs" in res.json()["detail"]
    res = analyst_client.post(f"/api/incidents/{inc2['id']}/alerts",
                              json={"alert_ids": ["alrt_nope"]})
    assert res.status_code == 404
    res = analyst_client.post(f"/api/incidents/{inc2['id']}/notes",
                              json={"body": "same operator, different host"})
    assert res.status_code == 200
    detail = analyst_client.get(f"/api/incidents/{inc2['id']}").json()
    assert detail["note_count"] == 1 and detail["alert_count"] == 3

    # 6. list rows expose the rollup fields; audit has every action kind
    page = analyst_client.get("/api/incidents?limit=50").json()
    row = next(i for i in page["items"] if i["id"] == inc2["id"])
    assert row["alert_count"] == 3 and row["severity"] in (
        "LOW", "MEDIUM", "HIGH", "CRITICAL")
    kinds = {e["kind"] for e in analyst_client.get(
        "/api/audit/entries?limit=500").json()["items"]}
    assert {"incident.create", "incident.investigate",
            "incident.false_positive", "incident.reopen",
            "incident.resolve", "incident.acknowledge",
            "incident.correlate", "incident.alert_add",
            "incident.note"} <= kinds
    # actors are preserved (analyst actions + system correlation)
    entries = analyst_client.get("/api/audit/entries?limit=500").json()["items"]
    auto = [e for e in entries if e["kind"] == "incident.alert_add"]
    assert auto, "no alert_add audit entries"
    assert {e["actor"] for e in auto} <= {"test_analyst", "spectra"}

    # tidy the shared session db
    assert analyst_client.post(
        f"/api/incidents/{inc2['id']}/resolve").status_code == 200


def test_api_incident_alert_layer_validation_and_permissions(analyst_client,
                                                             viewer_client,
                                                             raw_client):
    # unknown alert in a create is a 404, not a silent skip
    res = analyst_client.post("/api/incidents", json={
        "title": "missing alert", "alert_ids": ["alrt_nope"]})
    assert res.status_code == 404 and "alrt_nope" in res.json()["detail"]
    # title stays mandatory at the API (pydantic), empty is service policy
    assert analyst_client.post("/api/incidents",
                               json={"alert_ids": ["x"]}).status_code == 422
    assert analyst_client.post("/api/incidents",
                               json={"title": " "}).status_code == 400
    # attach body needs at least one alert; status filter knows the new states
    assert analyst_client.post("/api/incidents/1/alerts",
                               json={"alert_ids": []}).status_code == 422
    assert analyst_client.get("/api/incidents?status=NEW").status_code == 422
    # unknown incident -> 404 on every new action
    for path in ("investigate", "reopen", "false-positive", "acknowledge",
                 "resolve"):
        assert analyst_client.post(
            f"/api/incidents/999999/{path}").status_code == 404
    assert analyst_client.post(
        "/api/incidents/999999/alerts",
        json={"alert_ids": ["x"]}).status_code == 404
    # permissions: read needs investigate, mutations need incidents:manage
    assert viewer_client.get("/api/incidents").status_code == 403
    assert viewer_client.post(
        "/api/incidents/1/investigate").status_code == 403
    assert viewer_client.post(
        "/api/incidents/correlate", json={}).status_code == 403
    assert raw_client.post("/api/incidents/correlate",
                           json={}).status_code in (401, 403)
    # empty correlate selection is legal and changes nothing
    res = analyst_client.post("/api/incidents/correlate",
                              json={"alert_ids": []})
    assert res.status_code == 200 and res.json()["created"] == []
