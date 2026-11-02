"""The alert layer: severity, evidence, grouping, persistence, streaming.

Four independent concepts ride every alert — anomaly score, confidence,
severity, threat type — and these tests keep them apart: severity follows the
documented rule table (never a repackaged score), evidence is machine- and
human-readable, alerts are distinct objects from raw detections (linked by
``alert_id``, never merged), grouping correlates repeats without duplicating,
and alerts persist (SQLite) and stream (bus/WebSocket) with a status
lifecycle the API can drive.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from spectra.api.app import app
from spectra.api.runtime import engine
from spectra.config import Config
from spectra.demo import make_baseline_pcap, make_suspicious_pcap
from spectra.evidence import build_evidence
from spectra.features.extractor import FEATURE_NAMES, N_FEATURES
from spectra.pipeline import SpectraEngine
from spectra.severity import SEVERITIES, calculate_severity
from spectra.services.events import EventBus
from spectra.services.threat_alerts import (
    AlertNotFound,
    AlertStateError,
    AlertValidationError,
    ThreatAlertService,
)
from spectra.store import Store
from spectra.threats import classify_threat, unknown_threat

client = TestClient(app)  # session-scoped admin (conftest)

# -- helpers -------------------------------------------------------------------


def feats(**overrides) -> object:
    """A zero feature vector with named entries overridden (see test_threats)."""
    import numpy as np
    vec = np.zeros(N_FEATURES, dtype=np.float32)
    for name, value in overrides.items():
        assert name in FEATURE_NAMES, f"unknown feature {name}"
        vec[FEATURE_NAMES.index(name)] = float(value)
    return vec


def rec(**overrides) -> dict:
    """A minimal flow record with named fields overridden (see test_threats)."""
    base = {
        "proto": "TCP",
        "src": "10.0.0.5:40000",
        "dst": "10.1.1.1:443",
        "start_ts": 0.0,
        "last_ts": 1.0,
        "duration": 1.0,
        "packets": 10,
        "bytes": 5_000,
        "tls_version": None,
        "sni": None,
        "alpn": None,
        "ja3": None,
        "ja4": None,
        "cipher_count": 0,
        "extension_count": 0,
        "quic_version": None,
        "score": 70.0,
        "anomaly": True,
    }
    base.update(overrides)
    return base


def alert_record(**overrides) -> dict:
    """A flow record shaped like the publication path hands it to observe()."""
    base = {
        "src": "10.42.0.9:51111",
        "dst": "beacon.example.com:8443",
        "proto": "TCP",
        "start_ts": 1_700_000_000.0,
        "last_ts": 1_700_000_010.0,
        "duration": 10.0,
        "packets": 30,
        "bytes": 1_600,
        "sni": None,
        "tls_version": None,
        "quic_version": None,
        "alpn": None,
        "ja3": None,
        "ja4": None,
        "slice": None,
        "score": 97.0,
        "anomaly": True,
    }
    base.update(overrides)
    return base


def c2_threat(confidence: float = 0.7) -> dict:
    """A C2 verdict shaped exactly like classify_threat output."""
    return {
        "threat_type": "C2_BEACONING",
        "confidence": confidence,
        "supporting": [
            {"signal": "periodic_forward_timing", "weight": 0.5,
             "detail": "forward IAT mad/mean 0.02 over 30.20s spacing "
                       "(steady cadence)",
             "value": 30.2, "unit": "s"},
            {"signal": "repeated_destination", "weight": 0.4,
             "detail": "same src->dst pair seen 5 times before",
             "value": 5, "unit": "count"},
        ],
        "contradicting": [],
    }


def make_service(tmp_path, ttl: float = 600.0, *, store=None, model_info=None):
    """Isolated ThreatAlertService + store + captured bus events."""
    cfg = Config()
    cfg.alert_group_seconds = ttl
    svc_store = Store(str(tmp_path / "alerts.db")) if store is None else store
    bus = EventBus()
    seen: list[dict] = []
    bus.subscribe(seen.append)
    svc = ThreatAlertService(svc_store, cfg, bus, None,
                             model_info=model_info)
    return svc, svc_store, seen


# -- severity: documented ordinal calculation ---------------------------------

NEUTRAL = {"confidence": 0.7, "anomaly_score": None,
           "asset_criticality": None, "occurrences": 1}


def test_severity_category_base_levels():
    """Step 1 of the rule table: the documented base per threat category."""
    expectations = {
        "C2_BEACONING": "HIGH",
        "DATA_EXFILTRATION_SUSPECTED": "HIGH",
        "RECONNAISSANCE": "MEDIUM",
        "VOLUMETRIC_ANOMALY": "MEDIUM",
        "UNUSUAL_ENDPOINT_BEHAVIOR": "MEDIUM",
        "TLS_ANOMALY": "LOW",
        "QUIC_ANOMALY": "LOW",
        "UNKNOWN_ANOMALY": "LOW",
    }
    for threat_type, want in expectations.items():
        severity, factors = calculate_severity(threat_type=threat_type,
                                               **NEUTRAL)
        assert severity == want, f"{threat_type}: {severity} vs {want}"
        assert f"base {want}" in factors[0]
    # unknown categories stay modest rather than crash or escalate
    assert calculate_severity(threat_type="TOTALLY_NEW", **NEUTRAL)[0] == "LOW"


def test_severity_confidence_bands():
    """High confidence raises one level; thin evidence lowers one level."""
    low_base = {"threat_type": "TLS_ANOMALY", "anomaly_score": 50.0}
    assert calculate_severity(confidence=0.95, **low_base)[0] == "MEDIUM"
    assert calculate_severity(confidence=0.85, **low_base)[0] == "MEDIUM"
    assert calculate_severity(confidence=0.84, **low_base)[0] == "LOW"
    # thin evidence lowers ... but the floor keeps the result at LOW
    severity, factors = calculate_severity(threat_type="UNKNOWN_ANOMALY",
                                           confidence=0.2)
    assert severity == "LOW"
    assert any("lowered one level" in f for f in factors)
    assert any("clamped to LOW" in f for f in factors)


def test_severity_intensity_asset_and_correlation():
    """Steps 3-5: top-band score, critical asset, repeated sightings."""
    base = {"threat_type": "TLS_ANOMALY", "confidence": 0.7}
    assert calculate_severity(anomaly_score=99.0, **base)[0] == "MEDIUM"
    assert calculate_severity(anomaly_score=98.9, **base)[0] == "LOW"
    assert calculate_severity(anomaly_score=None, **base)[0] == "LOW"
    assert calculate_severity(asset_criticality="critical",
                              **base)[0] == "MEDIUM"
    assert calculate_severity(asset_criticality="internal",
                              **base)[0] == "LOW"
    assert calculate_severity(occurrences=3, **base)[0] == "MEDIUM"
    assert calculate_severity(occurrences=2, **base)[0] == "LOW"


def test_severity_clamps_at_critical():
    """Every escalation can fire without leaving the ordinal range."""
    severity, factors = calculate_severity(
        threat_type="C2_BEACONING", confidence=0.95, anomaly_score=99.9,
        asset_criticality="critical", occurrences=7)
    assert severity == "CRITICAL"
    assert any("clamped to CRITICAL" in f for f in factors)
    assert SEVERITIES.index(severity) == len(SEVERITIES) - 1


def test_severity_is_independent_of_anomaly_score():
    """A bigger score must not mean a bigger severity on its own."""
    # unknown at the very top of the score scale stays modest ...
    unknown, _ = calculate_severity(threat_type="UNKNOWN_ANOMALY",
                                    confidence=0.2, anomaly_score=99.9)
    # ... while a confident C2 with a *lower* score is urgent.
    c2, _ = calculate_severity(threat_type="C2_BEACONING",
                               confidence=0.95, anomaly_score=97.0)
    assert unknown == "LOW" and c2 == "CRITICAL"
    # same score, different inputs -> different levels (never score-mirrored)
    confident, _ = calculate_severity(threat_type="TLS_ANOMALY",
                                      confidence=0.9, anomaly_score=99.4)
    bland, _ = calculate_severity(threat_type="TLS_ANOMALY",
                                  confidence=0.6, anomaly_score=99.4)
    assert confident == "HIGH" and bland == "MEDIUM"


def test_severity_factors_document_every_input():
    """The derivation names all five inputs, including no-change ones."""
    severity, factors = calculate_severity(
        threat_type="RECONNAISSANCE", confidence=0.9, anomaly_score=99.4,
        asset_criticality="critical", occurrences=4)
    joined = " ".join(factors)
    assert "RECONNAISSANCE" in joined and "base MEDIUM" in joined
    assert "confidence 0.90" in joined
    assert "99.4" in joined
    assert "affected asset is critical" in joined
    assert "4 times" in joined
    assert severity == "CRITICAL"
    # honest absence: no score, no asset context, first sighting - stated
    _, quiet = calculate_severity(threat_type="TLS_ANOMALY", confidence=0.7)
    joined = " ".join(quiet)
    assert "anomaly intensity unavailable -> no change" in joined
    assert "no asset context available -> no change" in joined
    assert "1 sighting(s)" in joined


# -- evidence: machine- and human-readable -------------------------------------

def test_evidence_prompt_examples_are_structured():
    """Technical items carry key/value/unit; the summary is one plain sentence."""
    threat = {
        "threat_type": "C2_BEACONING",
        "confidence": 0.9,
        "supporting": [
            {"signal": "periodic_forward_timing", "weight": 0.5,
             "detail": "steady cadence", "value": 30.2, "unit": "s"},
            {"signal": "low_timing_mad", "weight": 0.3,
             "detail": "near-constant interval", "value": 0.7, "unit": "s"},
            {"signal": "repeated_destination", "weight": 0.4,
             "detail": "seen 4 times", "value": 4, "unit": "count"},
        ],
        "contradicting": [],
    }
    evidence = build_evidence({"dst": "198.51.100.7:8443"}, threat)
    technical = {i["key"]: i for i in evidence["supporting"]}
    assert technical["periodicity"]["value"] == pytest.approx(30.2)
    assert technical["periodicity"]["unit"] == "s"
    assert technical["periodicity"]["label"] == "Periodicity"
    assert technical["timing_mad"]["value"] == pytest.approx(0.7)
    assert technical["timing_mad"]["unit"] == "s"
    assert evidence["summary"] == (
        "Connections repeated approximately every 30 seconds with "
        "unusually stable timing.")
    for item in evidence["supporting"] + evidence["contradicting"]:
        assert {"key", "value", "unit", "label", "detail"} <= set(item)
        assert item["label"] and item["detail"] and item["key"]


def test_evidence_from_real_classification(tmp_path):
    """classify_threat output feeds build_evidence end to end (no re-derivation)."""
    window = [
        rec(src="10.0.0.66:43001", dst="198.51.100.7:8443",
            bytes=1_600, packets=28, duration=13.5)
        for _ in range(3)
    ]
    current = rec(src="10.0.0.66:43004", dst="198.51.100.7:8443",
                  bytes=1_600, packets=28, duration=13.5, score=91.0)
    vector = feats(
        iat_fwd_mean_s=30.2, iat_fwd_mad_s=0.7,
        bytes_mean=59.6, bytes_std=4.2, bytes_total=1_600,
        duration_s=13.5, packets_total=28,
    )
    threat = classify_threat(current, vector, window)
    assert threat["threat_type"] == "C2_BEACONING"

    evidence = build_evidence(current, threat)
    technical = {i["key"]: i for i in evidence["supporting"]}
    assert technical["periodicity"]["value"] == pytest.approx(30.2)
    assert technical["periodicity"]["unit"] == "s"
    assert technical["repeated_destination"]["value"] == 3
    assert evidence["summary"].startswith(
        "Connections repeated approximately every 30 seconds")


def test_evidence_exfiltration_ratio_and_first_seen():
    """outbound_ratio = 8.3, destination_first_seen = true, numeric summary."""
    window = [
        rec(src="10.0.0.9:51000", dst=f"10.9.9.{i}:80",
            duration=0.5, packets=10, bytes=800)
        for i in range(12, 22)
    ]  # 10.9.9.9 itself is absent -> the destination is first-seen
    current = rec(src="10.0.0.9:51111", dst="10.9.9.9:80",
                  duration=8.0, packets=400, bytes=930_000, score=88.0)
    vector = feats(
        duration_s=8.0, packets_total=400, bytes_total=930_000,
        bytes_fwd=830_000, bytes_bwd=100_000,
        packets_per_s=50.0, bytes_per_s=116_250.0,
        bytes_mean=1_300.0, bytes_std=400.0,
    )
    threat = classify_threat(current, vector, window)
    assert threat["threat_type"] == "DATA_EXFILTRATION_SUSPECTED"

    evidence = build_evidence(current, threat)
    technical = {i["key"]: i for i in evidence["supporting"]}
    assert technical["outbound_ratio"]["value"] == pytest.approx(8.3)
    assert technical["destination_first_seen"]["value"] is True
    assert technical["destination_first_seen"]["unit"] is None
    assert "8.3x" in evidence["summary"]


def test_evidence_unknown_stays_honest():
    """No category -> no fabricated numbers, an explicit explanation."""
    evidence = build_evidence({"dst": "10.2.2.2:443"}, unknown_threat())
    assert evidence["supporting"] == [] and evidence["contradicting"] == []
    assert "did not reach any specific threat category" in evidence["summary"]
    # a sub-threshold candidate is named as such
    near_miss = unknown_threat()
    near_miss["candidate"] = "RECONNAISSANCE"
    assert "reconnaissance" in build_evidence({}, near_miss)["summary"]


def test_evidence_never_raises_on_malformed_input():
    """Publication survives garbage: degraded shapes still return a document."""
    for threat in ({}, None, {"threat_type": None},
                   {"threat_type": "C2_BEACONING", "supporting": "oops",
                    "contradicting": 7}):
        evidence = build_evidence({}, threat)
        assert isinstance(evidence["supporting"], list)
        assert isinstance(evidence["contradicting"], list)
        assert isinstance(evidence["summary"], str) and evidence["summary"]


# -- the service: grouping, persistence, lifecycle ------------------------------

def test_alert_shape_and_persistence(tmp_path):
    svc, store, events = make_service(
        tmp_path, model_info=lambda: {"id": "spectra_iforest.joblib",
                                      "version": 3})
    alert = svc.observe(alert_record(), c2_threat(confidence=0.7),
                        score=97.0)

    # every field the analyst contract promises
    assert alert["alert_id"].startswith("alrt_")
    fields = {
        "alert_id", "flow_id", "timestamp", "first_seen", "last_seen",
        "source", "destination", "protocol", "threat_type", "anomaly_score",
        "confidence", "severity", "severity_factors", "model_id",
        "model_version", "evidence", "metadata", "module_annotations",
        "status", "occurrences",
    }
    assert fields <= set(alert)
    assert alert["status"] == "OPEN" and alert["occurrences"] == 1
    assert alert["severity"] in SEVERITIES
    assert alert["severity"] == "HIGH"  # C2 base; no escalation yet
    assert alert["model_id"] == "spectra_iforest.joblib"
    assert alert["model_version"] == "3"
    assert alert["flow_id"] is None  # documented: batched rows have no id yet
    assert alert["evidence"]["summary"]
    assert [e["type"] for e in events] == ["alert"]

    # durable row with JSON columns hydrated back to objects
    row = store.get_alert(alert["alert_id"])
    assert row is not None
    assert row["evidence"] == alert["evidence"]
    assert row["metadata"]["dst_port"] == "8443"
    assert row["metadata"]["asset_criticality"] is None
    assert row["severity_factors"] == alert["severity_factors"]
    assert row["status"] == "OPEN"


def test_alert_asset_context_escalates_severity(tmp_path):
    """A sensitive-sector sni marks the asset critical (severity factor)."""
    svc, store, _ = make_service(tmp_path)
    alert = svc.observe(
        alert_record(dst="10.0.0.9:8443",
                     sni="patient-portal.hospital.example"),
        c2_threat(confidence=0.7), score=97.0)
    assert alert["metadata"]["sector"] == "healthcare"
    assert alert["metadata"]["asset_criticality"] == "critical"
    assert alert["severity"] == "CRITICAL"  # HIGH base + critical asset
    assert any("critical" in f for f in alert["severity_factors"])


def test_grouping_accumulates_and_escalates(tmp_path):
    """Same behaviour -> one alert; three sightings correlate into escalation."""
    svc, store, events = make_service(tmp_path)
    threat = c2_threat(confidence=0.7)
    a1 = svc.observe(alert_record(), threat, score=97.0)
    a2 = svc.observe(alert_record(src="10.42.0.9:51112",
                                  last_ts=1_700_000_040.0),
                     threat, score=96.0)
    a3 = svc.observe(alert_record(src="10.42.0.9:51113",
                                  last_ts=1_700_000_070.0),
                     threat, score=95.0)

    assert {a1["alert_id"], a2["alert_id"], a3["alert_id"]} == {a1["alert_id"]}
    assert a3["occurrences"] == 3
    assert a3["last_seen"] == 1_700_000_070.0
    assert a3["anomaly_score"] == 97.0  # intensity high-water mark
    # correlation escalates: HIGH base -> CRITICAL at >= 3 sightings
    assert a1["severity"] == "HIGH" and a3["severity"] == "CRITICAL"
    assert any("3 times" in f for f in a3["severity_factors"])

    # one durable row, updated in place
    page = store.list_alerts(limit=500)
    assert [i["alert_id"] for i in page["items"]].count(a1["alert_id"]) == 1
    assert store.get_alert(a1["alert_id"])["occurrences"] == 3

    # streamed once on create, then one update per re-sighting
    kinds = [e["type"] for e in events]
    assert kinds.count("alert") == 1
    assert kinds.count("alert_updated") == 2


def test_grouping_separates_pairs_and_threat_types(tmp_path):
    """Grouping key is threat x protocol x endpoint hosts, not just source."""
    svc, _, _ = make_service(tmp_path)
    first = svc.observe(alert_record(), c2_threat(), score=97.0)
    other_host = svc.observe(alert_record(dst="elsewhere.example.com:443"),
                             c2_threat(), score=97.0)
    other_threat = svc.observe(
        alert_record(),
        {"threat_type": "RECONNAISSANCE", "confidence": 0.7,
         "supporting": [{"signal": "destination_fanout", "weight": 0.5,
                         "detail": "12 distinct dst hosts", "value": 12,
                         "unit": "count"}],
         "contradicting": []},
        score=97.0)
    ids = {first["alert_id"], other_host["alert_id"],
           other_threat["alert_id"]}
    assert len(ids) == 3


def test_group_window_expires_and_resolved_starts_new(tmp_path):
    """A stale sighting opens a fresh alert; RESOLVED is terminal for a group."""
    svc, store, _ = make_service(tmp_path, ttl=600.0)
    threat = c2_threat()
    first = svc.observe(alert_record(last_ts=1_000_000.0), threat, score=97.0)

    # within the window -> same alert
    again = svc.observe(alert_record(last_ts=1_000_300.0), threat,
                        score=97.0)
    assert again["alert_id"] == first["alert_id"]

    # beyond the window -> the group is stale, a new alert opens
    late = svc.observe(alert_record(last_ts=1_001_001.0), threat,
                       score=97.0)
    assert late["alert_id"] != first["alert_id"]
    assert late["occurrences"] == 1

    # resolving a group means *this* alert is done; a later sighting is new
    svc.acknowledge(late["alert_id"])
    resolved = svc.resolve(late["alert_id"])
    assert resolved["status"] == "RESOLVED"
    fresh = svc.observe(alert_record(last_ts=1_001_100.0), threat,
                        score=97.0)
    assert fresh["alert_id"] != late["alert_id"]
    assert fresh["status"] == "OPEN"
    assert store.get_alert(late["alert_id"])["status"] == "RESOLVED"


def test_status_lifecycle_and_errors(tmp_path):
    svc, _, _ = make_service(tmp_path)
    alert = svc.observe(alert_record(), c2_threat(), score=97.0)
    alert_id = alert["alert_id"]

    with pytest.raises(AlertNotFound):
        svc.get("alrt_does_not_exist")
    with pytest.raises(AlertNotFound):
        svc.acknowledge("alrt_does_not_exist")
    with pytest.raises(AlertValidationError):
        svc.list(status="SOMETHING_ELSE")

    acknowledged = svc.acknowledge(alert_id)
    assert acknowledged["status"] == "ACKNOWLEDGED"
    with pytest.raises(AlertStateError):
        svc.acknowledge(alert_id)

    resolved = svc.resolve(alert_id)
    assert resolved["status"] == "RESOLVED"
    with pytest.raises(AlertStateError):
        svc.resolve(alert_id)
    with pytest.raises(AlertStateError):
        svc.acknowledge(alert_id)


def test_service_works_without_persistence(tmp_path):
    """Persist=False engines still raise, list and transition alerts in memory."""
    svc = ThreatAlertService(None, Config(), None, None)
    alert = svc.observe(alert_record(), c2_threat(), score=97.0)
    assert alert["status"] == "OPEN"

    page = svc.list()
    assert page["count"] == 1 and page["items"][0]["alert_id"] == \
        alert["alert_id"]
    assert svc.get(alert["alert_id"])["severity"] in SEVERITIES
    assert svc.acknowledge(alert["alert_id"])["status"] == "ACKNOWLEDGED"
    assert svc.resolve(alert["alert_id"])["status"] == "RESOLVED"
    with pytest.raises(AlertStateError):
        svc.resolve(alert["alert_id"])
    with pytest.raises(AlertNotFound):
        svc.get("alrt_nope")


def test_persistence_failure_never_stops_the_hot_path(tmp_path):
    """A broken store degrades the alert, it does not raise into publication."""

    class _BrokenStore(Store):
        def insert_alert(self, alert: dict) -> None:
            raise RuntimeError("disk full")

    svc = ThreatAlertService(_BrokenStore(str(tmp_path / "broken.db")),
                             Config(), None, None)
    alert = svc.observe(alert_record(), c2_threat(), score=97.0)
    assert alert["alert_id"].startswith("alrt_")
    assert alert["evidence"]["summary"]


# -- streaming + separation from raw detections --------------------------------

def test_e2e_alerts_stream_persist_and_stay_separate_from_detections(tmp_path):
    """Suspicious traffic -> detections *and* alerts: distinct, linked, streamed."""
    baseline = make_baseline_pcap(str(tmp_path / "baseline.pcap"), n_flows=40)
    suspicious = make_suspicious_pcap(str(tmp_path / "suspicious.pcap"))
    engine_e = SpectraEngine(model_path=str(tmp_path / "model.joblib"),
                             idle_timeout=30.0)
    engine_e.train_from_pcap(baseline, contamination=0.05)

    events: list[dict] = []
    detections: list[dict] = []
    engine_e.subscribe(events.append)
    engine_e.subscribe(lambda e: detections.append(e["data"])
                       if e["type"] == "detection" else None)
    engine_e.start("pcap", path=suspicious)
    deadline = time.time() + 30
    while engine_e.running and time.time() < deadline:
        time.sleep(0.05)
    assert not engine_e.running, "capture did not finish"
    assert detections, "no anomalies detected in suspicious traffic"

    alert_events = [e for e in events if e["type"] == "alert"]
    assert alert_events, "flagged flows never raised an alert"
    alert_ids = {e["data"]["alert_id"] for e in alert_events}

    for a in alert_events:
        data = a["data"]
        # the four concepts, side by side, independent
        assert data["severity"] in SEVERITIES
        assert 0.0 <= data["confidence"] <= 1.0
        assert data["anomaly_score"] is None or 0.0 <= \
            data["anomaly_score"] <= 100.0
        assert data["threat_type"]
        assert data["evidence"]["summary"]
        assert data["severity_factors"]
        assert data["status"] == "OPEN"

    # raw detections stay raw: no alert-only fields leak into them
    for d in detections:
        assert "severity" not in d and "status" not in d
        assert "occurrences" not in d and "evidence" not in d
        assert d.get("threat"), "detection lost its threat verdict"

    # linkage: detection -> alert (stamped before persistence) -> store row
    linked = [d["alert_id"] for d in detections if d.get("alert_id")]
    assert linked, "no detection carried an alert back-link"
    assert set(linked) <= alert_ids
    store = engine_e.store
    assert store is not None
    for alert_id in list(alert_ids)[:5]:
        row = store.get_alert(alert_id)
        assert row is not None, f"alert {alert_id} was not persisted"
        assert row["evidence"]["summary"]

    # persisted flow rows keep the reverse link, hydrating through query_flows
    page = store.query_flows(limit=50, anomaly_only=True)
    with_link = [f for f in page["items"] if f.get("alert_id")]
    assert with_link, "persisted flows lost their alert_id"
    assert {f["alert_id"] for f in with_link} <= alert_ids


def test_alert_events_are_not_duplicated_in_the_events_table():
    """Durable alert rows live in ``alerts``; the feed skips both event types."""
    marker = "marker-alert-skip-1"
    status_marker = "marker-status-kept-1"
    engine._persist_event({"type": "alert", "data": {"marker": marker}})
    engine._persist_event({"type": "alert_updated",
                           "data": {"marker": marker}})
    engine._persist_event({"type": "status", "data": {"marker": status_marker}})
    dump = str(engine.store.query_events(limit=500)["items"])
    assert marker not in dump
    assert status_marker in dump


# -- API ------------------------------------------------------------------------

def _seed_api_alert(threat_type: str = "C2_BEACONING",
                    dst: str = "beacon.example.com:8443") -> dict:
    """Raise one alert on the shared API engine (unique pair per call)."""
    import random
    src = f"10.77.{random.randint(1, 250)}.{random.randint(1, 250)}:" \
          f"{random.randint(40000, 60000)}"
    return engine.threat_alerts.observe(
        alert_record(src=src, dst=dst),
        {**c2_threat(confidence=0.7), "threat_type": threat_type},
        score=97.0)


def test_api_alerts_read_acknowledge_resolve_and_audit(analyst_client):
    alert = _seed_api_alert()
    alert_id = alert["alert_id"]

    # reads: page filter + detail carry the full analyst contract
    page = client.get(f"/api/alerts?threat_type=C2_BEACONING&limit=500").json()
    assert any(i["alert_id"] == alert_id for i in page["items"])
    detail = client.get(f"/api/alerts/{alert_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["severity"] in SEVERITIES
    assert body["evidence"]["summary"]
    assert body["status"] == "OPEN"

    # lifecycle as the analyst (incidents:manage), attributed in the audit log
    res = analyst_client.post(f"/api/alerts/{alert_id}/acknowledge")
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "ACKNOWLEDGED"
    assert analyst_client.post(
        f"/api/alerts/{alert_id}/acknowledge").status_code == 409

    res = analyst_client.post(f"/api/alerts/{alert_id}/resolve")
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "RESOLVED"
    assert analyst_client.post(
        f"/api/alerts/{alert_id}/resolve").status_code == 409
    assert analyst_client.post(
        f"/api/alerts/{alert_id}/acknowledge").status_code == 409

    kinds = {e["kind"] for e in
             client.get("/api/audit/entries?limit=100").json()["items"]}
    assert {"alert.acknowledge", "alert.resolve"} <= kinds

    # filters observe the state machine
    resolved = client.get("/api/alerts?status=RESOLVED&limit=500").json()
    assert any(i["alert_id"] == alert_id for i in resolved["items"])
    open_page = client.get("/api/alerts?status=OPEN&limit=500").json()
    assert all(i["alert_id"] != alert_id for i in open_page["items"])


def test_api_alerts_validation_and_not_found(analyst_client):
    assert client.get("/api/alerts/alrt_missing").status_code == 404
    assert client.get("/api/alerts?status=BOGUS").status_code == 422
    assert analyst_client.post(
        "/api/alerts/alrt_missing/acknowledge").status_code == 404


def test_api_alerts_permissions(viewer_client):
    """Reading alerts rides ``read``; triage needs ``incidents:manage``."""
    alert = _seed_api_alert(threat_type="RECONNAISSANCE",
                            dst="scan-target.example.com:445")
    assert viewer_client.get("/api/alerts").status_code == 200
    res = viewer_client.post(f"/api/alerts/{alert['alert_id']}/acknowledge")
    assert res.status_code == 403
    assert "incidents:manage" in res.json()["detail"]
