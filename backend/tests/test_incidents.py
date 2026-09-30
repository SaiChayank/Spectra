"""Incident triage + analyst notes: lifecycle, validation, attribution.

The incidents API is what ``incidents:manage`` binds to (ANALYST): creating
an incident from a flagged detection, acknowledging, resolving, annotating -
all attributed to the signed-in user and written to the audit log.
"""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from spectra.api.app import app
from spectra.api.runtime import engine

client = TestClient(app)  # session-scoped admin (conftest)


def _seed_flow(anomaly: bool) -> int:
    """Insert one scored flow and return its durable id (newest-first read)."""
    store = engine.store
    now = time.time()
    store.save_flow(
        {
            "src": "10.9.9.9", "dst": "10.0.0.1", "sport": 44444,
            "dport": 443, "proto": "TCP", "packets": 12, "bytes": 1400,
            "duration": 0.5, "start_ts": now, "last_ts": now,
            "sni": "incident.test",
        },
        score=87.5 if anomaly else 4.0,
        anomaly=anomaly,
    )
    page = store.query_flows(limit=1, anomaly_only=anomaly)  # flushes
    return int(page["items"][0]["id"])


def test_incident_lifecycle_as_analyst(analyst_client):
    detection_id = _seed_flow(anomaly=True)

    # create from a detection, attributed to the analyst
    res = analyst_client.post("/api/incidents", json={
        "title": "suspicious beaconing", "detection_id": detection_id})
    assert res.status_code == 200, res.text
    incident = res.json()
    incident_id = int(incident["id"])
    assert incident["status"] == "OPEN"
    assert incident["created_by"] == "test_analyst"
    assert incident["detection_id"] == detection_id
    assert incident["note_count"] == 0

    detail = analyst_client.get(f"/api/incidents/{incident_id}").json()
    assert detail["notes"] == [] and detail["note_count"] == 0

    # acknowledge -> annotated -> resolve
    res = analyst_client.post(f"/api/incidents/{incident_id}/acknowledge")
    assert res.status_code == 200
    assert res.json()["status"] == "ACKNOWLEDGED"
    assert res.json()["acknowledged_by"] == "test_analyst"
    assert analyst_client.post(
        f"/api/incidents/{incident_id}/acknowledge").status_code == 409

    res = analyst_client.post(f"/api/incidents/{incident_id}/notes",
                              json={"body": "beacon interval ~60s"})
    assert res.status_code == 200
    assert res.json()["author"] == "test_analyst"

    res = analyst_client.post(f"/api/incidents/{incident_id}/resolve")
    assert res.status_code == 200
    assert res.json()["status"] == "RESOLVED"
    assert res.json()["resolved_by"] == "test_analyst"
    # RESOLVED is terminal
    assert analyst_client.post(
        f"/api/incidents/{incident_id}/resolve").status_code == 409
    assert analyst_client.post(
        f"/api/incidents/{incident_id}/acknowledge").status_code == 409

    detail = analyst_client.get(f"/api/incidents/{incident_id}").json()
    assert detail["note_count"] == 1 and len(detail["notes"]) == 1
    assert detail["notes"][0]["body"] == "beacon interval ~60s"

    # filters observe the state machine
    resolved = analyst_client.get("/api/incidents?status=RESOLVED").json()
    assert any(i["id"] == incident_id for i in resolved["items"])
    open_page = analyst_client.get("/api/incidents?status=OPEN").json()
    assert all(i["id"] != incident_id for i in open_page["items"])

    # transition actions are audited under the analyst actor
    kinds = {e["kind"] for e in
             client.get("/api/audit/entries?limit=100").json()["items"]}
    assert {"incident.create", "incident.acknowledge",
            "incident.resolve", "incident.note"} <= kinds


def test_incident_without_detection_is_allowed(analyst_client):
    res = analyst_client.post("/api/incidents",
                              json={"title": "manual observation"})
    assert res.status_code == 200
    assert res.json()["detection_id"] is None
    assert res.json()["status"] == "OPEN"


def test_incident_validation_and_not_found(analyst_client):
    plain_flow = _seed_flow(anomaly=False)

    res = analyst_client.post("/api/incidents", json={
        "title": "bad anchor", "detection_id": 999999})
    assert res.status_code == 404 and res.json()["detail"] == "detection not found"

    res = analyst_client.post("/api/incidents", json={
        "title": "not a detection", "detection_id": plain_flow})
    assert res.status_code == 400 and "flagged detection" in res.json()["detail"]

    res = analyst_client.post("/api/incidents", json={"title": " "})
    assert res.status_code == 400  # stripped empty title fails service policy

    assert analyst_client.get("/api/incidents/999999").status_code == 404
    assert analyst_client.post(
        "/api/incidents/999999/resolve").status_code == 404
    assert analyst_client.post(
        "/api/incidents/999999/notes",
        json={"body": "x"}).status_code == 404
    assert analyst_client.post(
        "/api/incidents/1/notes", json={"body": ""}).status_code == 422
    assert analyst_client.get(
        "/api/incidents?status=BOGUS").status_code == 422


def test_viewer_cannot_use_incidents(viewer_client):
    assert viewer_client.get("/api/incidents").status_code == 403
    res = viewer_client.post("/api/incidents", json={"title": "nope"})
    assert res.status_code == 403
    assert "investigate" in res.json()["detail"]
