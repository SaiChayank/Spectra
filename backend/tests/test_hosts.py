"""Host triage v0: aggregation of alert evidence per internal host + verdicts.

Uses the shared test engine; every host here lives in 10.77.0.0/16 (or is
deliberately external) so assertions are filtered to this module's hosts.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from spectra.api.app import app
from spectra.api.runtime import engine

client = TestClient(app)  # session-scoped admin (conftest)

T0 = 1_800_000_000.0
HI, MID, LOW, EXT = "10.77.0.1", "10.77.0.2", "10.77.0.3", "8.8.4.4"


def _alert(src: str, dst: str, threat: str, conf: float, score: float,
           seen: float) -> dict:
    rec = {"src": f"{src}:40000", "dst": f"{dst}:443", "proto": "TCP",
           "start_ts": seen, "last_ts": seen, "duration": 1.0, "packets": 3,
           "bytes": 100}
    return engine.threat_alerts.observe(
        rec, {"threat_type": threat, "confidence": conf, "supporting": [],
              "contradicting": []}, score=score)


@pytest.fixture(scope="module", autouse=True)
def seeded():
    _alert(HI, "203.0.113.5", "C2_BEACONING", 0.9, 50.0, T0 + 10)
    _alert(HI, "203.0.113.6", "PORT_SCAN", 0.3, 20.0, T0 + 20)
    _alert(MID, "203.0.113.7", "PORT_SCAN", 0.5, 10.0, T0 + 30)
    _alert(LOW, "203.0.113.8", "PORT_SCAN", 0.2, 30.0, T0 + 40)  # 0.30 via score
    _alert(EXT, "10.77.0.1", "PORT_SCAN", 0.99, 99.0, T0 + 50)   # external source


def _mine(res) -> list[dict]:
    return [h for h in res.json()["items"] if h["host"] in (HI, MID, LOW)]  # other tests share 10.77/16


def test_ranking_order_and_shape():
    res = client.get("/api/hosts?limit=1000")
    assert res.status_code == 200
    hosts = _mine(res)
    assert [h["host"] for h in hosts] == [HI, MID, LOW]
    top = hosts[0]
    assert top["confidence"] == 0.9 and top["evidence_count"] == 2
    assert top["top_evidence"] == {"detector": "beaconing", "technique": None,
                                   "destination": "203.0.113.5:443",
                                   "strength": 0.9}
    assert top["first_seen"] == T0 + 10 and top["last_seen"] == T0 + 20
    assert top["verdict"] is None
    ranks = [h["rank"] for h in res.json()["items"]]
    assert ranks == sorted(ranks) and ranks[0] == 1


def test_sort_last_seen_and_paging_and_since():
    hosts = _mine(client.get("/api/hosts?sort=last_seen&limit=1000"))
    assert [h["host"] for h in hosts] == [LOW, MID, HI]
    assert hosts[-1]["rank"] < hosts[0]["rank"]  # rank stays the risk rank
    page = client.get("/api/hosts?limit=1&offset=1").json()
    assert page["offset"] == 1 and len(page["items"]) == 1
    since = _mine(client.get(f"/api/hosts?since={T0 + 35}&limit=1000"))
    assert [h["host"] for h in since] == [LOW]


def test_validation_of_query():
    assert client.get("/api/hosts?sort=bogus").status_code == 422
    assert client.get("/api/hosts?limit=1001").status_code == 422


def test_external_hosts_excluded():
    hosts = [h["host"] for h in client.get("/api/hosts?limit=1000").json()["items"]]
    assert EXT not in hosts
    assert client.get(f"/api/hosts/{EXT}/evidence").status_code == 404


def test_evidence_contents():
    res = client.get(f"/api/hosts/{HI}/evidence")
    assert res.status_code == 200
    body = res.json()
    assert body["host"] == HI and body["count"] == 2
    first, second = body["items"]  # newest first
    assert first["time"] > second["time"]
    assert second["detector"] == "beaconing" and second["strength"] == 0.9
    assert second["destination"] == "203.0.113.5:443"
    assert second["alert_id"].startswith("alrt_")
    assert isinstance(second["flow_ids"], list)
    assert first["technique"] is None


def test_evidence_errors():
    assert client.get("/api/hosts/not-an-ip/evidence").status_code == 422
    assert client.get("/api/hosts/10.77.9.9/evidence").status_code == 404


def test_auth_matrix(raw_client, viewer_client, analyst_client):
    assert raw_client.get("/api/hosts").status_code == 401
    assert raw_client.get(f"/api/hosts/{HI}/evidence").status_code == 401
    assert raw_client.post(f"/api/hosts/{HI}/verdict",
                           json={"verdict": "true"}).status_code == 401
    assert viewer_client.get("/api/hosts").status_code == 200
    assert viewer_client.post(f"/api/hosts/{HI}/verdict",
                              json={"verdict": "true"}).status_code == 403
    assert analyst_client.post(f"/api/hosts/{LOW}/verdict",
                               json={"verdict": "expected"}).status_code == 200


def test_verdict_validation():
    url = f"/api/hosts/{MID}/verdict"
    assert client.post(url, json={"verdict": "maybe"}).status_code == 422
    assert client.post(url, json={}).status_code == 422
    assert client.post(url, json={"verdict": "true",
                                  "note": "x" * 501}).status_code == 422
    assert client.post("/api/hosts/zzz/verdict",
                       json={"verdict": "true"}).status_code == 422
    assert client.post("/api/hosts/10.77.9.9/verdict",
                       json={"verdict": "true"}).status_code == 404


def test_verdict_history_latest_wins_and_audit():
    url = f"/api/hosts/{MID}/verdict"
    a = client.post(url, json={"verdict": "true", "note": "seen c2"})
    assert a.status_code == 200
    assert a.json()["verdict"] == "true" and a.json()["note"] == "seen c2"
    assert a.json()["actor"] == "admin" and a.json()["host"] == MID
    b = client.post(url, json={"verdict": "false"})
    assert b.json()["verdict"] == "false" and b.json()["note"] is None
    # append-only: both rows exist; latest wins in the reads
    rows = engine._store._conn.execute(
        "SELECT verdict FROM host_verdicts WHERE host = ? ORDER BY id",
        (MID,)).fetchall()
    assert [r["verdict"] for r in rows] == ["true", "false"]
    mid = [h for h in _mine(client.get("/api/hosts?limit=1000"))
           if h["host"] == MID][0]
    assert mid["verdict"]["verdict"] == "false"
    assert client.get(f"/api/hosts/{MID}/evidence").json()["verdict"][
        "verdict"] == "false"
    entries = engine.audit_service.entries(limit=5, kind="host.verdict")
    assert entries["count"] >= 2
    assert entries["items"][0]["actor"] == "admin"
    assert "seen c2" not in json.dumps(entries["items"])


def test_responses_are_metadata_only():
    bodies = [client.get("/api/hosts?limit=1000").text,
              client.get(f"/api/hosts/{HI}/evidence").text]
    for text in bodies:
        for forbidden in ("payload", "raw", "plaintext", "bytes_b64", "hex"):
            assert forbidden not in text.lower()
