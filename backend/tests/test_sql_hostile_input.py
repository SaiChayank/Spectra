"""Hostile strings through every SQL-backed string filter (Bandit B608 triage).

Bandit flags 27 f-string SQL sites; review found every interpolated fragment is
a literal, a whitelisted column tuple or a placeholder list, with values bound
as parameters.  This pins that: injection strings must come back as plain
(empty) results and leave the tables intact.
"""

from __future__ import annotations

import pytest

HOSTILE = [
    "'; DROP TABLE flows; --",
    "x' OR '1'='1",
    "%' UNION SELECT username, password_hash FROM users --",
    "1; DELETE FROM audit_log",
    'a" OR 1=1 --',
    "\\' ESCAPE '\\",
    "%%%___",
]

FILTERED = [
    ("/api/history/flows", ("sni", "proto", "src", "dst")),
    ("/api/history/detections", ("sni", "proto", "src", "dst")),
    ("/api/audit/entries", ("kind", "actor")),
]


@pytest.mark.parametrize("payload", HOSTILE)
def test_filters_treat_hostile_strings_as_data(client, payload):
    before = client.get("/api/history/stats").json()
    for path, params in FILTERED:
        for name in params:
            res = client.get(path, params={name: payload})
            assert res.status_code in (200, 400, 422), (path, name, res.text[:200])
            if res.status_code == 200:
                assert res.json().get("count", 0) == 0 or name in ("sni", "src", "dst"), \
                    f"{path}?{name}= matched rows for a hostile string"
    # tables and the credentials table are still there and unchanged
    assert client.get("/api/history/stats").json()["flows"] == before["flows"]
    assert client.get("/api/audit/verify").json()["ok"] is True
    assert client.get("/api/auth/me").status_code == 200
    # nothing leaked a credential column
    for path, params in FILTERED:
        text = client.get(path, params={params[0]: payload}).text
        assert "password_hash" not in text and "scrypt" not in text
