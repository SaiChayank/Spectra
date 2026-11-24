"""Cookie-authenticated writes refuse foreign browser origins (CSRF).

SameSite=Lax stops cross-*site* requests from carrying the session cookie,
but browsers treat other ports on the same host (``localhost:9999``) and
sibling subdomains as the *same site*. A page there could submit an HTML
form - which needs no CORS preflight - to any POST route that takes no JSON
body (model rollback, audit key rotation, capture upload, alert resolve...)
and the browser would attach the operator's cookie. The gate now rejects an
unsafe request whose ``Origin`` is neither an allowed dashboard origin nor
the API's own host.
"""

from __future__ import annotations

import pytest

FOREIGN = "http://localhost:9999"


@pytest.mark.parametrize("origin", [FOREIGN, "null", "http://spectra.example.evil"])
def test_cookie_post_from_foreign_origin_is_refused(client, origin):
    res = client.post("/api/audit/checkpoint", headers={"Origin": origin})
    assert res.status_code == 403
    assert res.json() == {"detail": "cross-origin request refused"}


def test_form_upload_from_foreign_origin_is_refused(client):
    res = client.post("/api/captures", headers={"Origin": FOREIGN},
                      files={"file": ("x.pcap", b"\xd4\xc3\xb2\xa1" + b"\0" * 20)})
    assert res.status_code == 403


def test_foreign_origin_cannot_log_out_the_operator(viewer_client):
    # own session (not the shared admin one): on the old code this logout succeeded
    assert viewer_client.post("/api/auth/logout",
                              headers={"Origin": FOREIGN}).status_code == 403
    assert viewer_client.get("/api/auth/me").status_code == 200   # session intact


def test_login_from_foreign_origin_is_refused(raw_client):
    res = raw_client.post("/api/auth/login", headers={"Origin": FOREIGN},
                          json={"username": "admin", "password": "x"})
    assert res.status_code == 403


@pytest.mark.parametrize("origin", ["http://localhost:5173", "http://127.0.0.1:5173",
                                    "http://testserver"])
def test_dashboard_and_same_origin_writes_pass(client, origin):
    # configured dashboard origins, and same-origin (Origin host == Host)
    res = client.post("/api/audit/checkpoint", headers={"Origin": origin})
    assert res.status_code != 403


def test_requests_without_origin_are_unaffected(client):
    # curl, scripts and the CLI send no Origin; they cannot be a forged browser form
    assert client.post("/api/audit/checkpoint").status_code != 403


def test_reads_are_not_origin_checked(client):
    assert client.get("/api/auth/me", headers={"Origin": FOREIGN}).status_code == 200
