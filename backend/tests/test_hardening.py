"""Hardening regression suite - the final engineering pass, pinned.

Every test maps to a specific fix from the security/robustness review:

* request size limits (declared *and* streamed bodies),
* login throttling, password storage strength, cache headers, config coercion,
* authorization (role gates, last-admin guard),
* error-surface hygiene (no stack/paths/input echoed, generic 500s, 4xx
  instead of 500 for client-caused failures, bounded pagination),
* the event WebSocket (origin policy + session revalidation while streaming),
* runtime/module bounds: filter length/depth, the offline flow budget,
  single-flight analysis, TEE SIMULATED labelling, artifact digests,
* capture files: bounded record reads (no gigabyte allocation from a crafted
  header), malformed/truncated captures mapping to 400, no server path in any
  error message, PCAPNG still readable,
* persistence: poisoned-batch recovery and the lookup indexes.

Nothing here is skipped, xfailed or asserted loosely - a failure means a
real regression in behaviour the review asked for.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import secrets
import struct
import threading
import time
import tracemalloc

import pytest
from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import PcapNgWriter
from starlette.websockets import WebSocketDisconnect

import spectra.api.app as app_module
from spectra.api.app import app
from spectra.api.runtime import cfg, engine
from spectra.api.security import SESSION_COOKIE
from spectra.auth import hash_password, password_needs_rehash, verify_password
from spectra.capture.base import CaptureError
from spectra.capture.pcap_file import PcapFileSource
from spectra.config import Config
from spectra.db.batch import WriteBuffer
from spectra.db.connection import StoreError
from spectra.db.migrations import MIGRATIONS
from spectra.filters import (MAX_FILTER_DEPTH, MAX_FILTER_LENGTH, FilterError,
                             compile_filter)
from spectra.ml.integrity import DIGEST_SUFFIX, digest_ok, write_digest
from spectra.modules.bio.system import BioSystem
from spectra.modules.tee import TeeEnclave
from spectra.modules.tee.enclave import QUOTE_ENVIRONMENT
from spectra.services.auth import LoginThrottle
from spectra.store import Store
from spectra.tools import FlowBudgetError, collect_flows

# Carries the session-scoped admin cookie (see conftest).
client = TestClient(app)

TEMP_PASSWORD = "Hardening-2026!"


def fresh_client() -> TestClient:
    """A client with no session cookie (anonymous caller)."""
    c = TestClient(app)
    c.cookies.clear()
    return c


def login(c: TestClient, username: str, password: str):
    return c.post("/api/auth/login",
                  json={"username": username, "password": password})


def _legacy_hash(password: str, n: int = 16384, r: int = 8,
                 p: int = 1) -> str:
    """A hash in the pre-hardening parameters (self-describing encoding)."""
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32,
        maxmem=128 * 1024 * 1024)
    b64 = lambda raw: base64.b64encode(raw).decode("ascii")  # noqa: E731
    return f"scrypt${n}${r}${p}${b64(salt)}${b64(derived)}"


# -- request size limits --------------------------------------------------------

def test_oversized_json_body_is_refused_with_413(client, monkeypatch):
    """The cap runs before auth/parse, so a huge body costs no work."""
    monkeypatch.setattr(app_module, "JSON_BODY_LIMIT", 512)
    res = client.post("/api/auth/login",
                      json={"username": "x", "password": "y",
                            "pad": "a" * 4096})
    assert res.status_code == 413, res.text
    assert res.json() == {"detail": "request body too large"}
    # refused before the handler: no session was opened by the probe
    assert not res.cookies.get(SESSION_COOKIE)


def test_body_limit_counts_declared_and_streamed_bodies(monkeypatch):
    """Content-Length is checked up front; a chunked body is counted as it
    streams, so neither encoding can buffer an unbounded payload."""
    monkeypatch.setattr(app_module, "JSON_BODY_LIMIT", 64)
    read: list[bytes] = []

    async def inner(scope, receive, send):
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        read.append(body)
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-length", b"2")]})
        await send({"type": "http.response.body", "body": b"{}"})

    limiter = app_module._BodyLimit(inner)
    scope = {"type": "http", "method": "POST", "path": "/api/x"}

    def drive(headers, messages) -> list[dict]:
        pending = list(messages)
        sent: list[dict] = []

        async def receive():
            return pending.pop(0) if pending else {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)

        asyncio.run(limiter({**scope, "headers": headers}, receive, send))
        return sent

    # declared length over the cap: refused without touching the body
    over_declared = drive([(b"content-length", b"1000")], [])
    assert over_declared[0]["status"] == 413
    assert read == []

    # no Content-Length (chunked): the second chunk crosses the cap
    over_streamed = drive([], [
        {"type": "http.request", "body": b"a" * 40, "more_body": True},
        {"type": "http.request", "body": b"b" * 40, "more_body": False},
    ])
    assert over_streamed[0]["status"] == 413
    assert read == []

    # within the cap: the route runs normally
    ok = drive([], [{"type": "http.request", "body": b'{"a":1}',
                     "more_body": False}])
    assert ok[0]["status"] == 200
    assert read == [b'{"a":1}']


# -- authentication ------------------------------------------------------------

def test_login_throttle_sheds_repeated_failures(monkeypatch):
    """Repeated failures from one source are answered 429 + Retry-After,
    while a distinct username keeps its own budget (no shared lockout)."""
    probe = f"hardening_throttle_{secrets.token_hex(3)}"
    monkeypatch.setattr(engine.auth, "throttle",
                        LoginThrottle(limit=2, ip_limit=100, window=60.0))
    anonymous = fresh_client()

    codes = [login(anonymous, probe, "wrong-password").status_code
             for _ in range(3)]
    assert codes == [401, 401, 429]

    blocked = login(anonymous, probe, "wrong-password")
    assert blocked.status_code == 429
    assert blocked.headers.get("Retry-After")
    assert "input" not in str(blocked.json().get("detail", ""))

    # a second (unused) username is not locked out by the first one
    other = f"{probe}_b"
    assert login(anonymous, other, "wrong-password").status_code == 401


def test_password_hash_uses_current_scrypt_work_factor():
    encoded = hash_password(TEMP_PASSWORD)
    assert encoded.startswith("scrypt$")
    n, r, p = (int(part) for part in encoded.split("$")[1:4])
    assert n >= 2 ** 16, "work factor must not fall below OWASP-aligned N"
    assert (r, p) == (8, 1)
    assert verify_password(TEMP_PASSWORD, encoded)
    assert not password_needs_rehash(encoded)

    legacy = _legacy_hash(TEMP_PASSWORD)
    assert verify_password(TEMP_PASSWORD, legacy)
    assert password_needs_rehash(legacy), "pre-hardening rows must upgrade"


def test_legacy_password_hash_is_upgraded_on_login(client):
    """A stored legacy hash is re-hashed to the current parameters right
    after its own proof - verified with the *stored* row, not the response."""
    username = f"hardening_upg_{secrets.token_hex(3)}"
    created = client.post("/api/users", json={
        "username": username, "password": TEMP_PASSWORD, "role": "VIEWER"})
    assert created.status_code == 200, created.text
    user_id = int(created.json()["id"])
    try:
        legacy = _legacy_hash(TEMP_PASSWORD)
        engine.store.update_user(user_id, password_hash=legacy)
        assert engine.store.find_user_credentials(
            username)["password_hash"] == legacy

        assert login(fresh_client(), username, TEMP_PASSWORD).status_code == 200

        upgraded = engine.store.find_user_credentials(
            username)["password_hash"]
        assert upgraded != legacy
        assert not password_needs_rehash(upgraded)
        assert verify_password(TEMP_PASSWORD, upgraded)
    finally:
        assert client.delete(f"/api/users/{user_id}").status_code == 200


def test_auth_responses_are_never_cached(client, raw_client):
    ok = client.get("/api/auth/me")
    assert ok.status_code == 200
    assert ok.headers.get("cache-control") == "no-store"

    denied = raw_client.get("/api/auth/me")
    assert denied.status_code == 401
    assert denied.headers.get("cache-control") == "no-store"

    # the header stays scoped to identity endpoints
    stats = client.get("/api/stats")
    assert stats.status_code == 200
    assert "no-store" not in stats.headers.get("cache-control", "")


def test_config_coerces_list_env_overrides(monkeypatch):
    """A comma-split list must never reach CORSMiddleware as a bare string
    (which would make it compare single characters as origins)."""
    monkeypatch.setenv("SPECTRA_CORS_ORIGINS",
                       "http://a.example, http://b.example")
    multi = Config.from_env().cors_origins
    assert isinstance(multi, list)
    assert multi == ["http://a.example", "http://b.example"]

    monkeypatch.setenv("SPECTRA_CORS_ORIGINS", "http://solo.example")
    solo = Config.from_env().cors_origins
    assert isinstance(solo, list)
    assert solo == ["http://solo.example"]


# -- authorization -------------------------------------------------------------

def test_investigation_probe_is_denied_to_viewers(viewer_client,
                                                  analyst_client):
    """The 403 is a permission decision, not a validation artefact: an
    ANALYST reaches the handler (and then the missing capture)."""
    res = viewer_client.get("/api/pqc/scan?capture_id=999999")
    assert res.status_code == 403, res.text

    allowed = analyst_client.get("/api/pqc/scan?capture_id=999999")
    assert allowed.status_code == 404, allowed.text


def test_last_admin_cannot_be_demoted(client):
    admins = [u for u in client.get("/api/users?limit=200").json()["items"]
              if u["role"] == "ADMIN"]
    assert admins, "expected the bootstrap admin to exist"
    for admin in admins:
        res = client.patch(f"/api/users/{admin['id']}",
                           json={"role": "ANALYST"})
        assert res.status_code == 409, res.text
        assert "last ADMIN" in res.json()["detail"]
    # the account is untouched
    assert client.get(f"/api/users/{admins[0]['id']}").json()["role"] == "ADMIN"


# -- error surface & input validation ------------------------------------------

def test_validation_errors_never_echo_request_input(client):
    query = client.get("/api/history/flows?limit=0")
    assert query.status_code == 422
    assert isinstance(query.json()["detail"], list)
    for err in query.json()["detail"]:
        assert {"loc", "msg", "type"} <= set(err)
        assert "input" not in err

    body = client.post("/api/model/robustness", json={"max_features": 999})
    assert body.status_code == 422
    for err in body.json()["detail"]:
        assert "input" not in err


def test_huge_numeric_ids_answer_422(client):
    res = client.get(f"/api/incidents/{9 * 10 ** 27}")
    assert res.status_code == 422, res.text
    assert res.json()["detail"] == "numeric parameter out of range"


def test_internal_failures_answer_generic_500(client, monkeypatch):
    """Model/storage exceptions are logged in full but never reach the
    client (no SQL, no paths, no stack trace)."""

    def _model_boom(*args, **kwargs):
        raise RuntimeError("internal detail /srv/private/model.bin")

    def _store_boom(*args, **kwargs):
        raise StoreError("no such column: secret_hash at /srv/data/db.sqlite")

    monkeypatch.setattr(engine.model, "robustness", _model_boom)
    res = client.post("/api/model/robustness", json={})
    assert res.status_code == 500, res.text
    assert res.headers["content-type"].startswith("application/json")
    assert res.json() == {"detail": "robustness evaluation failed"}
    assert "/srv/private" not in res.text

    monkeypatch.setattr(engine.capture_resources, "list_captures", _store_boom)
    res = client.get("/api/captures")
    assert res.status_code == 500, res.text
    assert res.json() == {"detail": "persistence failure"}
    assert "/srv/data" not in res.text

    monkeypatch.setattr(engine.store, "query_flows", _store_boom)
    res = client.get("/api/history/flows")
    assert res.status_code == 500, res.text
    assert res.json() == {"detail": "storage error"}
    assert "/srv/data" not in res.text


def test_offline_flow_budget_answers_400(client, monkeypatch):
    """An oversized capture is a client-side condition (400), not an
    internal failure - checked on both routes that read a capture offline."""

    def _over_budget(*args, **kwargs):
        raise FlowBudgetError(
            "capture holds more than 250000 complete flows - "
            "refusing to buffer it")

    for path, method, payload in (
        ("/api/model/robustness", "robustness", {}),
        ("/api/twin/shadow", "shadow", {}),
    ):
        monkeypatch.setattr(engine.model, method, _over_budget)
        res = client.request("POST", path, json=payload)
        assert res.status_code == 400, f"{path}: {res.text}"
        assert "complete flows" in res.json()["detail"]
        assert "Traceback" not in res.text


def test_pagination_limits_are_bounded(client):
    for limit in (0, -1, 1001, 10 ** 6):
        res = client.get(f"/api/history/flows?limit={limit}")
        assert res.status_code == 422, f"limit={limit}: {res.status_code}"
    assert client.get("/api/history/flows?limit=1000").status_code == 200
    assert client.get("/api/history/detections?limit=1000").status_code == 200


# -- event WebSocket ------------------------------------------------------------

def test_websocket_rejects_foreign_origin_with_4403(client):
    """Cross-site WebSocket hijacking: a browser session must not be usable
    from an origin that is neither same-host nor configured."""
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(
                "/ws/events", headers={"Origin": "http://evil.example"}):
            pass
    assert exc.value.code == 4403


def test_websocket_accepts_same_host_and_configured_origins(client):
    for origin in (None, "http://testserver", cfg.cors_origins[0]):
        kwargs = {"headers": {"Origin": origin}} if origin else {}
        with client.websocket_connect("/ws/events", **kwargs) as ws:
            assert ws.receive_json()["type"] == "status", origin


def _await_close(session, timeout: float) -> dict:
    """Read the socket until the app closes it, bounded.

    ``WebSocketTestSession.receive`` blocks with no timeout of its own, so
    the read runs in a daemon thread and the caller asserts on the result:
    a revalidation regression fails the assertion instead of hanging the
    suite (no per-test timeout plugin here).
    """
    outcome: dict[str, object] = {}

    def _run() -> None:
        try:
            while True:
                message = session.receive()
                if message.get("type") == "websocket.close":
                    outcome["code"] = int(message.get("code") or 1000)
                    return
        except BaseException as exc:  # portal teardown cancels a blocked read
            outcome["error"] = repr(exc)

    worker = threading.Thread(target=_run, name="ws-drain", daemon=True)
    worker.start()
    worker.join(timeout)
    outcome["finished"] = not worker.is_alive()
    return outcome


def test_websocket_session_revalidated_after_logout(client, monkeypatch):
    """Logout closes an already-connected stream (4401) instead of letting a
    revoked session keep reading events until its TTL lapses."""
    monkeypatch.setattr(app_module, "REVALIDATE_INTERVAL", 0.3)
    username = f"hardening_ws_{secrets.token_hex(3)}"
    created = client.post("/api/users", json={
        "username": username, "password": TEMP_PASSWORD, "role": "VIEWER"})
    assert created.status_code == 200, created.text
    user_id = int(created.json()["id"])
    try:
        c = fresh_client()
        assert login(c, username, TEMP_PASSWORD).status_code == 200
        token = c.cookies.get(SESSION_COOKIE)
        assert token

        with c.websocket_connect(f"/ws/events?token={token}") as ws:
            assert ws.receive_json()["type"] == "status"
            assert c.post("/api/auth/logout").status_code == 200
            outcome = _await_close(ws, timeout=5.0)

        assert outcome.get("code") == 4401, outcome
        assert outcome.get("finished") is True, outcome
    finally:
        assert client.delete(f"/api/users/{user_id}").status_code == 200


# -- runtime & module bounds -----------------------------------------------------

def test_filter_expression_length_and_depth_are_capped():
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234,
                                                             dport=443)
    # a sane expression still compiles and matches
    assert compile_filter("tcp")(pkt)

    # length is rejected before tokenizing
    with pytest.raises(FilterError, match="too long"):
        compile_filter("x" * (MAX_FILTER_LENGTH + 1))

    # ... and the recursive negation parse is depth-bounded
    with pytest.raises(FilterError, match="deeper than"):
        compile_filter("not " * (MAX_FILTER_DEPTH + 2) + "tcp")


def test_offline_flow_collection_is_budgeted(tmp_path):
    """One offline run may not buffer an unbounded number of flows."""
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    from spectra.demo import write_pcap

    def _syn(src: str, dst: str, sport: int, dport: int):
        return (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                / IP(src=src, dst=dst)
                / TCP(sport=sport, dport=dport, flags="S", seq=1))

    pcap = write_pcap(str(tmp_path / "two_flows.pcap"), [
        _syn("10.7.0.1", "10.7.0.2", 51000, 443),
        _syn("10.7.0.3", "10.7.0.4", 51001, 443),
    ])
    assert len(collect_flows(pcap, max_flows=10)) == 2   # both fit

    with pytest.raises(FlowBudgetError, match="complete flows"):
        collect_flows(pcap, max_flows=1)                 # budget enforced


def test_analysis_slot_refuses_a_second_concurrent_run(client):
    """Single-flight: a burst of analysis requests is refused immediately
    (409) instead of queueing worker threads behind a model fit."""
    with engine.model.analysis_slot():
        res = client.post("/api/model/robustness", json={})
        assert res.status_code == 409, res.text
        assert "already running" in res.json()["detail"]
    # released on exit: the guard is a slot, not a latch
    assert engine.model.analysis_lock.acquire(blocking=False)
    engine.model.analysis_lock.release()


def test_tee_quote_labels_itself_simulated(tmp_path):
    """The attestation quote is software-only and says so inside the signed
    body, so no consumer can mistake it for hardware attestation."""
    model = tmp_path / "model.bin"
    model.write_bytes(b"model-weights-v1")
    tee = TeeEnclave(str(model), key_path=str(tmp_path / "tee.key"))

    quote = tee.quote(nonce="hardening-1")
    assert quote["environment"] == QUOTE_ENVIRONMENT == "SIMULATED"

    report = tee.verify(quote, nonce="hardening-1")
    assert report["ok"] is True
    assert report["environment"] == "SIMULATED"
    checks = {c["name"]: c for c in report["checks"]}
    assert checks["environment"]["ok"] is True

    # the label is signed: relabelling the quote invalidates the signature
    forged = dict(quote, environment="HARDWARE")
    broken = tee.verify(forged, nonce="hardening-1")
    assert broken["ok"] is False
    failed = [c["name"] for c in broken["checks"] if not c["ok"]]
    assert "signature" in failed

    # the signing key is written owner-only where the platform has mode bits
    if os.name == "posix":
        assert os.stat(tee.key_path).st_mode & 0o077 == 0
    else:  # pragma: no cover - Windows has no POSIX mode bits
        assert os.stat(tee.key_path).st_mode & 0o200


def test_artifact_digest_refuses_corrupted_state(tmp_path):
    path = str(tmp_path / "bio_state.joblib")
    with open(path, "wb") as fh:
        fh.write(b"state-bytes-v1")
    write_digest(path)
    assert digest_ok(path)

    # one flipped byte: the sidecar disagrees, so nothing is unpickled
    with open(path, "ab") as fh:
        fh.write(b"\x00")
    assert not digest_ok(path)
    assert BioSystem().load(path) is False

    # a missing sidecar is the documented legacy path (load, but log it)
    legacy = str(tmp_path / "legacy.joblib")
    with open(legacy, "wb") as fh:
        fh.write(b"legacy-state")
    assert digest_ok(legacy)

    # an unreadable/unparseable sidecar is refused rather than ignored
    with open(path + DIGEST_SUFFIX, "w", encoding="ascii") as fh:
        fh.write("not-a-digest\n")
    assert not digest_ok(path)


# -- persistence ----------------------------------------------------------------

def test_batch_flush_discards_a_poisoned_batch(tmp_path):
    """A row that cannot be committed is dropped with its batch: otherwise
    the same failing rows would be retried (and fail) forever, wedging
    every later flush."""
    store = Store(str(tmp_path / "poison.db"))
    try:
        buf = WriteBuffer(store._db, batch_size=2, flush_interval=0.0)
        buf.add("events", (time.time(), "hardening", None, '{"n":0}'))
        with pytest.raises(StoreError):
            buf.add("events", (object(),))     # batch full -> commit fails

        assert buf.pending() == 0              # dropped, not replayed
        assert buf.flush() == 0

        # the writer is not wedged: healthy rows still commit
        buf.add("events", (time.time(), "hardening", None, '{"n":1}'))
        buf.add("events", (time.time(), "hardening", None, '{"n":2}'))
        assert buf.pending() == 0
        rows = store._db.query(
            "SELECT COUNT(*) AS n FROM events WHERE type = 'hardening'")
        assert rows[0]["n"] == 2
    finally:
        store.close()


def test_lookup_indexes_are_created(tmp_path):
    store = Store(str(tmp_path / "indexes.db"))
    try:
        assert store.schema_version == MIGRATIONS[-1].version
        indexes = {r["name"] for r in store._db.query(
            "SELECT name FROM sqlite_master WHERE type='index' "
            "AND name LIKE 'idx_%'")}
        # actor-filtered audit page + duplicate-import hash lookup
        assert {"idx_audit_actor", "idx_captures_hash"} <= indexes
    finally:
        store.close()


# -- capture files ---------------------------------------------------------------

def _crafted_pcap(path: str, caplen: int = 0x20000000) -> None:
    """A 40-byte PCAP whose single record header claims ``caplen`` bytes."""
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        fh.write(struct.pack("<IIII", 1_700_000_000, 0, caplen, caplen))


def test_crafted_record_length_cannot_drive_a_gigabyte_allocation(tmp_path):
    """scapy reads ``caplen`` bytes straight from the record header, so a
    40-byte capture could otherwise make the server allocate half a GiB (and a
    4 GiB claim 4 GiB).  No record can be longer than its own file."""
    path = tmp_path / "crafted.pcap"
    _crafted_pcap(str(path))

    already = tracemalloc.is_tracing()
    if not already:
        tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        list(PcapFileSource(str(path)).packets())   # must not raise
        _, peak = tracemalloc.get_traced_memory()
    finally:
        if not already:
            tracemalloc.stop()

    # Measured unclamped: 536,880,110 bytes for the 512 MiB claim.
    assert peak < 8 * 1024 * 1024


def test_capture_errors_report_a_basename_not_a_path(tmp_path):
    """Error text reaches HTTP clients: no server-side directory may leak."""
    missing = tmp_path / "gone.pcap"
    with pytest.raises(CaptureError) as exc:
        PcapFileSource(str(missing))
    assert "gone.pcap" in str(exc.value)
    assert str(tmp_path) not in str(exc.value)

    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"\x00\x01\x02\x03" + b"\x00" * 40)   # not pcap/pcapng
    with pytest.raises(CaptureError) as exc2:
        list(PcapFileSource(str(bad)).packets())
    assert "bad.pcap" in str(exc2.value)
    assert str(tmp_path) not in str(exc2.value)


def test_truncated_pcapng_block_is_a_capture_error(tmp_path):
    """A block claiming more bytes than follow fails mid-iteration: that must
    surface as CaptureError (HTTP 400 on the capture/training routes), not as
    a raw scapy exception escaping to a 500."""
    path = tmp_path / "trunc.pcapng"
    with open(path, "wb") as fh:
        # SHB (28 B) + IDB (20 B), then an EPB whose block length claims 40
        # bytes while only 16 bytes of it are present.
        fh.write(struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D,
                             1, 0, -1, 28))
        fh.write(struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20))
        fh.write(struct.pack("<III", 6, 40, 0) + b"\x00" * 8)

    with pytest.raises(CaptureError) as exc:
        list(PcapFileSource(str(path)).packets())
    assert "trunc.pcapng" in str(exc.value)
    assert str(tmp_path) not in str(exc.value)


def test_pcapng_captures_still_read_through_the_bounded_stream(tmp_path):
    """Regression guard for handing scapy a clamped stream instead of a path:
    that is what keeps its PCAP -> PCAPNG fallback on the same file object."""
    pkt = (Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
           / IP(src="10.1.1.1", dst="10.2.2.2")
           / TCP(sport=1234, dport=443, flags="S"))
    path = tmp_path / "one.pcapng"
    with PcapNgWriter(str(path)) as writer:
        writer.write(pkt)

    packets = list(PcapFileSource(str(path)).packets())
    assert len(packets) == 1
    assert packets[0][IP].src == "10.1.1.1"
