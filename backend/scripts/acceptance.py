#!/usr/bin/env python
"""Spectra acceptance runner.

Signs in as the local admin first (auth group: login, sessions, RBAC), then
exercises every API route group against a running server with that session,
opens the WebSocket with its token, runs negative-path checks, and sweeps the
CLI. Prints a PASS/WARN/FAIL table.

Admin credentials come from ``SPECTRA_ADMIN_PASSWORD`` (and optional
``SPECTRA_ADMIN_USERNAME``), falling back to ``data/admin_bootstrap.txt``.

    cd backend
    python scripts/acceptance.py                 # API + WS + CLI
    python scripts/acceptance.py --skip-cli      # API + WS only
    python scripts/acceptance.py --skip-ws       # API + CLI only

Exit code 0 = no FAILs (warnings allowed); 1 = at least one FAIL.
Requires the API to be running:  python -m spectra.cli serve --port 8787
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = "http://127.0.0.1:8787"
PCAP_BASE = os.path.join(BACKEND, "demo_pcaps", "baseline.pcap")
PCAP_SUSP = os.path.join(BACKEND, "demo_pcaps", "suspicious.pcap")
CAPTURE_STORE_DIR = os.path.realpath(os.environ.get(
    "SPECTRA_CAPTURE_STORE_DIR",
    os.path.join(os.environ.get("SPECTRA_DATA_DIR",
                                os.path.join(BACKEND, "data")), "captures")))

results: list[tuple[str, str, str, str]] = []
PROOF_SEQ: int | None = None
# capture ids the core group imported; later groups address them by id
CAP_SUSP_ID: int | None = None
CAP_BASE_ID: int | None = None
# session established by the auth group; attached to every later request
SESSION_COOKIE = "spectra_session"
COOKIE_HEADER: str | None = None
TOKEN: str | None = None


def add(group: str, name: str, state: str, detail: str = "") -> None:
    results.append((group, name, state, detail))
    mark = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}[state]
    print(f"  [{mark}] {group:<12} {name}" + (f"  — {detail}" if detail else ""))


def _decode(raw: bytes):
    # JSON endpoints decode to dicts; plain-text endpoints (Prometheus
    # metrics) return their body verbatim.
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return raw.decode("utf-8", errors="replace")


def _cookie_header() -> dict:
    """Session cookie for every request (empty until the auth group logs in)."""
    return {"Cookie": COOKIE_HEADER} if COOKIE_HEADER else {}


def set_session(token: str | None) -> None:
    """Install (or clear) the session used by every later request."""
    global COOKIE_HEADER, TOKEN
    TOKEN = token
    COOKIE_HEADER = f"{SESSION_COOKIE}={token}" if token else None


def _cookie_value(set_cookie: str) -> str | None:
    """Pull the session token back out of a Set-Cookie header."""
    marker = f"{SESSION_COOKIE}="
    if marker not in set_cookie:
        return None
    return set_cookie.split(marker, 1)[1].split(";", 1)[0] or None


def _call(r: urllib.request.Request, timeout: int):
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, _decode(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, _decode(exc.read())
        except Exception:  # noqa: BLE001
            return exc.code, {}


def req(method: str, path: str, body=None, timeout: int = 60):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    headers.update(_cookie_header())
    r = urllib.request.Request(
        BASE + path, data=data, method=method, headers=headers,
    )
    return _call(r, timeout)


def resp_headers(path: str) -> dict:
    """Response headers of a GET (correlation-id check; never the body)."""
    r = urllib.request.Request(BASE + path, headers=dict(_cookie_header()))
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        return {k.lower(): v for k, v in (exc.headers or {}).items()}


def upload(filename: str, payload: bytes, timeout: int = 60):
    """Import a capture: multipart bytes, never a server filesystem path."""
    boundary = "----SpectraAcceptBoundary7c1f"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; '
        f'filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + payload + f"\r\n--{boundary}--\r\n".encode()
    r = urllib.request.Request(
        BASE + "/api/captures", data=body, method="POST",
        headers=dict(
            {"Content-Type":
             f"multipart/form-data; boundary={boundary}"},
            **_cookie_header()),
    )
    return _call(r, timeout)


def admin_credentials() -> tuple[str, str]:
    """Admin credentials: ``SPECTRA_ADMIN_PASSWORD`` env, else the one-time
    bootstrap file the first start wrote (``data/admin_bootstrap.txt``)."""
    password = os.environ.get("SPECTRA_ADMIN_PASSWORD", "").strip()
    if password:
        return os.environ.get("SPECTRA_ADMIN_USERNAME", "admin"), password
    data_dir = os.environ.get("SPECTRA_DATA_DIR",
                              os.path.join(BACKEND, "data"))
    path = os.path.join(data_dir, "admin_bootstrap.txt")
    creds: dict[str, str] = {}
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if "=" in line and not line.lstrip().startswith("#"):
                    k, _, v = line.strip().partition("=")
                    creds[k] = v
    if creds.get("password"):
        return creds.get("username", "admin"), creds["password"]
    raise SystemExit(
        "no admin credentials: set SPECTRA_ADMIN_PASSWORD or leave "
        f"{path} in place")


def login(username: str, password: str) -> tuple[int, dict, str]:
    """POST /api/auth/login -> (status, body, Set-Cookie header)."""
    data = json.dumps({"username": username, "password": password}).encode()
    r = urllib.request.Request(
        BASE + "/api/auth/login", data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return (resp.status, _decode(resp.read()),
                    resp.headers.get("Set-Cookie", ""))
    except urllib.error.HTTPError as exc:
        try:
            return (exc.code, _decode(exc.read()),
                    exc.headers.get("Set-Cookie", ""))
        except Exception:  # noqa: BLE001
            return exc.code, {}, ""


def check(group: str, name: str, cond, detail="") -> bool:
    add(group, name, "pass" if cond else "fail", detail if not cond else "")
    return bool(cond)


def want(group: str, name: str, status: int, ok_codes=(200,), detail="") -> bool:
    return check(group, name, status in ok_codes,
                 f"HTTP {status} {detail}".strip())


def wait_capture(timeout: float = 45.0) -> dict:
    deadline = time.time() + timeout
    st: dict = {}
    while time.time() < deadline:
        _, st = req("GET", "/api/status")
        if not st.get("running"):
            return st
        time.sleep(0.4)
    return st


def wait_capture_terminal(capture_id: int, timeout: float = 45.0) -> dict:
    """Poll a capture resource until its status is terminal."""
    deadline = time.time() + timeout
    st: dict = {}
    while time.time() < deadline:
        _, st = req("GET", f"/api/captures/{capture_id}")
        if st.get("status") in ("COMPLETED", "FAILED", "STOPPED"):
            return st
        time.sleep(0.4)
    return st


def upload_fresh(filename: str, payload: bytes, timeout: int = 60):
    """Import, replacing an identical leftover resource (hermetic reruns)."""
    st, body = upload(filename, payload, timeout)
    if st == 409 and isinstance(body.get("detail"), dict):
        req("DELETE", f"/api/captures/{body['detail']['capture_id']}")
        st, body = upload(filename, payload, timeout)
    return st, body


def susp_capture_id() -> int | None:
    """The suspicious capture's id, importing it if the core group did not."""
    global CAP_SUSP_ID
    if CAP_SUSP_ID is None:
        with open(PCAP_SUSP, "rb") as fh:
            st, up = upload_fresh("suspicious.pcap", fh.read())
        if st == 200:
            CAP_SUSP_ID = int(up["capture_id"])
    return CAP_SUSP_ID


def base_capture_id() -> int | None:
    """The baseline capture's id (training / twin / delete checks)."""
    global CAP_BASE_ID
    if CAP_BASE_ID is None:
        with open(PCAP_BASE, "rb") as fh:
            st, up = upload_fresh("baseline.pcap", fh.read())
        if st == 200:
            CAP_BASE_ID = int(up["capture_id"])
    return CAP_BASE_ID


# ---------------------------------------------------------------- API groups


def run_auth() -> None:
    """Local authentication: login, sessions, RBAC, logout, re-login."""
    g = "auth"
    username, password = admin_credentials()

    # anonymous caller is refused at the gate, before any handler runs
    st, body = req("GET", "/api/stats")
    check(g, "unauthenticated request -> 401",
          st == 401 and isinstance(body, dict)
          and "auth" in str(body.get("detail", "")).lower()
          and "password" not in str(body),
          f"HTTP {st} detail={body.get('detail')!r}")

    # enumeration resistance: unknown user and wrong password look alike
    st_u, b_u, _ = login("no_such_user_acc", "whatever-123")
    st_w, b_w, _ = login(username, "definitely-not-the-password")
    check(g, "login failures are indistinguishable",
          st_u == 401 and st_w == 401 and b_u == b_w
          and b_u.get("detail") == "invalid username or password",
          f"unknown={st_u} wrong={st_w} detail={b_u.get('detail')!r}")

    # successful login: HttpOnly cookie, no secret material in the body
    st, body, set_cookie = login(username, password)
    if not check(g, "POST /api/auth/login",
                 st == 200 and body.get("user", {}).get("role") == "ADMIN",
                 f"HTTP {st} {body.get('detail', '')}"):
        return
    token = _cookie_value(set_cookie)
    check(g, "session cookie is HttpOnly + SameSite=Lax",
          bool(token) and "HttpOnly" in set_cookie
          and "samesite=lax" in set_cookie.lower(),
          set_cookie[:120])
    check(g, "login body carries no password or token material",
          "password" not in body and "scrypt$" not in json.dumps(body)
          and "token" not in json.dumps(body), sorted(body))
    if not token:
        add(g, "session established", "fail", "no session cookie returned")
        return
    set_session(token)

    # current user: role + permissions, still no hash material
    st, me = req("GET", "/api/auth/me")
    check(g, "GET /api/auth/me (ADMIN identity)",
          st == 200 and me.get("user", {}).get("username") == username
          and me.get("user", {}).get("role") == "ADMIN"
          and "users:manage" in (me.get("user", {}).get("permissions") or []),
          f"HTTP {st} role={(me.get('user') or {}).get('role')}")
    st, users = req("GET", "/api/users")
    check(g, "GET /api/users (no hash material)",
          st == 200 and (users.get("count") or 0) >= 1
          and "password_hash" not in json.dumps(users)
          and "scrypt$" not in json.dumps(users),
          f"HTTP {st} count={users.get('count')}")

    # -- role restriction end to end: a live VIEWER session ----------------
    admin_token = token
    viewer_name, viewer_pw = "acc_viewer", "acc-viewer-pass-2026"
    st, created = req("POST", "/api/users",
                      {"username": viewer_name, "password": viewer_pw,
                       "role": "VIEWER"})
    viewer_id = created.get("id") if st == 200 else None
    if st == 409:  # leftover account from an earlier interrupted run
        _, listing = req("GET", "/api/users?limit=200")
        viewer_id = next((u.get("id") for u in listing.get("items", [])
                          if u.get("username") == viewer_name), None)
    if check(g, "POST /api/users (create VIEWER)", st in (200, 409),
             f"HTTP {st} {created.get('detail', '')}"):
        vst, _, vcookie = login(viewer_name, viewer_pw)
        viewer_token = _cookie_value(vcookie)
        check(g, "VIEWER login", vst == 200 and bool(viewer_token),
              f"HTTP {vst}")
        if viewer_token:
            set_session(viewer_token)
            want(g, "VIEWER reads the dashboard", req("GET", "/api/stats")[0])
            caps = req("POST", "/api/capture/start", {"mode": "live"})[0]
            users_code = req("GET", "/api/users")[0]
            graph_code = req("GET", "/api/graph")[0]
            check(g, "VIEWER denied capture/users/graph (403)",
                  caps == 403 and users_code == 403 and graph_code == 403,
                  f"capture={caps} users={users_code} graph={graph_code}")
            set_session(admin_token)
            if viewer_id:
                want(g, "DELETE /api/users/{id}",
                     req("DELETE", f"/api/users/{viewer_id}")[0])
                set_session(viewer_token)
                check(g, "deleted account's session dies with it",
                      req("GET", "/api/auth/me")[0] == 401,
                      "session still live")
                set_session(admin_token)

    # -- logout kills the session; re-login restores access ----------------
    st, out = req("POST", "/api/auth/logout")
    check(g, "POST /api/auth/logout", st == 200 and out.get("ok") is True,
          f"HTTP {st} {out}")
    set_session(admin_token)     # replay the logged-out token
    check(g, "logged-out token replayed -> 401",
          req("GET", "/api/auth/me")[0] == 401, "replay accepted")
    set_session(None)
    st, _, set_cookie = login(username, password)
    token2 = _cookie_value(set_cookie)
    check(g, "re-login opens a fresh session",
          st == 200 and bool(token2) and token2 != admin_token, f"HTTP {st}")
    set_session(token2 or admin_token)
    check(g, "session usable for the rest of the run",
          req("GET", "/api/auth/me")[0] == 200, "")


def run_core() -> None:
    g = "core"
    want(g, "GET /api/health", req("GET", "/api/health")[0])
    want(g, "GET /api/status", req("GET", "/api/status")[0])
    want(g, "GET /api/stats", req("GET", "/api/stats")[0])
    want(g, "GET /api/flows", req("GET", "/api/flows?limit=5")[0])
    want(g, "GET /api/detections", req("GET", "/api/detections?limit=5")[0])
    want(g, "GET /api/interfaces", req("GET", "/api/interfaces")[0])
    want(g, "GET /api/metrics", req("GET", "/api/metrics")[0])

    stt, metrics_body = req("GET", "/api/metrics")
    check(g, "metrics is Prometheus plaintext",
          stt == 200 and isinstance(metrics_body, str)
          and "spectra_packets_total" in metrics_body
          and not metrics_body.lstrip().startswith('"'),
          f"type={type(metrics_body).__name__}")

    stt, cap = req("GET", "/api/capabilities")
    check(g, "GET /api/capabilities",
          stt == 200 and isinstance(cap, dict)
          and cap.get("modules", {}).get("tee", {}).get("status") == "SIMULATED"
          and cap.get("hardware_backed_count") == 0,
          f"HTTP {stt}")

    # -- system health: per-subsystem states, reasons, runtime metrics ----
    stt, health = req("GET", "/api/health/system")
    if check(g, "GET /api/health/system",
             stt == 200 and isinstance(health, dict), f"HTTP {stt}"):
        valid = {"HEALTHY", "DEGRADED", "UNAVAILABLE", "SIMULATED"}
        subs = health.get("subsystems") or []
        check(g, "health reports all 14 subsystems with reasons",
              len(subs) == 14
              and len({s.get("name") for s in subs}) == 14
              and all(s.get("state") in valid
                      and s.get("reason")
                      and isinstance(s.get("evidence"), dict)
                      for s in subs),
              f"n={len(subs)}")
        check(g, "health overall state + counts are coherent",
              health.get("state") in valid
              and sum((health.get("counts") or {}).values()) == 14
              and bool(health.get("reason")),
              f"state={health.get('state')} reason={health.get('reason')!r}")
        metrics = health.get("metrics") or {}
        check(g, "health metrics expose saturation, drops and latencies",
              {"packets", "flows", "queues", "inference", "database",
               "rates", "websocket", "errors"} <= set(metrics)
              and isinstance(metrics.get("queues", {}).get("saturation"), list)
              and isinstance(metrics.get("packets", {}).get("drop_ratio"),
                             (int, float))
              and isinstance(metrics.get("inference", {}).get("p95_ms"),
                             (int, float)),
              f"keys={sorted(metrics)}")
        # correlation id on every response (structured request log)
        headers = resp_headers("/api/health/system")
        check(g, "responses carry X-Request-ID",
              bool(headers.get("x-request-id")),
              f"headers={sorted(headers)}")

    # -- managed capture resources: import -> validate -> process ---------
    global CAP_SUSP_ID, CAP_BASE_ID
    with open(PCAP_SUSP, "rb") as fh:
        susp_bytes = fh.read()
    st, cap = upload_fresh("suspicious.pcap", susp_bytes)
    if not check(g, "POST /api/captures (import)",
                 st == 200 and cap.get("status") == "UPLOADED"
                 and cap.get("source_type") == "upload"
                 and (cap.get("size_bytes") or 0) == len(susp_bytes),
                 f"HTTP {st} {cap.get('detail', '')}"):
        return
    CAP_SUSP_ID = int(cap["capture_id"])
    check(g, "import stores under a generated name",
          str(cap.get("stored_name", "")).startswith("cap_")
          and "/" not in str(cap.get("stored_name", ""))
          and ".." not in str(cap.get("stored_name", "")),
          str(cap.get("stored_name")))

    st, dup = upload("suspicious-copy.pcap", susp_bytes)
    check(g, "duplicate import -> 409 with existing id",
          st == 409 and isinstance(dup.get("detail"), dict)
          and dup["detail"].get("capture_id") == CAP_SUSP_ID,
          f"HTTP {st}")

    st, _ = upload("notes.txt", b"hello world")
    check(g, "import rejects non-pcap extension -> 400", st == 400,
          f"HTTP {st}")
    st, _ = upload("junk.pcap", b"this is not a capture file at all")
    check(g, "import rejects bad signature -> 400", st == 400, f"HTTP {st}")

    # traversal filename: basename only (and this is the baseline resource)
    with open(PCAP_BASE, "rb") as fh:
        base_bytes = fh.read()
    st, trav = upload_fresh("../../data/baseline.pcap", base_bytes)
    ok, detail = (st == 200 and trav.get("original_name") == "baseline.pcap"
                  and str(trav.get("stored_name", "")).startswith("cap_"),
                  f"HTTP {st} name={trav.get('original_name')!r}")
    check(g, "traversal filename sanitized on import", ok, detail)
    if st == 200:
        CAP_BASE_ID = int(trav["capture_id"])

    st, page = req("GET", "/api/captures?limit=50")
    check(g, "GET /api/captures",
          st == 200 and (page.get("count") or 0) >= 1
          and CAP_SUSP_ID in [c.get("capture_id")
                              for c in page.get("items", [])],
          f"HTTP {st} count={page.get('count')}")
    st, det0 = req("GET", f"/api/captures/{CAP_SUSP_ID}")
    check(g, "GET /api/captures/{id}",
          st == 200 and det0.get("status") == "UPLOADED",
          f"HTTP {st} status={det0.get('status')}")

    st, _ = req("POST", f"/api/captures/{CAP_SUSP_ID}/process")
    if not want(g, "POST /api/captures/{id}/process", st, (200, 409)):
        return
    final = wait_capture()
    det = wait_capture_terminal(CAP_SUSP_ID)
    check(g, "capture completed",
          not final.get("running")
          and det.get("status") == "COMPLETED"
          and (det.get("flows") or 0) > 0,
          f"status={det.get('status')} flows={det.get('flows')} "
          f"error={det.get('error')}")
    check(g, "capture metadata persisted",
          det.get("source_type") == "upload"
          and det.get("original_name") == "suspicious.pcap"
          and (det.get("packets") or 0) > 0
          and (det.get("imported_at") or 0) > 0,
          str({k: det.get(k) for k in
               ("source_type", "original_name", "packets", "imported_at")}))

    # no server filesystem paths in API output (resource metadata, status)
    leaked = (CAPTURE_STORE_DIR in json.dumps(det)
              or os.path.isabs(str(final.get("source") or "")))
    check(g, "no server filesystem paths exposed", not leaked,
          f"status.source={final.get('source')!r}")
    check(g, "status.source is the imported name",
          final.get("source") == "suspicious.pcap",
          f"source={final.get('source')!r}")


def run_ws() -> None:
    g = "ws"
    try:
        import websockets  # noqa: F401
    except ImportError:
        add(g, "websocket events", "warn", "websockets lib not installed")
        return

    async def _run() -> list[str]:
        import websockets

        types: list[str] = []
        base_ws = BASE.replace("http", "ws", 1)
        # an anonymous handshake must be refused before any events flow
        try:
            async with websockets.connect(base_ws + "/ws/events",
                                          open_timeout=10):
                pass
            rejected = False
        except Exception:  # noqa: BLE001 - close 4401 / HTTP 403 both count
            rejected = True
        check(g, "anonymous WebSocket handshake refused", rejected,
              "connected without a session")

        url = base_ws + f"/ws/events?token={TOKEN or ''}"
        async with websockets.connect(url, open_timeout=10) as ws:
            cap_id = susp_capture_id()
            await asyncio.to_thread(
                lambda: req("POST", f"/api/captures/{cap_id}/process"))
            await asyncio.to_thread(wait_capture)
            deadline = time.time() + 12
            while time.time() < deadline:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=4)
                except asyncio.TimeoutError:
                    break
                try:
                    types.append(json.loads(raw).get("type", "?"))
                except Exception:  # noqa: BLE001
                    continue
                if "flow" in types and "status" in types:
                    break
        return types

    try:
        types = asyncio.run(asyncio.wait_for(_run(), timeout=60))
        ok = "flow" in types and "status" in types
        check(g, "flow + status events received", ok, f"types={sorted(set(types))}")
    except Exception as exc:  # noqa: BLE001
        add(g, "flow + status events received", "fail", str(exc))


def run_incidents() -> None:
    """Incident triage: create from a detection, acknowledge, annotate,
    resolve - all attributed to the signed-in user (incidents:manage)."""
    g = "incidents"
    username = admin_credentials()[0]
    # SQLite-backed (row_to_flow carries `id`); /api/detections is the
    # in-memory live buffer whose records have no durable id to anchor on.
    st, dets = req("GET", "/api/history/detections?limit=1")
    det_id = None
    if st == 200 and isinstance(dets, dict) and dets.get("items"):
        det_id = dets["items"][0].get("id")
    if det_id is None:
        add(g, "GET /api/history/detections (anchor)", "warn",
            f"HTTP {st} count={(dets or {}).get('count', '?') if isinstance(dets, dict) else '?'}"
            f" keys={list(dets)[:5] if isinstance(dets, dict) else type(dets).__name__}"
            f" items={len(dets.get('items') or []) if isinstance(dets, dict) else 0}")
        return
    st, inc = req("POST", "/api/incidents",
                  {"title": "acceptance triage", "detection_id": det_id})
    if not check(g, "POST /api/incidents",
                 st == 200 and inc.get("status") == "OPEN",
                 f"HTTP {st} {inc.get('detail', '')}"):
        return
    check(g, "incident attributed to the signed-in user",
          inc.get("created_by") == username
          and inc.get("detection_id") == det_id,
          str({k: inc.get(k) for k in ("created_by", "detection_id")}))
    iid = inc["id"]
    st, ack = req("POST", f"/api/incidents/{iid}/acknowledge")
    check(g, "acknowledge",
          st == 200 and ack.get("status") == "ACKNOWLEDGED", f"HTTP {st}")
    st, note = req("POST", f"/api/incidents/{iid}/notes",
                   {"body": "from acceptance"})
    check(g, "analyst note",
          st == 200 and note.get("author") == username, f"HTTP {st}")
    st, res = req("POST", f"/api/incidents/{iid}/resolve")
    check(g, "resolve",
          st == 200 and res.get("status") == "RESOLVED", f"HTTP {st}")
    st, _ = req("POST", f"/api/incidents/{iid}/resolve")
    check(g, "resolved is terminal (409)", st == 409, f"HTTP {st}")
    st, det = req("GET", f"/api/incidents/{iid}")
    check(g, "GET /api/incidents/{id} carries the note",
          st == 200 and det.get("note_count") == 1, f"HTTP {st}")
    st, _ = req("GET", "/api/incidents/999999")
    check(g, "unknown incident -> 404", st == 404, f"HTTP {st}")


def run_model() -> None:
    g = "model"
    st, body = req("POST", "/api/model/train",
                   {"capture_id": base_capture_id(), "contamination": 0.05})
    check(g, "POST /api/model/train", st == 200 and body.get("n_train", 0) > 0,
          f"HTTP {st} {body.get('detail', '')}")
    st, body = req("GET", "/api/model")
    check(g, "GET /api/model", st == 200 and body.get("trained") is True,
          f"HTTP {st}")
    want(g, "GET /api/model/drift", req("GET", "/api/model/drift")[0])
    want(g, "GET /api/model/evasion", req("GET", "/api/model/evasion")[0])
    want(g, "POST /api/model/robustness", req("POST", "/api/model/robustness", {})[0])


def run_history() -> None:
    g = "history"
    for name in ("flows", "detections", "captures", "stats", "model-runs",
                 "events"):
        want(g, f"GET /api/history/{name}", req("GET", f"/api/history/{name}")[0])


def run_graph() -> None:
    g = "graph"
    want(g, "GET /api/graph/summary", req("GET", "/api/graph/summary")[0])
    st, snap = req("GET", "/api/graph")
    if not want(g, "GET /api/graph", st):
        return
    nodes = snap.get("nodes") or []
    edges = snap.get("edges") or []
    if not nodes:
        add(g, "node/cascade/path", "warn", "graph empty (no flows yet)")
        return
    nid = nodes[0].get("id") if isinstance(nodes[0], dict) else nodes[0]
    want(g, "GET /api/graph/node", req("GET", f"/api/graph/node?id={urllib.parse.quote(str(nid))}")[0],
         (200, 404))
    want(g, "GET /api/graph/cascade",
         req("GET", f"/api/graph/cascade?id={urllib.parse.quote(str(nid))}")[0],
         (200, 404))
    if edges:
        src = urllib.parse.quote(str(edges[0].get("source", "")))
        dst = urllib.parse.quote(str(edges[0].get("target", "")))
        want(g, "GET /api/graph/path",
             req("GET", f"/api/graph/path?src={src}&dst={dst}")[0], (200, 404))
    else:
        add(g, "GET /api/graph/path", "warn", "no edges")


def run_pqc() -> None:
    g = "pqc"
    want(g, "GET /api/pqc", req("GET", "/api/pqc")[0])
    want(g, "GET /api/pqc/inventory", req("GET", "/api/pqc/inventory")[0])
    want(g, "GET /api/pqc/scan",
         req("GET", f"/api/pqc/scan?capture_id={susp_capture_id()}")[0])


def run_audit() -> None:
    global PROOF_SEQ
    g = "audit"
    want(g, "GET /api/audit/head", req("GET", "/api/audit/head")[0])
    st, entries = req("GET", "/api/audit/entries?limit=5")
    check(g, "GET /api/audit/entries (key: items)", st == 200 and "items" in entries,
          f"HTTP {st}")
    want(g, "GET /api/audit/verify", req("GET", "/api/audit/verify")[0])
    st, ck = req("POST", "/api/audit/checkpoint")
    if not check(g, "POST /api/audit/checkpoint", st == 200 and "seq" in ck,
                 f"HTTP {st} {ck.get('detail', '')}"):
        return
    seq = ck["seq"]
    want(g, "GET /api/audit/checkpoint/verify",
         req("GET", f"/api/audit/checkpoint/verify?seq={seq}")[0])
    # inclusion proofs target the capture.stop entry: its leaves are the
    # session's flow records (checkpoint entries carry no leaves)
    st, stops = req("GET", "/api/audit/entries?kind=capture.stop&limit=10")
    proof_seq = None
    if st == 200:
        for item in stops.get("items", []):
            st2, proof = req("GET",
                             f"/api/audit/proof?seq={item.get('seq')}&leaf=0")
            if st2 == 200 and proof.get("merkle_root"):
                proof_seq = item.get("seq")
                break
    if check(g, "GET /api/audit/proof (capture.stop leaf 0)", proof_seq is not None,
             "no capture.stop entry with leaves found"):
        st2, proof = req("GET", f"/api/audit/proof?seq={proof_seq}&leaf=0")
        check(g, "proof carries root + siblings",
              st2 == 200 and proof.get("siblings") is not None
              and proof.get("merkle_root"),
              f"HTTP {st2} keys={list(proof)}")
        PROOF_SEQ = proof_seq
    st, cert = req("POST", "/api/audit/certificate",
                   {"profile": "hipaa", "min_flows": 1})
    if check(g, "POST /api/audit/certificate", st == 200 and cert, f"HTTP {st}"):
        st2, v = req("POST", "/api/audit/certificate/verify", {"certificate": cert})
        check(g, "POST /api/audit/certificate/verify",
              st2 == 200 and v.get("ok") is True, f"HTTP {st2} ok={v.get('ok')}")


def run_twin() -> None:
    g = "twin"
    want(g, "GET /api/twin/topology", req("GET", "/api/twin/topology")[0])
    st, pbs = req("GET", "/api/twin/playbooks")
    if not want(g, "GET /api/twin/playbooks", st):
        return
    items = pbs.get("items") or pbs.get("playbooks") or []
    name = items[0].get("name") if items and isinstance(items[0], dict) else None
    sim = {"seed": 3, "rounds": 4, "capability": 0.6}
    want(g, "POST /api/twin/simulate", req("POST", "/api/twin/simulate", sim)[0])
    if name:
        want(g, "POST /api/twin/playbook",
             req("POST", "/api/twin/playbook", {"name": name, **sim})[0])
    else:
        add(g, "POST /api/twin/playbook", "warn", "no library playbooks listed")
    want(g, "POST /api/twin/evaluate", req("POST", "/api/twin/evaluate", sim)[0])
    want(g, "POST /api/twin/recommend", req("POST", "/api/twin/recommend", sim)[0])
    want(g, "POST /api/twin/shadow",
         req("POST", "/api/twin/shadow",
             {"capture_id": base_capture_id(), "retrain": True})[0])


def run_bio() -> None:
    g = "bio"
    st, body = req("GET", "/api/bio/status")
    check(g, "GET /api/bio/status", st == 200 and body.get("available") is True,
          f"HTTP {st} available={body.get('available')}")
    st, body = req("POST", "/api/bio/assess",
                   {"features": [0.0] * 39, "score": 42.0})
    check(g, "POST /api/bio/assess", st == 200 and body.get("available") is True,
          f"HTTP {st} {body.get('detail', '')}")


def run_tee() -> None:
    g = "tee"
    st, q = req("POST", "/api/tee/attest", {"nonce": "acc-1"})
    if not check(g, "POST /api/tee/attest", st == 200 and q.get("signature"),
                 f"HTTP {st}"):
        return
    st, v = req("POST", "/api/tee/verify", {"quote": q, "nonce": "acc-1"})
    checks_ok = all(c.get("ok") for c in v.get("checks", []))
    check(g, "POST /api/tee/verify (7 checks)", st == 200 and v.get("ok") and checks_ok,
          f"HTTP {st} ok={v.get('ok')}")
    st, v2 = req("POST", "/api/tee/verify", {"quote": q, "measurement": "0" * 64})
    check(g, "verify rejects wrong measurement", st == 200 and v2.get("ok") is False,
          f"ok={v2.get('ok')}")
    st, inf = req("POST", "/api/tee/infer", {"features": [0.1] * 39})
    check(g, "POST /api/tee/infer", st == 200 and inf.get("score") is not None
          and inf.get("receipt"), f"HTTP {st}")
    st, fed = req("POST", "/api/tee/federate",
                  {"deltas": [[0.1, 0.2], [0.3, 0.4]], "shareholders": 2, "seed": 5})
    check(g, "POST /api/tee/federate", st == 200 and fed.get("exact") is True
          and fed.get("aggregate") == [0.4, 0.6],
          f"HTTP {st} aggregate={fed.get('aggregate')}")
    check(g, "federate leaks no shares or seed",
          isinstance(fed, dict) and not any(
              k in fed for k in ("party_shares", "aggregate_shares", "seed")),
          f"keys={sorted(fed)}")


def run_edge() -> None:
    g = "edge"
    st, rep = req("GET", "/api/edge/report")
    check(g, "GET /api/edge/report",
          st == 200 and all(k in rep for k in
                            ("link", "link_profiles", "micro", "deployments",
                             "slices", "slice_counts")),
          f"HTTP {st} keys={list(rep) if st == 200 else rep}")
    st, out = req("POST", "/api/edge/link", {"link": "geostationary"})
    ok = st == 200 and abs(out.get("link", {}).get("timing_scale", 0) - 40.0) < 0.01
    check(g, "POST /api/edge/link (geo, scale 40)", ok, f"HTTP {st} {out}")
    st, out = req("POST", "/api/edge/link", {"link": "terrestrial"})
    check(g, "restore terrestrial link", st == 200, f"HTTP {st}")
    st, out = req("POST", "/api/edge/slice",
                  {"record": {"sni": "portal.hospital.example", "bytes": 900,
                              "packets": 6, "duration": 1.0,
                              "tls_version": "TLS 1.3"},
                   "level": 2})
    check(g, "POST /api/edge/slice (urllc escalates)",
          st == 200 and out.get("slice") == "urllc"
          and out.get("adjusted_level") == 3, f"HTTP {st} {out}")
    st, out = req("POST", "/api/edge/deploy", {"node": "mec-acc", "slice": "embb"})
    check(g, "POST /api/edge/deploy", st == 200 and out.get("digest"),
          f"HTTP {st} {out.get('detail', '')}")


def run_negative() -> None:
    global CAP_BASE_ID
    g = "negative"
    cases = [
        ("train missing field -> 422",
         ("POST", "/api/model/train", {}), (422,)),
        ("train by pcap_path is gone -> 422",
         ("POST", "/api/model/train", {"pcap_path": PCAP_BASE}), (422,)),
        ("pqc/scan unknown capture -> 404",
         ("GET", "/api/pqc/scan?capture_id=999999", None), (404,)),
        ("pqc/scan without capture_id -> 422",
         ("GET", "/api/pqc/scan?pcap=nope.pcap", None), (422,)),
        ("graph/node unknown -> 404",
         ("GET", "/api/graph/node?id=host:nope", None), (404,)),
        ("bio/assess wrong length -> 400",
         ("POST", "/api/bio/assess", {"features": [0.1] * 3}), (400,)),
        ("tee/federate 1 party -> 400",
         ("POST", "/api/tee/federate",
          {"deltas": [[0.1]], "shareholders": 3}), (400,)),
        ("edge/link unknown -> 400",
         ("POST", "/api/edge/link", {"link": "warp_drive"}), (400,)),
        ("capture/start bad mode -> 422",
         ("POST", "/api/capture/start", {"mode": "bogus"}), (422,)),
        ("capture/start pcap mode is gone -> 422",
         ("POST", "/api/capture/start",
          {"mode": "pcap", "path": PCAP_SUSP}), (422,)),
        ("capture details unknown -> 404",
         ("GET", "/api/captures/999999", None), (404,)),
        ("capture process unknown -> 404",
         ("POST", "/api/captures/999999/process", None), (404,)),
        ("audit/proof far seq -> 404",
         ("GET", "/api/audit/proof?seq=999999&leaf=0", None), (404,)),
        ("twin/simulate rounds over cap -> 422",
         ("POST", "/api/twin/simulate", {"rounds": 999}), (422,)),
    ]
    for name, (m, p, b), codes in cases:
        st, _ = req(m, p, b)
        check(g, name, st in codes, f"got HTTP {st}, want {codes}")

    # -- delete where safe: the baseline resource has finished its work ----
    base_id = CAP_BASE_ID
    if base_id:
        st, out = req("DELETE", f"/api/captures/{base_id}")
        check(g, "DELETE /api/captures/{id}",
              st == 200 and out.get("deleted") == base_id,
              f"HTTP {st} {out}")
        st, _ = req("GET", f"/api/captures/{base_id}")
        check(g, "deleted capture is gone", st == 404, f"HTTP {st}")
        with open(PCAP_BASE, "rb") as fh:
            st, again = upload("baseline.pcap", fh.read())
        check(g, "re-import after delete allowed",
              st == 200 and again.get("capture_id") != base_id,
              f"HTTP {st}")
        if st == 200:
            req("DELETE", f"/api/captures/{again.get('capture_id')}")
        CAP_BASE_ID = None
    else:
        add(g, "DELETE /api/captures/{id}", "warn", "no baseline capture id")


# ------------------------------------------------------------------ CLI sweep


def run_cli(tmp: str) -> None:
    g = "cli"
    env = dict(os.environ)
    env["PYTHONPATH"] = BACKEND + os.pathsep + env.get("PYTHONPATH", "")
    m2 = os.path.join(tmp, "m2.joblib")

    def run(args: list[str], name: str, timeout: int = 180):
        proc = subprocess.run(
            [sys.executable, "-m", "spectra.cli", *args],
            cwd=BACKEND, env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        check(g, "spectra " + name, proc.returncode == 0,
              f"exit={proc.returncode} {out.strip().splitlines()[-1][:160] if out.strip() else ''}")
        return proc

    run(["demo", "--out", os.path.join(tmp, "demo"), "--flows", "10",
         "--train", "--model", os.path.join(tmp, "m.joblib")], "demo")
    run(["train", PCAP_BASE, "--out", m2, "--contamination", "0.05"], "train")
    run(["scan", PCAP_SUSP, "--model", m2], "scan")
    run(["pqc", PCAP_SUSP], "pqc")
    run(["adversarial", PCAP_SUSP, "--model", m2], "adversarial")

    run(["audit", "entries", "--limit", "5"], "audit entries")
    run(["audit", "verify"], "audit verify")
    run(["audit", "checkpoint", "--json"], "audit checkpoint")
    proof_seq = PROOF_SEQ
    if proof_seq is None:
        try:
            _, stops = req("GET", "/api/audit/entries?kind=capture.stop&limit=5")
            proof_seq = (stops.get("items") or [{}])[0].get("seq")
        except Exception:  # noqa: BLE001
            proof_seq = None
    if proof_seq:
        run(["audit", "proof", "--seq", str(proof_seq), "--leaf", "0"],
            "audit proof")
    else:
        add(g, "spectra audit proof", "warn", "no capture.stop entry found")
    cert = os.path.join(tmp, "cert.json")
    if run(["audit", "certify", "--profile", "hipaa", "--out", cert],
           "audit certify").returncode == 0 and os.path.isfile(cert):
        run(["audit", "verify-cert", cert], "audit verify-cert")
    run(["audit", "profiles"], "audit profiles")

    run(["twin", "topology"], "twin topology")
    run(["twin", "playbooks"], "twin playbooks")
    run(["twin", "simulate", "--rounds", "4", "--seed", "3"], "twin simulate")
    run(["twin", "playbook", "--name", "beacon_containment", "--rounds", "4"],
        "twin playbook")
    run(["twin", "shadow", "--pcap", PCAP_BASE], "twin shadow")

    run(["bio", "status"], "bio status")
    run(["bio", "assess", PCAP_SUSP], "bio assess")

    proc = run(["tee", "attest", "--json"], "tee attest")
    quote = os.path.join(tmp, "quote.json")
    with open(quote, "w", encoding="utf-8") as fh:
        fh.write(proc.stdout)
    run(["tee", "verify", quote], "tee verify")
    run(["tee", "infer", PCAP_SUSP], "tee infer")
    run(["tee", "federate", "--pcap", PCAP_SUSP], "tee federate")

    run(["edge", "report"], "edge report")
    run(["edge", "link", "leo_satellite"], "edge link")
    run(["edge", "link", "terrestrial"], "edge link restore")
    run(["edge", "slice", "--sni", "x.example", "--bytes", "500",
         "--packets", "4", "--level", "2"], "edge slice")
    run(["edge", "deploy", "mec-cli-acc", "--slice", "embb"], "edge deploy")

    run(["status"], "status")
    add(g, "spectra serve", "pass", "covered by the running acceptance server")


def _npcap_present() -> bool:
    return os.path.exists(r"C:\Windows\System32\wpcap.dll")


def _make_https_traffic() -> None:
    """Poke a few HTTPS endpoints so live capture has TLS flows to track."""
    for url in ("https://www.example.com/", "https://www.cloudflare.com/",
                "https://github.com/", "https://www.wikipedia.org/"):
        try:
            urllib.request.urlopen(url, timeout=4).read(256)
        except Exception:  # noqa: BLE001 - best-effort traffic generation
            pass
        time.sleep(0.3)


def run_live(skip: bool = False) -> None:
    """Live NIC capture: gated on Npcap; requires an elevated API server."""
    g = "live"
    if skip:
        add(g, "live capture", "warn", "skipped via --skip-live")
        return
    if not _npcap_present():
        add(g, "live capture", "warn",
            "Npcap not installed - live path unverified (install from "
            "https://nmap.org/npcap/ and rerun)")
        return

    st, body = req("GET", "/api/interfaces")
    want(g, "GET /api/interfaces", st)
    ifaces = body.get("interfaces") or []
    details = body.get("details") or []
    check(g, "interfaces listed", len(ifaces) > 0, f"got {ifaces!r}")
    if not ifaces:
        return
    # prefer the adapter that actually carries traffic (real, non-APIPA IP)
    pick = next((d["id"] for d in details
                 if d.get("ip") and not d["ip"].startswith(("169.254", "127."))),
                ifaces[0])

    st, _ = req("POST", "/api/capture/start", {"mode": "live", "iface": pick})
    if not want(g, "POST /api/capture/start (live)", st):
        return

    threading.Thread(target=_make_https_traffic, daemon=True).start()
    saw_running = False
    deadline = time.time() + 8.0
    while time.time() < deadline:
        _, poll = req("GET", "/api/status")
        saw_running = saw_running or bool(poll.get("running"))
        time.sleep(0.5)

    _, status = req("GET", "/api/status")
    packets = status.get("packets", 0)
    check(g, "live capture ran cleanly", saw_running and not status.get("error"),
          f"error={status.get('error')!r}")
    check(g, "live packets > 0", packets > 0, f"packets={packets}")

    st, _ = req("POST", "/api/capture/stop")
    want(g, "POST /api/capture/stop", st)
    _, status = req("GET", "/api/status")
    flows = status.get("flows", 0)
    check(g, "live flows tracked >= 1", flows >= 1,
          f"flows={flows}, packets={status.get('packets', 0)}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--skip-cli", action="store_true")
    ap.add_argument("--skip-ws", action="store_true")
    ap.add_argument("--skip-live", action="store_true",
                    help="skip the Npcap-gated live capture group")
    args = ap.parse_args()

    try:
        urllib.request.urlopen(BASE + "/api/health", timeout=5)
    except Exception as exc:  # noqa: BLE001
        print(f"API not reachable at {BASE}: {exc}\n"
              f"Start it first:  cd backend && python -m spectra.cli serve --port 8787")
        return 1

    print("== auth (local accounts, sessions, RBAC) ==")
    run_auth()
    print("== core + capture ==")
    run_core()
    print("== incidents (analyst triage) ==")
    run_incidents()
    if not args.skip_ws:
        print("== websocket ==")
        run_ws()
    print("== model ==")
    run_model()
    print("== history ==")
    run_history()
    print("== graph (Module 7) ==")
    run_graph()
    print("== pqc (Module 1) ==")
    run_pqc()
    print("== audit (Module 5) ==")
    run_audit()
    print("== twin (Module 4) ==")
    run_twin()
    print("== bio (Module 6) ==")
    run_bio()
    print("== tee (Module 2) ==")
    run_tee()
    print("== edge (Module 8) ==")
    run_edge()
    print("== adversarial (Module 3, via robustness probe above) ==")
    print("== negative paths ==")
    run_negative()
    if not args.skip_cli:
        print("== CLI sweep ==")
        with tempfile.TemporaryDirectory(prefix="spectra_acc_") as tmp:
            run_cli(tmp)
    print("== live capture (Npcap-gated) ==")
    run_live(skip=args.skip_live)

    fails = [r for r in results if r[2] == "fail"]
    warns = [r for r in results if r[2] == "warn"]
    passes = [r for r in results if r[2] == "pass"]
    print(f"\n{len(passes)} passed, {len(warns)} warnings, {len(fails)} failed "
          f"of {len(results)} checks")
    for r in fails:
        print(f"  FAIL {r[0]} / {r[1]}: {r[3]}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
