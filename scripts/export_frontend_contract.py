#!/usr/bin/env python
"""Export the frontend contract (docs/frontend-plan.md section 4.1).

    python scripts/export_frontend_contract.py          # (re)write frontend/contract/
    python scripts/export_frontend_contract.py --check  # exit 1 when the committed contract is stale

Writes ``frontend/contract/openapi.json`` and ``frontend/contract/fixtures/*.json``: real responses
recorded from the real FastAPI app (TestClient) against a throwaway data directory seeded with the demo
captures. Metadata only: the app never holds payload bytes, and this script adds none.

Redaction and normalisation (so a re-run is byte-identical and nothing sensitive is written):
  * passwords, TOTP secrets/otpauth URIs/recovery codes are replaced by "<redacted>" (request and response);
    session cookies appear only as cookie *names*; the final scan fails the run if any secret/path leaked.
  * wall-clock numbers (within a few days of the run start) -> 1800000000 + whole hours since start
    (type kept: float stays float). Synthetic capture timestamps (2023) are untouched: they are stable.
  * ids with a random part (alrt_*, mdl_*, cap_*) and every 64-hex digest -> deterministic stand-ins of the
    same length, numbered by first appearance. Absolute paths -> <DATA_DIR> / <REPO>.
  * keys in VOLATILE_KEYS (uptimes, durations, host load) -> 0; X-Request-ID and Retry-After are not kept
    except Retry-After (rounded to a bucket).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "frontend" / "contract"
BACKEND = ROOT / "backend"

# Obviously fake, test-only values (the data dir is a throwaway temp dir).
ADMIN_USER = "admin"
ADMIN_PW = "contract-export-fake-admin-pw"
VIEWER = ("contract-viewer", "contract-fake-viewer-pw")
ANALYST = ("contract-analyst", "contract-fake-analyst-pw")
PW_USER = ("contract-pwchange", "contract-fake-old-pw-1")
PW_NEW = "contract-fake-new-pw-2"
TOTP_USER = ("contract-totp", "contract-fake-totp-pw-1")

SECRET_KEYS = {"password", "code", "totp_code", "secret", "otpauth_uri", "otpauth", "recovery_codes",
               "token", "csrf", "csrf_token", "session"}
VOLATILE_KEYS = {"uptime_s", "latency_ms", "duration_ms", "load_avg", "cpu_percent", "mem_percent",
                 "rss_bytes", "elapsed_s", "elapsed_ms"}
FIXED_EPOCH = 1_800_000_000
KEEP_HEADERS = ("content-type", "retry-after")
WS_MESSAGES = 25

# GET routes that are not recorded (reason shown in the summary and the README).
SKIP_GET = {
    "/api/metrics": "Prometheus text, wall-clock counters; not JSON, not a UI data source",
}
# Query values needed by GET routes that require them.
QUERY = {
    "/api/search": {"q": "10.0.0.7"},
    "/api/audit/proof": {"seq": 1, "leaf": 0},
    "/api/model/registry/compare": None,   # filled once model ids exist
    "/api/graph/node": {"id": "10.0.0.7"},
    "/api/graph/cascade": {"id": "10.0.0.7"},
    "/api/graph/path": {"src": "10.0.0.7", "dst": "93.184.216.34"},
}


# ---------------------------------------------------------------------------------------------------
# recording
# ---------------------------------------------------------------------------------------------------

class Recorder:
    def __init__(self) -> None:
        self.items: list[dict] = []
        self.secrets: set[str] = set()
        self.start = time.time()

    def add(self, name_hint: str | None, rec: dict) -> None:
        rec["_variant"] = name_hint
        self.items.append(rec)

    def call(self, client, method: str, path: str, *, variant: str | None = None, query: dict | None = None,
             json_body=None, files=None, shape=None, expect: int | None = None):
        """One recorded call. ``shape`` overrides the stored body description (multipart)."""
        res = client.request(method, path, params=query, json=json_body, files=files)
        for ck in client.cookies.jar:
            self.secrets.add(ck.value)
        if "set-cookie" in res.headers:
            for part in res.headers.get_list("set-cookie"):
                m = re.match(r"[^=]+=([^;]*)", part)
                if m and m.group(1):
                    self.secrets.add(m.group(1))
        try:
            body = res.json()
        except ValueError:
            body = res.text
        hdrs = {k: res.headers[k] for k in KEEP_HEADERS if k in res.headers}
        names = [re.match(r"([^=]+)=", c).group(1) for c in res.headers.get_list("set-cookie")]
        if names:
            hdrs["set-cookie-names"] = names
        req_body = shape if shape is not None else _redact_req(json_body)
        self.add(variant, {
            "request": {"method": method, "path": path, "query": query or {}, "body": req_body},
            "status": res.status_code, "headers": hdrs, "body": _redact(body)})
        if expect is not None and res.status_code != expect:
            print(f"  note: {method} {path} {variant or ''} -> {res.status_code} (expected {expect})",
                  file=sys.stderr)
        return res


def _redact_req(body):
    if body is None:
        return None
    return _redact(body)


def _redact(o):
    if isinstance(o, dict):
        return {k: ("<redacted>" if k in SECRET_KEYS and v not in (None, "", [], {}) else _redact(v))
                for k, v in o.items()}
    if isinstance(o, list):
        return [_redact(v) for v in o]
    return o


# ---------------------------------------------------------------------------------------------------
# normalisation
# ---------------------------------------------------------------------------------------------------

class Normaliser:
    ID_RE = re.compile(r"\b(alrt|mdl|cap)_([0-9a-f]{8,})\b")
    HEX64 = re.compile(r"(?<![0-9A-Za-z])[0-9a-f]{64}(?![0-9A-Za-z])")

    def __init__(self, start: float, paths: dict[str, str]):
        self.start = start
        self.paths = sorted(paths.items(), key=lambda kv: -len(kv[0]))
        self.map: dict[str, str] = {}

    def _stand_in(self, token: str) -> str:
        if token not in self.map:
            h = hashlib.sha256(f"stand-in-{len(self.map)}".encode()).hexdigest()
            self.map[token] = (h * 2)[:len(token)]
        return self.map[token]

    def string(self, s: str) -> str:
        for real, ph in self.paths:
            s = s.replace(real, ph)
        s = self.ID_RE.sub(lambda m: f"{m.group(1)}_{self._stand_in(m.group(2))}", s)
        return self.HEX64.sub(lambda m: self._stand_in(m.group(0)), s)

    def number(self, x):
        if isinstance(x, bool):
            return x
        if self.start - 120 <= x <= self.start + 2 * 86400:
            v = FIXED_EPOCH + round((x - self.start) / 3600) * 3600
            return float(v) if isinstance(x, float) else int(v)
        return x

    def walk(self, o, key: str | None = None):
        if isinstance(o, dict):
            return {self.string(k): self.walk(v, k) for k, v in o.items()}
        if isinstance(o, list):
            return [self.walk(v) for v in o]
        if isinstance(o, str):
            return self.string(o)
        if isinstance(o, (int, float)) and not isinstance(o, bool):
            if key in VOLATILE_KEYS:
                return 0.0 if isinstance(o, float) else 0
            return self.number(o)
        return o


def fixture_name(method: str, path: str, variant: str | None) -> str:
    base = re.sub(r"[/{}]+", "_", path).strip("_")
    return f"{method}_{base}" + (f"__{variant}" if variant else "") + ".json"


def dumps(o) -> str:
    return json.dumps(o, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------------------------------------
# scenario
# ---------------------------------------------------------------------------------------------------

def wait_done(client, capture_id: int, timeout: float = 60.0) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        d = client.get(f"/api/captures/{capture_id}").json()
        if d.get("status") in ("COMPLETED", "FAILED", "STOPPED"):
            return d
        time.sleep(0.05)
    raise RuntimeError(f"capture {capture_id} did not finish")


def run_scenario(work: Path, rec: Recorder, app, engine, TestClient) -> None:
    from spectra.demo import make_baseline_pcap, make_suspicious_pcap

    pcaps = {}
    make_baseline_pcap(str(work / "baseline.pcap"))
    pcaps["baseline"] = work / "baseline.pcap"
    for tag, seed in (("suspicious", 11), ("suspicious2", 12), ("suspicious3", 13), ("suspicious4", 14)):
        make_suspicious_pcap(str(work / f"{tag}.pcap"), seed=seed)
        pcaps[tag] = work / f"{tag}.pcap"

    anon = TestClient(app)
    admin = TestClient(app)

    def login(client, user, pw, **kw):
        return rec.call(client, "POST", "/api/auth/login", json_body={"username": user, "password": pw}, **kw)

    def upload(client, tag, **kw):
        data = pcaps[tag].read_bytes()
        shape = {"multipart": {"file": {"filename": f"{tag}.pcap", "content_type": "application/octet-stream",
                                        "bytes": "<omitted>"}}}
        return rec.call(client, "POST", "/api/captures", shape=shape,
                        files={"file": (f"{tag}.pcap", data, "application/octet-stream")}, **kw)

    # -- unauthenticated + login ---------------------------------------------------------------
    rec.call(anon, "GET", "/api/health")
    rec.call(anon, "GET", "/api/auth/me", variant="401", expect=401)
    rec.call(anon, "GET", "/api/alerts", variant="401", expect=401)
    rec.call(anon, "POST", "/api/auth/login", variant="422", json_body={"username": ""}, expect=422)
    login(anon, ADMIN_USER, "wrong-password-fake", variant="401_bad_password")
    login(admin, ADMIN_USER, ADMIN_PW, expect=200)
    rec.call(admin, "GET", "/api/auth/me", expect=200)

    # -- empty database + no model (scenario switch in the plan) ---------------------------------
    empty_reads = ["/api/alerts", "/api/incidents", "/api/captures", "/api/flows", "/api/detections",
                   "/api/status", "/api/stats", "/api/model", "/api/model/registry", "/api/model/drift",
                   "/api/history/captures", "/api/history/detections", "/api/history/stats",
                   "/api/graph/summary", "/api/audit/head"]
    for p in empty_reads:
        rec.call(admin, "GET", p, variant="empty")

    # -- seed: baseline, train, suspicious captures ----------------------------------------------
    base = upload(admin, "baseline", expect=200).json()
    base_id = base["capture_id"]
    upload(admin, "baseline", variant="409_duplicate", expect=409)
    rec.call(admin, "POST", "/api/model/train", variant="400_too_few_flows_or_bad", json_body={
        "capture_id": base_id, "contamination": 0.02}, expect=200)       # real training (the P0 write)
    train_ok = rec.items[-1]["status"] == 200
    assert train_ok, "training the demo baseline failed"
    # a second model so compare/activate/rollback have something to act on
    rec.call(admin, "POST", "/api/model/train", variant="candidate_only",
             json_body={"capture_id": base_id, "contamination": 0.05, "activate": False}, expect=200)
    rec.call(admin, "POST", "/api/model/train", variant="422", json_body={"capture_id": base_id,
             "contamination": 5}, expect=422)
    rec.call(admin, "POST", "/api/model/train", variant="404_capture", json_body={"capture_id": 9999},
             expect=None)

    ids = {"capture_id": base_id}
    susp_ids = []
    for tag in ("suspicious", "suspicious2", "suspicious3"):
        cid = upload(admin, tag, expect=200).json()["capture_id"]
        susp_ids.append(cid)
    first = susp_ids[0]
    rec.call(admin, "POST", f"/api/captures/{first}/process", expect=200)
    wait_done(admin, first)
    rec.call(admin, "POST", f"/api/captures/{first}/process", variant="reprocess", expect=200)
    for cid in susp_ids[1:]:
        admin.post(f"/api/captures/{cid}/process")      # not recorded: seeding (same call as above)
        wait_done(admin, cid)

    alerts = admin.get("/api/alerts?limit=100").json()["items"]
    alert_ids = [a["alert_id"] for a in alerts]
    assert len(alert_ids) >= 2, f"expected >=2 demo alerts, got {len(alert_ids)}"
    ids["alert_id"] = alert_ids[0]

    # -- users + roles ------------------------------------------------------------------------------
    for (u, pw), role in ((VIEWER, "VIEWER"), (ANALYST, "ANALYST"), (PW_USER, "ANALYST"), (TOTP_USER, "VIEWER")):
        rec.call(admin, "POST", "/api/users", json_body={"username": u, "password": pw, "role": role},
                 variant=f"create_{role.lower()}" if u != PW_USER[0] and u != TOTP_USER[0] else
                 ("create_for_password_change" if u == PW_USER[0] else "create_for_totp"), expect=200)
    rec.call(admin, "POST", "/api/users", variant="409_duplicate",
             json_body={"username": VIEWER[0], "password": VIEWER[1], "role": "VIEWER"})
    rec.call(admin, "POST", "/api/users", variant="422_weak_input",
             json_body={"username": "x", "password": "short", "role": "NOPE"}, expect=422)
    users = admin.get("/api/users").json()["items"]
    uid = {u["username"]: u["id"] for u in users}
    ids["user_id"] = uid[ANALYST[0]]

    # -- incidents (read fixtures) + P0 writes, each on a fresh incident ----------------------------
    inc = rec.call(admin, "POST", "/api/incidents", json_body={
        "title": "Demo beacon investigation", "alert_ids": alert_ids[:1],
        "summary": "Two periodic flows from the suspicious demo capture"}, expect=200).json()
    ids["incident_id"] = inc["id"] if "id" in inc else inc.get("incident_id")
    iid = ids["incident_id"]
    rec.call(admin, "POST", f"/api/incidents/{iid}/notes", json_body={"body": "Checked the destination: unknown."},
             expect=200)
    rec.call(admin, "POST", f"/api/incidents/{iid}/notes", variant="422", json_body={"body": ""}, expect=422)
    rec.call(admin, "POST", f"/api/incidents/{iid}/investigate", expect=200)
    rec.call(admin, "POST", "/api/incidents", variant="422", json_body={"title": ""}, expect=422)

    def fresh_incident(title):
        r = admin.post("/api/incidents", json={"title": title})
        assert r.status_code == 200, r.text
        j = r.json()
        return j.get("id", j.get("incident_id"))

    i2 = fresh_incident("Resolve me")
    rec.call(admin, "POST", f"/api/incidents/{i2}/acknowledge", expect=200)
    rec.call(admin, "POST", f"/api/incidents/{i2}/resolve", expect=200)
    rec.call(admin, "POST", f"/api/incidents/{i2}/reopen", expect=200)
    i3 = fresh_incident("False positive")
    rec.call(admin, "POST", f"/api/incidents/{i3}/false-positive", expect=200)
    rec.call(admin, "POST", f"/api/incidents/{i3}/resolve", variant="409_bad_transition")
    rec.call(admin, "POST", "/api/incidents/correlate", expect=200)
    
    # -- alerts: acknowledge / resolve on fresh alerts -------------------------------------------------
    rec.call(admin, "POST", f"/api/alerts/{alert_ids[1]}/acknowledge", expect=200)
    rec.call(admin, "POST", f"/api/alerts/{alert_ids[1]}/resolve", expect=200)
    rec.call(admin, "POST", f"/api/alerts/{alert_ids[1]}/acknowledge", variant="409_already_resolved")

    # -- model registry actions --------------------------------------------------------------------------
    reg = admin.get("/api/model/registry").json()
    models = [m["model_id"] if "model_id" in m else m["id"] for m in reg["items"]]
    active = reg["active"]["model_id"] if "model_id" in reg["active"] else reg["active"]["id"]
    other = [m for m in models if m != active][0]
    ids["model_id"] = active
    QUERY["/api/model/registry/compare"] = {"a": active, "b": other}
    ids["name"] = None

    # -- read every GET route (ids that exist) -------------------------------------------------------------
    spec = app.openapi()
    for path in sorted(spec["paths"]):
        if "get" not in spec["paths"][path] or path in SKIP_GET:
            continue
        real = path
        for param in re.findall(r"{(\w+)}", path):
            if param == "name":
                names = admin.get("/api/model/eval").json()
                items = names.get("reports") or names.get("items") or []
                nm = items[0] if items and isinstance(items[0], str) else (items[0].get("name") if items else None)
                if nm is None:
                    break
                real = real.replace("{name}", nm)
            else:
                real = real.replace("{" + param + "}", str(ids[param]))
        else:
            rec.call(admin, "GET", real, query=QUERY.get(path))
    rec.call(admin, "GET", "/api/alerts", variant="filtered", query={"status": "OPEN", "limit": 2})
    rec.call(admin, "GET", "/api/flows", variant="limit_2", query={"limit": 2})
    rec.call(admin, "GET", "/api/flows", variant="422_bad_limit", query={"limit": "abc"}, expect=422)

    # registry writes after the reads (they change which model is active)
    rec.call(admin, "POST", f"/api/model/registry/{other}/validate", expect=200)
    rec.call(admin, "POST", f"/api/model/registry/{other}/activate", expect=200)
    rec.call(admin, "POST", "/api/model/registry/rollback", expect=200)
    rec.call(admin, "POST", f"/api/model/registry/{other}/retire", expect=None)
    rec.call(admin, "POST", f"/api/model/registry/{active}/retire", variant="409_active", expect=None)

    # -- audit writes ---------------------------------------------------------------------------------------------
    rec.call(admin, "POST", "/api/audit/checkpoint", expect=200)
    rec.call(admin, "GET", "/api/audit/checkpoint/verify", variant="after_checkpoint", expect=200)
    cert = rec.call(admin, "POST", "/api/audit/certificate", json_body={"seq": 1}, expect=None)

    # -- error variants --------------------------------------------------------------------------------------------
    rec.call(admin, "GET", "/api/alerts/alrt_doesnotexist", variant="404", expect=404)
    rec.call(admin, "GET", "/api/incidents/999999", variant="404", expect=404)
    rec.call(admin, "GET", "/api/captures/999999", variant="404", expect=404)
    rec.call(admin, "GET", "/api/users/999999", variant="404", expect=404)
    rec.call(admin, "GET", "/api/model/registry/mdl_doesnotexist", variant="404", expect=404)
    rec.call(admin, "POST", "/api/alerts/alrt_doesnotexist/acknowledge", variant="404", expect=404)

    viewer = TestClient(app)
    login(viewer, *VIEWER, variant="viewer", expect=200)
    rec.call(viewer, "GET", "/api/auth/me", variant="viewer", expect=200)
    rec.call(viewer, "POST", f"/api/captures/{susp_ids[0]}/process", variant="403_viewer", expect=403)
    rec.call(viewer, "POST", "/api/model/train", variant="403_viewer", json_body={"capture_id": base_id}, expect=403)
    rec.call(viewer, "POST", "/api/users", variant="403_viewer", expect=403,
             json_body={"username": "contract-nope", "password": "contract-fake-pw-9", "role": "VIEWER"})
    rec.call(viewer, "POST", f"/api/alerts/{alert_ids[0]}/acknowledge", variant="403_viewer", expect=403)
    rec.call(viewer, "PATCH", f"/api/users/{uid[VIEWER[0]]}", variant="403_viewer_own_password",
             json_body={"password": PW_NEW}, expect=403)
    analyst = TestClient(app)
    login(analyst, *ANALYST, variant="analyst", expect=200)
    rec.call(analyst, "GET", "/api/auth/me", variant="analyst", expect=200)
    rec.call(analyst, "POST", f"/api/alerts/{alert_ids[0]}/acknowledge", variant="analyst", expect=None)
    rec.call(analyst, "POST", "/api/model/train", variant="403_analyst", json_body={"capture_id": base_id}, expect=403)

    # -- logout (fresh session) ---------------------------------------------------------------------------------
    out = TestClient(app)
    login(out, ADMIN_USER, ADMIN_PW, variant="second_session", expect=200)
    rec.call(out, "POST", "/api/auth/logout", expect=200)
    rec.call(out, "GET", "/api/auth/me", variant="401_after_logout", expect=401)

    # -- change password (admin-only route today: see README) -------------------------------------------------------
    pw = TestClient(app)
    login(pw, *PW_USER, variant="before_password_change", expect=200)
    rec.call(admin, "PATCH", f"/api/users/{uid[PW_USER[0]]}", json_body={"password": PW_NEW}, expect=200)
    rec.call(pw, "GET", "/api/auth/me", variant="401_session_revoked_by_password_change", expect=401)
    login(pw, PW_USER[0], PW_NEW, variant="new_password", expect=200)
    rec.call(admin, "PATCH", f"/api/users/{uid[PW_USER[0]]}", variant="422_short_password",
             json_body={"password": "x"}, expect=422)
    rec.call(admin, "DELETE", f"/api/users/{uid[PW_USER[0]]}", expect=200)
    rec.call(admin, "DELETE", f"/api/users/{uid[ADMIN_USER]}", variant="409_self", expect=None)

    # -- TOTP (secret and recovery codes redacted) ------------------------------------------------------------------
    tt = TestClient(app)
    login(tt, *TOTP_USER, variant="totp_user", expect=200)
    rec.call(tt, "POST", "/api/auth/totp/setup", variant="wrong_password", json_body={"password": "wrong-fake"})
    sres = rec.call(tt, "POST", "/api/auth/totp/setup", json_body={"password": TOTP_USER[1]}, expect=200)
    for v in _collect(sres.json(), SECRET_KEYS):
        rec.secrets.add(v)
    rec.call(tt, "POST", "/api/auth/totp/enable", variant="wrong_code", json_body={"code": "000000"})
    rec.call(admin, "DELETE", f"/api/users/{uid[TOTP_USER[0]]}/totp", expect=200)

    # -- 429: login throttle (throwaway name so the admin is never locked out) -----------------------------------------------
    th = TestClient(app)
    for _ in range(40):
        r = th.post("/api/auth/login", json={"username": "contract-throttle", "password": "wrong-fake"})
        if r.status_code == 429:
            break
    rec.call(th, "POST", "/api/auth/login", variant="429_throttled",
             json_body={"username": "contract-throttle", "password": "wrong-fake"}, expect=429)

    # -- 503: locked database (same provocation as backend/tests/test_storage_unavailable.py) -------------------------------------
    db = engine.store._db
    db.conn.execute("PRAGMA busy_timeout=100")
    other_conn = sqlite3.connect(engine.config.db_path, timeout=1, isolation_level=None)
    other_conn.execute("BEGIN EXCLUSIVE")
    try:
        rec.call(admin, "POST", "/api/users", variant="503_storage_locked", expect=503,
                 json_body={"username": "contract-locked", "password": "contract-fake-pw-9", "role": "VIEWER"})
        rec.call(admin, "GET", "/api/stats", variant="during_lock", expect=200)
        rec.call(admin, "GET", "/api/health", variant="database_busy", expect=200)
    finally:
        other_conn.execute("ROLLBACK")
        other_conn.close()
        db.conn.execute("PRAGMA busy_timeout=5000")

    # -- key rotation last (changes the audit signing key of the throwaway dir only) ------------------------------------------------------------
    rec.call(admin, "POST", "/api/audit/rotate-key", expect=200)
    rec.call(admin, "GET", "/api/audit/verify", variant="after_rotation", expect=200)

    # -- WebSocket ----------------------------------------------------------------------------------------------------------------------------
    record_ws(rec, admin, upload, susp_ids_extra="suspicious4", pcaps=pcaps)


def _collect(o, keys):
    out = []
    if isinstance(o, dict):
        for k, v in o.items():
            if k in keys and isinstance(v, str) and v:
                out.append(v)
            elif k in keys and isinstance(v, list):
                out += [x for x in v if isinstance(x, str)]
            else:
                out += _collect(v, keys)
    elif isinstance(o, list):
        for v in o:
            out += _collect(v, keys)
    return out


def record_ws(rec: Recorder, admin, upload, susp_ids_extra: str, pcaps) -> None:
    msgs: list = []
    stop = threading.Event()
    with admin.websocket_connect("/ws/events") as ws:
        def reader():
            try:
                while len(msgs) < WS_MESSAGES and not stop.is_set():
                    msgs.append(ws.receive_json())
            except Exception:  # noqa: BLE001 - socket closed
                pass
        t = threading.Thread(target=reader, daemon=True)
        t.start()
        time.sleep(0.3)
        res = upload(admin, susp_ids_extra)
        cid = res.json()["capture_id"]
        admin.post(f"/api/captures/{cid}/process")
        wait_done(admin, cid)
        time.sleep(0.5)
        stop.set()
    t.join(timeout=3)
    rec.ws = msgs[:WS_MESSAGES]
    # the upload/process above went through ``upload`` (recorded as POST /api/captures); drop that duplicate
    rec.items = [i for i in rec.items if not (i["request"]["body"] and isinstance(i["request"]["body"], dict)
                 and i["request"]["body"].get("multipart", {}).get("file", {}).get("filename") ==
                 f"{susp_ids_extra}.pcap")]


# ---------------------------------------------------------------------------------------------------
# generation
# ---------------------------------------------------------------------------------------------------

def generate(out: Path) -> dict:
    """Write the contract into ``out`` and return a summary. Runs once per process (imports the app)."""
    for k in [k for k in os.environ if k.startswith("SPECTRA_")]:
        del os.environ[k]
    work = Path(tempfile.mkdtemp(prefix="spectra_contract_")).resolve()
    data = work / "data"
    data.mkdir()
    os.environ.update({"SPECTRA_DATA_DIR": str(data), "SPECTRA_MODEL_PATH": str(data / "spectra_model.joblib"),
                       "SPECTRA_ADMIN_PASSWORD": ADMIN_PW})
    os.chdir(work)                      # so no relative default path lands in the repository
    sys.path.insert(0, str(BACKEND))
    import warnings
    warnings.filterwarnings("ignore")
    from fastapi.testclient import TestClient

    import spectra.api.app as app_module
    app, engine = app_module.app, app_module.engine

    rec = Recorder()
    rec.ws = []
    try:
        run_scenario(work, rec, app, engine, TestClient)
        openapi = app.openapi()
    finally:
        pass

    norm = Normaliser(rec.start, {str(data): "<DATA_DIR>", str(work): "<WORK_DIR>", str(BACKEND): "<REPO>/backend",
                                  str(ROOT): "<REPO>"})
    files: dict[str, str] = {"openapi.json": dumps(openapi)}
    counts: dict[str, int] = {}
    seen: dict[str, int] = {}
    for it in rec.items:
        item = {k: v for k, v in it.items() if not k.startswith("_")}
        item = norm.walk(item)
        h = item["headers"]
        if "retry-after" in h:
            h["retry-after"] = "<seconds>"
        name = fixture_name(item["request"]["method"], item["request"]["path"], it["_variant"])
        if name in seen:                                # same call recorded twice: keep the first, numbered later ones
            seen[name] += 1
            name = name[:-5] + f"__{seen[name]}.json"
        seen.setdefault(name, 1)
        files["fixtures/" + name] = dumps(item)
        key = str(item["status"])
        counts[key] = counts.get(key, 0) + 1
    files["fixtures/ws_events.json"] = dumps({
        "description": "First messages from /ws/events: a status snapshot, then events emitted while a "
                       "capture is uploaded and processed.", "messages": norm.walk(rec.ws)})

    leaks = [s for s in sorted(rec.secrets | {ADMIN_PW, PW_NEW, VIEWER[1], ANALYST[1], PW_USER[1], TOTP_USER[1]})
             if len(s) >= 6 and any(s in v for v in files.values())]
    paths = [p for p in (str(work), str(data), str(ROOT), str(Path.home()), "admin_bootstrap", "/tmp/")
             if any(p in v for v in files.values())]
    if leaks or paths:
        raise SystemExit(f"redaction check FAILED: secrets={[(s[:4], [k for k, v in files.items() if s in v]) for s in leaks]} paths={paths}")

    import shutil
    if out.exists():
        for sub in (out / "fixtures",):
            shutil.rmtree(sub, ignore_errors=True)
    for rel, text in files.items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    os.chdir(ROOT)
    shutil.rmtree(work, ignore_errors=True)
    return {"files": len(files), "by_status": dict(sorted(counts.items())), "ws": len(rec.ws)}


def tree(d: Path) -> dict[str, bytes]:
    return {str(p.relative_to(d)): p.read_bytes() for p in sorted(d.rglob("*"))
            if p.is_file() and (p.name == "openapi.json" or p.parent.name == "fixtures")}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="regenerate into a temp dir; exit 1 on any difference")
    args = ap.parse_args()
    if args.check:
        tmp = Path(tempfile.mkdtemp(prefix="spectra_contract_check_"))
        summary = generate(tmp)
        new, old = tree(tmp), tree(CONTRACT)
        diff = sorted(k for k in set(new) | set(old) if new.get(k) != old.get(k))
        if diff:
            print(f"contract is stale ({len(diff)} file(s) differ); run: python scripts/export_frontend_contract.py")
            for k in diff[:30]:
                print("  ", k, "(missing)" if k not in old else "(removed)" if k not in new else "(changed)")
            return 1
        print(f"contract up to date ({summary['files']} files)")
        return 0
    summary = generate(CONTRACT)
    (CONTRACT / "proposed").mkdir(exist_ok=True)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
