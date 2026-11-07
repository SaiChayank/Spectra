#!/usr/bin/env python
"""Install the built wheel into a clean virtualenv and run it (Phase 11 gate).

    python scripts/smoke_install.py backend/dist/spectra-1.0.0-py3-none-any.whl
    python scripts/smoke_install.py <wheel> --python 3.13 --report smoke.txt

The environment contains only the wheel and what pip resolves for it (no test or
dev packages), so a dependency that is imported at runtime but undeclared fails here.
Then ``spectra serve`` starts on a free loopback port with a throwaway data directory
and a generated model path, and the script checks the real surface: dashboard, asset
caching and security headers, SPA fallback, API 404 shape, login with the bootstrap
password (read from its mode-0600 file, never printed), metrics, the event WebSocket
(refused without a session, accepted with one), key-file permissions, clean shutdown.

Exit 0 only if every check passes.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, bool(ok), detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  - {detail}" if detail else ""), flush=True)
    return bool(ok)


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http(base: str, path: str, *, method: str = "GET", body: dict | None = None,
         cookie: str | None = None, timeout: float = 15.0):
    headers = {"Content-Type": "application/json"} if body is not None else {}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(base + path, method=method, headers=headers,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


WS_PROBE = r"""
import asyncio, sys
from websockets.asyncio.client import connect
async def main(url, origin, cookie):
    headers = {"Origin": origin}
    if cookie:
        headers["Cookie"] = cookie
    try:
        async with connect(url, additional_headers=headers, open_timeout=8) as ws:
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=4)
                print("OPEN first-frame", len(msg))
            except asyncio.TimeoutError:
                print("OPEN quiet")
    except Exception as exc:
        code = getattr(getattr(exc, "rcvd", None), "code", None)
        status = getattr(getattr(exc, "response", None), "status_code", None)
        print("REFUSED", type(exc).__name__, code, status)
asyncio.run(main(*sys.argv[1:4]))
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("wheel")
    ap.add_argument("--python", default=None, help="interpreter/version for the venv (uv syntax, e.g. 3.13)")
    ap.add_argument("--keep", action="store_true", help="keep the temp directory")
    args = ap.parse_args()
    wheel = os.path.abspath(args.wheel)
    tmp = tempfile.mkdtemp(prefix="spectra_smoke_")
    venv = os.path.join(tmp, "venv")
    data = os.path.join(tmp, "data")
    py = os.path.join(venv, "bin", "python")
    uv = shutil.which("uv")
    server: subprocess.Popen | None = None
    try:
        print(f"== install {os.path.basename(wheel)} into a clean venv ({tmp})")
        t0 = time.time()
        if uv:
            r = run([uv, "venv", "--quiet", *(["--python", args.python] if args.python else []), venv])
            ok = r.returncode == 0
            r2 = run([uv, "pip", "install", "--quiet", "--python", py, wheel]) if ok else r
        else:
            r = run([args.python or sys.executable, "-m", "venv", venv])
            ok = r.returncode == 0
            r2 = run([py, "-m", "pip", "install", "--quiet", wheel]) if ok else r
        check("clean venv created and wheel installed", ok and r2.returncode == 0,
              f"{time.time() - t0:.1f}s" + ("" if r2.returncode == 0 else " " + r2.stderr[-300:]))
        if not results[-1][1]:
            return 1
        ver = run([py, "-c", "import sys, spectra; print(sys.version.split()[0], spectra.__version__)"])
        check("package imports from site-packages", ver.returncode == 0, ver.stdout.strip())
        listing = run([py, "-m", "pip", "list", "--format=json"]) if not uv else \
            run([uv, "pip", "list", "--python", py, "--format=json"])
        names = {p["name"].lower() for p in json.loads(listing.stdout or "[]")}
        check("environment holds no test/dev tooling", not (names & {"pytest", "ruff", "pip-audit", "prometheus-client"}),
              f"{len(names)} packages")
        spectra_cmd = os.path.join(venv, "bin", "spectra")
        h = run([spectra_cmd, "--help"])
        check("`spectra --help` runs", h.returncode == 0 and "serve" in h.stdout)

        print("== serve")
        port = free_port()
        env = {**os.environ, "SPECTRA_DATA_DIR": data, "SPECTRA_MODEL_PATH": os.path.join(data, "m.joblib"),
               "PYTHONDONTWRITEBYTECODE": "1"}
        env.pop("SPECTRA_ADMIN_PASSWORD", None)             # exercise the generated-password path
        log = open(os.path.join(tmp, "server.log"), "w")
        server = subprocess.Popen([spectra_cmd, "serve", "--port", str(port)], env=env,
                                  stdout=log, stderr=subprocess.STDOUT, cwd=tmp)
        base = f"http://127.0.0.1:{port}"
        up = False
        for _ in range(90):
            if server.poll() is not None:
                break
            try:
                if http(base, "/api/health", timeout=2)[0] == 200:
                    up = True
                    break
            except Exception:  # noqa: BLE001
                time.sleep(1)
        check("server answers /api/health", up, f"port {port}")
        if not up:
            print(open(os.path.join(tmp, "server.log")).read()[-1500:])
            return 1

        st, hd, body = http(base, "/")
        html = body.decode("utf-8", "replace")
        check("GET / serves the dashboard", st == 200 and 'id="root"' in html and hd.get("content-type", "").startswith("text/html"))
        csp = hd.get("content-security-policy", "")
        check("dashboard has CSP, nosniff, frame denial",
              "default-src 'self'" in csp and hd.get("x-content-type-options") == "nosniff"
              and hd.get("x-frame-options") == "DENY", csp[:60])
        asset = re.search(r'src="(/assets/[^"]+\.js)"', html)
        a_st, a_hd, _ = http(base, asset.group(1)) if asset else (0, {}, b"")
        check("hashed JS asset is served and immutable", a_st == 200 and "immutable" in a_hd.get("cache-control", "")
              and "javascript" in a_hd.get("content-type", ""), asset.group(1) if asset else "no asset in index")
        check("client-side route falls back to the index", http(base, "/network")[2].decode().count('id="root"') == 1)
        check("missing asset is a 404", http(base, "/assets/missing.js")[0] == 404)
        check("API needs a session (default-deny, even for unknown paths)",
              http(base, "/api/auth/me")[0] == 401 and http(base, "/api/nothing")[0] == 401)

        print("== sign in with the generated bootstrap password")
        boot = os.path.join(data, "admin_bootstrap.txt")
        check("bootstrap file exists with mode 0600", os.path.isfile(boot) and stat.S_IMODE(os.stat(boot).st_mode) == 0o600)
        password = ""
        for line in open(boot, encoding="utf-8"):
            if line.startswith("password="):
                password = line.split("=", 1)[1].strip()
        st, hd, body = http(base, "/api/auth/login", method="POST", body={"username": "admin", "password": password})
        cookie = (hd.get("set-cookie") or "").split(";")[0]
        check("login succeeds and sets an HttpOnly session cookie",
              st == 200 and cookie.startswith("spectra_session=") and "httponly" in (hd.get("set-cookie") or "").lower())
        st, _, body = http(base, "/api/auth/me", cookie=cookie)
        check("session is accepted (ADMIN)", st == 200 and json.loads(body)["user"]["role"] == "ADMIN")
        st, hd, body = http(base, "/api/nothing", cookie=cookie)
        check("signed in, an unknown API path is a JSON 404 (never the dashboard)",
              st == 404 and hd.get("content-type", "").startswith("application/json") and b"<html" not in body.lower())
        st, hd, body = http(base, "/api/metrics", cookie=cookie)
        check("metrics endpoint answers in Prometheus format",
              st == 200 and "version=0.0.4" in hd.get("content-type", "") and b"spectra_build_info" in body)

        print("== event WebSocket")
        origin = base
        ws_url = f"ws://127.0.0.1:{port}/ws/events"
        anon = run([py, "-c", WS_PROBE, ws_url, origin, ""], timeout=40)
        check("WebSocket is refused without a session", anon.stdout.startswith("REFUSED"), anon.stdout.strip())
        authed = run([py, "-c", WS_PROBE, ws_url, origin, cookie], timeout=40)
        check("WebSocket opens with the session from the page's own origin", authed.stdout.startswith("OPEN"), authed.stdout.strip())
        foreign = run([py, "-c", WS_PROBE, ws_url, "http://evil.example", cookie], timeout=40)
        check("WebSocket from a foreign origin is refused", foreign.stdout.startswith("REFUSED"), foreign.stdout.strip())

        print("== files created on first run")
        keys = [os.path.join(dp, f) for dp, _, fs in os.walk(data) for f in fs if f.endswith(".key")]
        loose = [k for k in keys if stat.S_IMODE(os.stat(k).st_mode) & 0o077]
        check("every key file is mode 0600", not loose, f"{len(keys)} key file(s)")
        check("database created", os.path.isfile(os.path.join(data, "spectra.db")))

        print("== shutdown")
        server.send_signal(signal.SIGINT)
        try:
            code = server.wait(timeout=15)
            check("server exits cleanly on SIGINT", code in (0, 130, -2), f"exit {code}")
        except subprocess.TimeoutExpired:
            server.kill()
            check("server exits cleanly on SIGINT", False, "did not stop in 15 s")
        server = None
        leaked = password and password in open(os.path.join(tmp, "server.log"), errors="replace").read()
        check("server log never contains the generated password", not leaked)
    finally:
        if server is not None:
            server.kill()
        if not args.keep:
            shutil.rmtree(tmp, ignore_errors=True)
        else:
            print(f"kept {tmp}")
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed of {len(results)} checks")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
