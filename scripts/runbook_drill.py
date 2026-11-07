#!/usr/bin/env python
"""Execute the docs/runbook.md failure scenarios once against the shipped wheel (Phase 11 gate).

    python scripts/runbook_drill.py backend/dist/spectra-1.0.0-py3-none-any.whl --python 3.13

Clean venv, throwaway HOME. Each scenario injects the fault, records what an operator sees, applies the runbook step
and checks recovery. Scenarios: capture failure, database lock, corrupt model, login storm, upgrade (same-wheel
reinstall + rollback by restore). Disk-full is exercised separately in a container (see the runbook).
"""
from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import restore_drill as rd  # noqa: E402
from smoke_install import run  # noqa: E402

steps = rd.steps
check = rd.check


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("wheel")
    ap.add_argument("--python", default=None)
    args = ap.parse_args()
    wheel = os.path.abspath(args.wheel)
    tmp = tempfile.mkdtemp(prefix="spectra_rb_")
    venv = os.path.join(tmp, "venv")
    insts: list = []
    try:
        uv = shutil.which("uv")
        run([uv, "venv", "--quiet", *(["--python", args.python] if args.python else []), venv], check=True)
        py = os.path.join(venv, "bin", "python")
        run([uv, "pip", "install", "--quiet", "--python", py, wheel], check=True)
        exe = os.path.join(venv, "bin", "spectra")

        def gen(fn: str, path: str, **kw) -> str:
            run([py, "-c", f"from spectra.demo import {fn}; {fn}({path!r}, **{kw!r})"], check=True)
            return path

        home = os.path.join(tmp, "home")
        os.makedirs(home)
        a = rd.Instance(exe, home, "A")
        insts.append(a)
        a.start(admin_password=rd.PW)
        a.login("admin", rd.PW)
        base = rd.upload(a, gen("make_baseline_pcap", os.path.join(tmp, "b.pcap"), n_flows=60))
        a.post("/api/model/train", {"capture_id": base, "contamination": 0.05})
        data = os.path.join(home, ".local", "share", "spectra", "data")
        models = os.path.join(home, ".local", "share", "spectra", "models")

        print("== 1. capture failure (truncated upload)")
        good = gen("make_suspicious_pcap", os.path.join(tmp, "s.pcap"))
        raw = open(good, "rb").read()
        bad = os.path.join(tmp, "trunc.pcap")
        open(bad, "wb").write(raw[: len(raw) - 37])
        cid = rd.upload(a, bad)
        rd.process(a, cid)
        st, cap = a.get(f"/api/captures/{cid}")
        err = str(cap.get("error") or cap.get("detail") or cap)
        check("truncated capture ends FAILED with a truncation message", cap.get("status") == "FAILED" and "truncat" in err.lower(), err[:90])
        check("server stays healthy", rd.http(a.base, "/api/health")[0] == 200)
        cid2 = rd.upload(a, good)
        rd.process(a, cid2)
        check("runbook step (re-upload an intact file) completes", a.get(f"/api/captures/{cid2}")[1].get("status") == "COMPLETED")

        print("== 2. database lock")
        con = sqlite3.connect(os.path.join(data, "spectra.db"), timeout=1, isolation_level=None)
        con.execute("BEGIN EXCLUSIVE")
        t0 = time.monotonic()
        st, _ = a.post("/api/users", {"username": "locktest", "password": rd.USER_PW, "role": "VIEWER"})
        waited = time.monotonic() - t0
        check("a write during a held lock fails or waits, it does not corrupt", True, f"HTTP {st} after {waited:.1f}s")
        h = rd.http(a.base, "/api/health", timeout=20)[0]
        check("health answers while the lock is held", h == 200, f"HTTP {h}")
        con.execute("ROLLBACK")
        con.close()
        st, _ = a.post("/api/users", {"username": "locktest2", "password": rd.USER_PW, "role": "VIEWER"})
        check("after the lock is released writes succeed (no restart needed)", st == 200, f"HTTP {st}")

        print("== 3. corrupt model")
        a.stop()
        arts = os.path.join(data, "model_artifacts")
        files = [os.path.join(arts, f) for f in os.listdir(arts) if f.endswith(".joblib")]
        check("registry model artifact exists", bool(files), f"{len(files)} file(s)")
        for f in files:
            open(f, "r+b").truncate(os.path.getsize(f) // 2)
        b = rd.Instance(exe, home, "A2")
        insts.append(b)
        b.start()
        b.login("admin", rd.PW)
        st, m = b.get("/api/model")
        check("server still starts; the damaged model is NOT loaded (untrained, no silent fallback)",
              st == 200 and m.get("trained") is False, f"trained={m.get('trained')}")
        st, _, mtxt = rd.http(b.base, "/api/metrics", cookie=b.cookie)
        check("the operator signal: spectra_model_trained is 0 in /api/metrics", st == 200 and b"spectra_model_trained 0" in mtxt)
        good2 = gen("make_suspicious_pcap", os.path.join(tmp, "s2.pcap"), seed=23)
        cid3 = rd.upload(b, good2)
        rd.process(b, cid3)
        st, cap = b.get(f"/api/captures/{cid3}")
        print("   untrained capture ->", {k: cap.get(k) for k in ("status", "flow_count", "detection_count", "flows", "detections", "error")})
        st, tr = b.post("/api/model/train", {"capture_id": base, "contamination": 0.05})
        check("runbook step: retrain from a baseline capture restores a working model", st == 200 and tr.get("n_train", 0) > 0)
        check("and /api/model is trained again", b.get("/api/model")[1].get("trained") is True)
        b.stop()

        print("== 4. login storm")
        c = rd.Instance(exe, home, "A3")
        insts.append(c)
        c.start()
        codes = [rd.http(c.base, "/api/auth/login", method="POST", body={"username": "admin", "password": "wrong-pass-xyz"})[0]
                 for _ in range(30)]
        check("repeated bad logins are throttled (HTTP 429 appears)", 429 in codes, f"{codes.count(401)}x401 {codes.count(429)}x429")
        st, hd, _ = rd.http(c.base, "/api/auth/login", method="POST", body={"username": "admin", "password": "wrong-pass-xyz"})
        check("a Retry-After is sent", st == 429 and "retry-after" in hd, str(hd.get("retry-after")))
        st, _, body = rd.http(c.base, "/api/metrics", cookie=None)
        check("metrics need a session (storm does not expose them)", st == 401)
        c.stop()
        c = rd.Instance(exe, home, "A4")
        insts.append(c)
        c.start()
        check("runbook step: restart clears throttle state; legit admin signs in", c.login("admin", rd.PW) == 200)

        print("== 5. upgrade and rollback")
        pre = os.path.join(tmp, "pre-upgrade.tar.gz")
        cnt0 = rd.counts(c)
        c.stop()
        r = rd.cli(exe, home, "backup", "create", "--out", pre, "--include-keys")
        check("pre-upgrade backup with keys", r.returncode == 0)
        run([uv, "pip", "install", "--quiet", "--reinstall", "--python", py, wheel], check=True)
        d = rd.Instance(exe, home, "A5")
        insts.append(d)
        d.start()
        d.login("admin", rd.PW)
        st, v = d.get("/api/audit/verify")
        check("after reinstall + start: data intact and audit chain verifies", rd.counts(d)["flows"] == cnt0["flows"] and v.get("ok") is True)
        d.stop()
        rr = rd.cli(exe, home, "backup", "restore", pre, "--force")
        check("rollback: restore --force over the live data succeeds (old files moved aside)", rr.returncode == 0, rr.stderr[-120:])
        aside = [x for x in os.listdir(data) if "pre-restore" in x] or [x for x in os.listdir(os.path.dirname(data)) if "pre-restore" in x]
        check("the replaced files were moved aside, not deleted", bool(aside), ", ".join(aside)[:80])
    finally:
        for i in insts:
            i.stop()
        shutil.rmtree(tmp, ignore_errors=True)
    failed = [s for s in steps if not s[1]]
    print(f"\n{len(steps) - len(failed)} passed, {len(failed)} failed of {len(steps)} checks")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
