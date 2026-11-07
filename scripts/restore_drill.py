#!/usr/bin/env python
"""Disaster-recovery drill against the shipped wheel (Phase 11 gate).

    python scripts/restore_drill.py backend/dist/spectra-1.0.0-py3-none-any.whl --python 3.13

Everything runs through the installed product (CLI + HTTP), in a clean virtualenv, with a
throwaway HOME - nothing of the repository's own data is touched:

 1. start instance A, load it (train on the demo baseline, process a capture, audit checkpoint,
    a user with a TOTP second factor);
 2. take two backups of the *running* instance: with keys and without;
 3. keep working (more data - this is what a disaster loses: the RPO);
 4. disaster: SIGKILL the server and destroy its whole data directory;
 5. recover (timed - the RTO): ``spectra backup restore`` into a fresh HOME, start, wait healthy;
 6. verify what came back: rows, audit chain, old checkpoint, model, admin login, the TOTP user;
 7. repeat the recovery from the key-less archive and show what that costs (a new audit key
    epoch, the TOTP user locked out until an admin/CLI reset) and that the reset works.

Honest scope: tiny scale (the demo captures), one machine, a clean shutdown of nothing - the
timings say how long the steps take *here*, not at production volume. "RTO" below covers
restore + start + first healthy answer; it excludes noticing the failure and fetching the archive.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from smoke_install import free_port, http, run  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PW = "Drill-" + hashlib.sha256(os.urandom(16)).hexdigest()[:20]       # throwaway, never printed
USER_PW = "Drill-user-" + hashlib.sha256(os.urandom(16)).hexdigest()[:16]
steps: list[tuple[str, bool, str]] = []
timings: dict[str, float] = {}


def check(name: str, ok: bool, detail: str = "") -> bool:
    steps.append((name, bool(ok), detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  - {detail}" if detail else ""), flush=True)
    return bool(ok)


def hotp(secret: bytes, counter: int) -> str:
    mac = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return str((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 10**6).zfill(6)


def b32decode(text: str) -> bytes:
    import base64
    return base64.b32decode(text + "=" * (-len(text) % 8))


class Instance:
    """One ``spectra serve`` process with its own HOME."""

    def __init__(self, exe: str, home: str, name: str) -> None:
        self.exe, self.home, self.name = exe, home, name
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.proc: subprocess.Popen | None = None
        self.cookie: str | None = None

    @property
    def env(self) -> dict:
        env = {k: v for k, v in os.environ.items() if not k.startswith("SPECTRA_") and k not in ("HOME", "XDG_DATA_HOME")}
        env.update(HOME=self.home, PYTHONDONTWRITEBYTECODE="1")
        return env

    def start(self, admin_password: str | None = None) -> float:
        env = self.env
        if admin_password:
            env["SPECTRA_ADMIN_PASSWORD"] = admin_password
        t0 = time.monotonic()
        log = open(os.path.join(self.home, f"{self.name}.log"), "w")  # noqa: SIM115 - lives with the process
        self.proc = subprocess.Popen([self.exe, "serve", "--port", str(self.port)], env=env, stdout=log,
                                     stderr=subprocess.STDOUT, cwd=self.home)
        for _ in range(120):
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.name} exited at start-up (see {self.name}.log)")
            try:
                if http(self.base, "/api/health", timeout=2)[0] == 200:
                    return time.monotonic() - t0
            except Exception:  # noqa: BLE001
                time.sleep(0.5)
        raise RuntimeError(f"{self.name} never became healthy")

    def kill(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGKILL)
            self.proc.wait()

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def login(self, user: str, password: str, code: str | None = None) -> int:
        body = {"username": user, "password": password, **({"totp_code": code} if code else {})}
        st, hd, _ = http(self.base, "/api/auth/login", method="POST", body=body)
        if st == 200:
            self.cookie = (hd.get("set-cookie") or "").split(";")[0]
        return st

    def get(self, path: str):
        st, _, body = http(self.base, path, cookie=self.cookie)
        try:
            return st, json.loads(body)
        except ValueError:
            return st, {}

    def post(self, path: str, body: dict | None = None):
        st, _, raw = http(self.base, path, method="POST", body=body or {}, cookie=self.cookie)
        try:
            return st, json.loads(raw)
        except ValueError:
            return st, {}


def upload(inst: Instance, path: str) -> int:
    boundary = "----DrillBoundary"
    with open(path, "rb") as fh:
        payload = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{os.path.basename(path)}"\r\n'
                   f"Content-Type: application/octet-stream\r\n\r\n").encode() + fh.read() + f"\r\n--{boundary}--\r\n".encode()
    import urllib.request
    req = urllib.request.Request(inst.base + "/api/captures", data=payload, method="POST",
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "Cookie": inst.cookie})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())["capture_id"]


def process(inst: Instance, capture_id: int) -> None:
    inst.post(f"/api/captures/{capture_id}/process")
    for _ in range(120):
        if inst.get(f"/api/captures/{capture_id}")[1].get("status") in ("COMPLETED", "FAILED"):
            return
        time.sleep(0.5)


def counts(inst: Instance) -> dict:
    st, flows = inst.get("/api/history/flows?limit=1")
    st2, audit = inst.get("/api/audit/head")
    return {"flows": flows.get("count"), "audit_head_seq": audit.get("seq")}


def cli(exe: str, home: str, *args: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("SPECTRA_") and k not in ("HOME", "XDG_DATA_HOME")}
    env.update(HOME=home, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([exe, *args], env=env, capture_output=True, text=True, cwd=home, check=False)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("wheel")
    ap.add_argument("--python", default=None)
    ap.add_argument("--json", help="write the measurements here")
    args = ap.parse_args()
    wheel = os.path.abspath(args.wheel)
    tmp = tempfile.mkdtemp(prefix="spectra_drill_")
    venv = os.path.join(tmp, "venv")
    insts: list[Instance] = []
    try:
        uv = shutil.which("uv")
        assert uv, "this drill uses uv to create the clean environment"
        run([uv, "venv", "--quiet", *(["--python", args.python] if args.python else []), venv], check=True)
        run([uv, "pip", "install", "--quiet", "--python", os.path.join(venv, "bin", "python"), wheel], check=True)
        exe = os.path.join(venv, "bin", "spectra")
        py = os.path.join(venv, "bin", "python")
        ver = run([py, "-c", "import sys, spectra; print(sys.version.split()[0], spectra.__version__)"]).stdout.strip()
        print(f"== drill on Spectra (python/version): {ver}; clean venv from {os.path.basename(wheel)}")

        def gen(fn: str, path: str, **kw) -> str:          # synthetic traffic, made by the installed package
            code = f"from spectra.demo import {fn}; {fn}({path!r}, **{kw!r})"
            run([py, "-c", code], check=True)
            return path

        def make_baseline_pcap(path: str, **kw) -> str:
            return gen("make_baseline_pcap", path, **kw)

        def make_suspicious_pcap(path: str, **kw) -> str:
            return gen("make_suspicious_pcap", path, **kw)

        # 1. instance A ------------------------------------------------------------------------
        print("== 1. instance A")
        home_a = os.path.join(tmp, "homeA")
        os.makedirs(home_a)
        a = Instance(exe, home_a, "A")
        insts.append(a)
        a.start(admin_password=PW)
        check("A starts", a.login("admin", PW) == 200)
        base_id = upload(a, make_baseline_pcap(os.path.join(tmp, "b.pcap"), n_flows=80))
        st, tr = a.post("/api/model/train", {"capture_id": base_id, "contamination": 0.05})
        check("A trains a model", st == 200 and tr.get("n_train", 0) > 0, f"n_train {tr.get('n_train')}")
        s1 = upload(a, make_suspicious_pcap(os.path.join(tmp, "s1.pcap"), seed=11))
        process(a, s1)
        st, ck = a.post("/api/audit/checkpoint")
        check("A has an audit checkpoint", st == 200 and ck.get("seq"), f"seq {ck.get('seq')}")
        st, _ = a.post("/api/users", {"username": "carol", "password": USER_PW, "role": "ANALYST"})
        carol = Instance.__new__(Instance)
        carol.__dict__.update(a.__dict__)
        carol.cookie = None
        carol.login("carol", USER_PW)
        st, setup = carol.post("/api/auth/totp/setup", {"password": USER_PW})
        secret = b32decode(setup["secret"])
        st, en = carol.post("/api/auth/totp/enable", {"code": hotp(secret, int(time.time() // 30))})
        check("a user (carol) enrolled a TOTP second factor", st == 200 and len(en.get("recovery_codes", [])) == 8)
        at_backup = counts(a)
        a.get("/api/stats")

        # 2. two backups of the RUNNING instance ----------------------------------------------------
        print("== 2. backups of the running instance")
        arch_keys = os.path.join(tmp, "with-keys.tar.gz")
        arch_nokeys = os.path.join(tmp, "no-keys.tar.gz")
        t0 = time.monotonic()
        r1 = cli(exe, home_a, "backup", "create", "--out", arch_keys, "--include-keys", "--json")
        timings["backup_with_keys_s"] = round(time.monotonic() - t0, 3)
        t0 = time.monotonic()
        r2 = cli(exe, home_a, "backup", "create", "--out", arch_nokeys, "--json")
        timings["backup_without_keys_s"] = round(time.monotonic() - t0, 3)
        check("backup (with keys) of the running server", r1.returncode == 0, f"{timings['backup_with_keys_s']} s")
        check("backup (without keys) of the running server", r2.returncode == 0, f"{timings['backup_without_keys_s']} s")
        manifest = json.loads(r1.stdout)["manifest"] if r1.returncode == 0 else {}
        check("both archives verify", cli(exe, home_a, "backup", "verify", arch_keys).returncode == 0
              and cli(exe, home_a, "backup", "verify", arch_nokeys).returncode == 0)
        backup_done = time.time()
        timings["archive_with_keys_bytes"] = os.path.getsize(arch_keys)
        timings["archive_without_keys_bytes"] = os.path.getsize(arch_nokeys)
        timings["db_rows_at_backup"] = manifest.get("db", {}).get("rows", {})

        # 3. keep working: this is what a disaster costs (the RPO) -------------------------------------
        print("== 3. work continues after the backup")
        time.sleep(2)
        s2 = upload(a, make_suspicious_pcap(os.path.join(tmp, "s2.pcap"), seed=12))
        process(a, s2)
        before_disaster = counts(a)
        check("more data was written after the backup",
              (before_disaster["flows"] or 0) > (at_backup["flows"] or 0),
              f"flows {at_backup['flows']} -> {before_disaster['flows']}")

        # 4. disaster -------------------------------------------------------------------------------------
        print("== 4. disaster: SIGKILL + the whole data directory destroyed")
        a.kill()
        disaster_at = time.time()
        shutil.rmtree(home_a)
        check("instance A and its data are gone", not os.path.exists(home_a))
        timings["rpo_observed_s"] = round(disaster_at - backup_done, 1)

        # 5+6. recover from the archive WITH keys (timed) -----------------------------------------------------
        print("== 5. recovery from the archive with keys (timed)")
        home_b = os.path.join(tmp, "homeB")
        os.makedirs(home_b)
        t_rec = time.monotonic()
        rr = cli(exe, home_b, "backup", "restore", arch_keys, "--json")
        timings["restore_with_keys_s"] = round(time.monotonic() - t_rec, 3)
        check("restore into an empty home succeeds", rr.returncode == 0, f"{timings['restore_with_keys_s']} s")
        b = Instance(exe, home_b, "B")
        insts.append(b)
        b.start()                                              # no SPECTRA_ADMIN_PASSWORD: the restored admin must work
        timings["rto_with_keys_s"] = round(time.monotonic() - t_rec, 3)
        check("server is healthy again (RTO = restore + start + first healthy answer)", True,
              f"{timings['rto_with_keys_s']} s")
        print("== 6. what came back")
        check("the admin's password still works (users restored)", b.login("admin", PW) == 200)
        now = counts(b)
        check("flows equal the state at backup time, not at disaster time",
              now["flows"] == at_backup["flows"] and now["flows"] < before_disaster["flows"],
              f"restored {now['flows']}, at backup {at_backup['flows']}, at disaster {before_disaster['flows']}")
        lost = before_disaster["flows"] - now["flows"]
        timings["flows_lost_since_backup"] = lost
        st, v = b.get("/api/audit/verify")
        check("audit chain verifies", st == 200 and v.get("ok") is True, f"{v.get('entries')} entries, epoch {v.get('epoch')}")
        entries = b.get("/api/audit/entries?kind=backup.restore&limit=5")[1].get("items", [])
        check("the restore itself is recorded in the audit chain", len(entries) == 1 and entries[0]["actor"] == "restore")
        st, ckv = b.get(f"/api/audit/checkpoint/verify?seq={ck['seq']}")
        check("the pre-disaster checkpoint still verifies", st == 200 and ckv.get("ok") is True)
        st, model = b.get("/api/model")
        check("the trained model came back", st == 200 and model.get("trained") is True, f"n_train {model.get('n_train')}")
        carol_b = Instance.__new__(Instance)
        carol_b.__dict__.update(b.__dict__)
        carol_b.cookie = None
        check("the TOTP user is still challenged for a code", carol_b.login("carol", USER_PW) == 401)
        check("and accepts a valid code (the key was restored)",
              carol_b.login("carol", USER_PW, hotp(secret, int(time.time() // 30) + 1)) == 200)
        b.stop()

        # 7. recovery from the key-less archive -----------------------------------------------------------
        print("== 7. recovery from the archive WITHOUT keys")
        home_c = os.path.join(tmp, "homeC")
        os.makedirs(home_c)
        t_rec = time.monotonic()
        rr = cli(exe, home_c, "backup", "restore", arch_nokeys, "--json")
        timings["restore_without_keys_s"] = round(time.monotonic() - t_rec, 3)
        check("restore without keys succeeds", rr.returncode == 0)
        c = Instance(exe, home_c, "C")
        insts.append(c)
        c.start()
        timings["rto_without_keys_s"] = round(time.monotonic() - t_rec, 3)
        check("server healthy again", True, f"{timings['rto_without_keys_s']} s")
        check("admin can sign in", c.login("admin", PW) == 200)
        st, v = c.get("/api/audit/verify")
        check("a new audit key epoch started and the chain still verifies",
              st == 200 and v.get("ok") is True and (v.get("epoch") or 0) >= 2, f"epoch {v.get('epoch')}")
        st, ckv = c.get(f"/api/audit/checkpoint/verify?seq={ck['seq']}")
        check("the old checkpoint still verifies (from the public keys in the database)", st == 200 and ckv.get("ok") is True)
        carol_c = Instance.__new__(Instance)
        carol_c.__dict__.update(c.__dict__)
        carol_c.cookie = None
        code = hotp(secret, int(time.time() // 30) + 2)
        check("without totp.key the TOTP user cannot sign in (documented cost)", carol_c.login("carol", USER_PW, code) == 401)
        c.stop()
        rst = cli(exe, home_c, "auth", "totp-reset", "carol")
        check("`spectra auth totp-reset` clears it", rst.returncode == 0)
        c2 = Instance(exe, home_c, "C2")
        insts.append(c2)
        c2.start()
        carol_c2 = Instance.__new__(Instance)
        carol_c2.__dict__.update(c2.__dict__)
        carol_c2.cookie = None
        check("after the reset the user signs in with the password", carol_c2.login("carol", USER_PW) == 200)
        c2.stop()
        for inst in insts:
            leaked = PW in open(os.path.join(inst.home, f"{inst.name}.log"), errors="replace").read() \
                if os.path.exists(os.path.join(inst.home, f"{inst.name}.log")) else False
            if leaked:
                check("no server log contains the admin password", False, inst.name)
        check("no server log contains the admin password", True)
    finally:
        for inst in insts:
            inst.stop()
        shutil.rmtree(tmp, ignore_errors=True)
    failed = [s for s in steps if not s[1]]
    print("\n== measurements (tiny scale, one machine: how long the steps take HERE)")
    for k, v in timings.items():
        print(f"   {k}: {v}")
    print(f"\n{len(steps) - len(failed)} passed, {len(failed)} failed of {len(steps)} checks")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"python": ver, "timings": timings, "steps": [{"name": n, "ok": ok, "detail": d} for n, ok, d in steps]},
                      fh, indent=2)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
