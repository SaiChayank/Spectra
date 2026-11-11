#!/usr/bin/env python
"""Spectra-Bench: run every step of a frozen preregistration file and write one hashed manifest (docs/35 Phase E0).

    cd backend
    .venv/bin/python scripts/spectra_bench.py --prereg ../ci/prereg/e0.json --bench-data ~/Projects/Spectra_bench_data --out ../docs/evidence/<date>/bench-run

The prereg file is committed before the run; its SHA-256 and the git commit (plus a dirty flag) go in manifest.json, so a result can be
traced to the exact protocol and code.  A failing step stops the run and is recorded; nothing is retried or skipped silently.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def git(*a: str) -> str:
    return subprocess.run(["git", *a], capture_output=True, text=True, cwd=BACKEND).stdout.strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--prereg", required=True)
    ap.add_argument("--bench-data", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", default=None, help="comma-separated step ids")
    a = ap.parse_args()
    prereg = json.load(open(a.prereg))
    want = set(a.only.split(",")) if a.only else None
    os.makedirs(a.out, exist_ok=True)
    manifest = {"prereg": os.path.basename(a.prereg), "prereg_sha256": sha256(a.prereg), "git_commit": git("rev-parse", "HEAD"),
                "git_dirty": bool(git("status", "--porcelain", "--untracked-files=no")), "steps": []}
    rc = 0
    for step in prereg["steps"]:
        if want and step["id"] not in want:
            continue
        args = [x.format(bench=a.bench_data, out=a.out) for x in step["args"]]
        t0 = time.time()
        r = subprocess.run([sys.executable, os.path.join(BACKEND, step["script"]), *args], cwd=BACKEND)
        out = os.path.join(a.out, step["out"])
        ok = r.returncode == 0 and os.path.exists(out)
        manifest["steps"].append({"id": step["id"], "ok": ok, "seconds": round(time.time() - t0, 1),
                                  "output": step["out"], "sha256": sha256(out) if ok else None})
        if not ok:
            rc = 1
            break
    json.dump(manifest, open(os.path.join(a.out, "manifest.json"), "w"), indent=1)
    print(json.dumps(manifest, indent=1))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
