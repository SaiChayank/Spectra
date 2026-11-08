#!/usr/bin/env python
"""Spectra-Bench E0: pair-level beaconing detectors against a jitter sweep (docs/35 §3).

    cd backend
    .venv/bin/python scripts/bench_beacon_sweep.py --data ~/Projects/Spectra_bench_data/datasets --out ../docs/evidence/<date>/bench/beacon-sweep.json

Negatives: every (src, dst, sni) pair with >= MIN_FLOWS flows in the real CTU-Normal captures listed below (benign hosts, real timing).
Positives: SYNTHETIC beacons (eval.pairbench.inject_beacons) at each interval x jitter; 30 flows each, 200 per cell.
Hard negatives: steady gamma-renewal services (cv 0.5) with the beacon's size spread (0.05) or a wide one (0.5).
Both are pair-level; recall is at a fixed benign-pair false-alert rate.  Synthetic positives are idealised, so a miss here is a real
miss, a hit is an upper bound.  Thresholds are not tuned: nothing is fitted to this data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND)

from spectra.eval.pairbench import SCORERS, evaluate, inject_beacons, pair_series, steady_negatives  # noqa: E402
from spectra.tools import collect_flows  # noqa: E402

BENIGN = ["ctu_normal--2017-04-28_normal.pcap", "ctu_normal--2017-05-01_normal.pcap"]
INTERVALS = [30, 300, 3600]
JITTERS = [0.0, 0.1, 0.25, 0.5, 0.75, 0.9]
MIN_FLOWS, N_POS, BOOT, SEED = 10, 200, 500, 1337


def sha256(p: str) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    benign, files = {}, {}
    for name in BENIGN:
        path = os.path.join(a.data, name)
        files[name] = sha256(path)
        flows = collect_flows(path, max_flows=3_000_000)
        for k, v in pair_series(flows, MIN_FLOWS).items():
            benign[(name,) + k] = v  # same host pair on two days stays two pairs
        print(f"{name}: {len(flows)} flows, {len(benign)} pairs so far", file=sys.stderr)
    cells = []
    for interval in INTERVALS:
        for jitter in JITTERS:
            pos = inject_beacons(N_POS, interval_s=interval, jitter=jitter, seed=SEED)
            res = evaluate(benign, pos, bootstrap=BOOT, seed=SEED)
            hard = {}
            for tag, cv in (("steady_size_cv_0.05", 0.05), ("steady_size_cv_0.5", 0.5)):
                neg = {("steady", i): v for i, v in enumerate(steady_negatives(N_POS, interval_s=interval, size_cv=cv))}
                hard[tag] = evaluate(neg, pos, bootstrap=BOOT, seed=SEED)
            cells.append({"interval_s": interval, "jitter": jitter, "metrics": res, "hard_negatives": hard})
            print(interval, jitter, {k: round(v["roc_auc"], 2) for k, v in res.items()},
                  {t: {k: round(v["roc_auc"], 2) for k, v in h.items()} for t, h in hard.items()}, file=sys.stderr)
    out = {"benchmark": "beacon-sweep (synthetic positives, real benign pairs)", "min_flows": MIN_FLOWS, "n_benign_pairs": len(benign),
           "n_pos_per_cell": N_POS, "scorers": list(SCORERS), "inputs_sha256": files,
           "git_commit": subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=BACKEND).stdout.strip(),
           "python": platform.python_version(), "cells": cells}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(out, open(a.out, "w"), indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
