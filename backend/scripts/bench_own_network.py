#!/usr/bin/env python
"""Own-network baseline check (docs/human-benchmark-tasks.md, task 12): how much does a model trained on the first part of
YOUR benign capture flag in the rest of it?  No labels are needed or used.

    cd backend
    python scripts/bench_own_network.py --pcap-dir <dir with the hourly pcaps> --train-hours 24 --out report.json

Reads every *.pcap in time order (a file cut off mid-record, as tcpdump leaves it when stopped, is read up to the cut).
Trains on all flows that START in the first --train-hours hours and reports, for each later hour, the number of flows and the
flag rate at the model's default threshold, plus the drift (PSI) of each later day against the training slice.  A flag rate far
above the training contamination on traffic that is all benign means the baseline does not cover your network: retrain on more
days, or accept alerts as "unusual for this network", not "malicious".  Metadata only: nothing is stored but counts and rates.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spectra.capture import open_source  # noqa: E402
from spectra.features.extractor import flows_to_matrix  # noqa: E402
from spectra.ml.model import SpectraDetector  # noqa: E402
from spectra.parse.flow import FlowTracker  # noqa: E402


def read_flows(path: str) -> tuple[list, bool]:
    flows: list = []
    tracker = FlowTracker(idle_timeout=30.0, on_complete=flows.append)
    cut = False
    try:
        for pkt in open_source("pcap", path=path).packets():
            tracker.process(pkt, float(pkt.time))
    except Exception as exc:  # noqa: BLE001 - only a cut-off tail is tolerated
        if "truncated" not in str(exc):
            raise
        cut = True
    list(tracker.flush_all())
    return flows, cut


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap-dir", required=True)
    ap.add_argument("--train-hours", type=float, default=24.0)
    ap.add_argument("--contamination", type=float, default=0.02)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    files = sorted(glob.glob(os.path.join(a.pcap_dir, "*.pcap")))
    if not files:
        print("no *.pcap files found", file=sys.stderr)
        return 2
    starts, X, cuts = [], [], 0
    for p in files:
        fl, cut = read_flows(p)
        cuts += cut
        if fl:
            starts += [f.start_ts for f in fl]
            X.append(flows_to_matrix(fl))
        print(f"  {os.path.basename(p)}: {len(fl)} flows{' (cut off)' if cut else ''}", flush=True)
    if not X:
        print("no flows parsed", file=sys.stderr)
        return 2
    X, starts = np.vstack(X), np.array(starts)
    t0 = starts.min()
    hours_f = (starts - t0) / 3600.0
    hour = np.floor(hours_f).astype(int)
    train = hours_f < a.train_hours
    if train.sum() < 200 or (~train).sum() < 200:
        print(f"need >= 200 flows on each side of the split (train {int(train.sum())}, test {int((~train).sum())})", file=sys.stderr)
        return 2
    det = SpectraDetector(contamination=a.contamination, random_state=42)
    fit = det.fit(X[train])
    flags = np.asarray(det.predict(X[~train])).astype(bool)
    rows = []
    for h in sorted(set(hour[~train].tolist())):
        m = hour[~train] == h
        rows.append({"hour_since_start": int(h), "flows": int(m.sum()), "flag_rate": round(float(flags[m].mean()), 4)})
    days = sorted({int(h // 24) for h in hour[~train]})
    drift = {}
    for d in days:
        m = (hour // 24) == d
        if m.sum() >= 200:
            psi = det.psi(X[m])
            drift[f"day_{d}"] = {"flows": int(m.sum()), "psi": psi.get("psi"), "level": psi.get("level")}
    rep = {"files": len(files), "files_cut_off": cuts, "flows_total": int(len(X)), "train_hours": a.train_hours,
           "train_flows": int(train.sum()), "test_flows": int((~train).sum()), "model_fit": fit,
           "overall_flag_rate_on_test": round(float(flags.mean()), 4), "expected_if_baseline_matched": a.contamination,
           "by_hour": rows, "drift_by_day": drift,
           "reading": "All traffic is assumed benign (your own network). A flag rate well above the expected value means "
                      "the training slice does not cover your network's normal behaviour."}
    json.dump(rep, open(a.out, "w", encoding="utf-8"), indent=2)
    print(f"flag rate on the held-out part: {rep['overall_flag_rate_on_test']:.2%} (expected about {a.contamination:.0%}); wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
