#!/usr/bin/env python
"""Frozen beacon scorer v2a1 on the owner's own benign capture (docs/human-benchmark-tasks.md task 12): false pairs per day.

    cd backend
    .venv/bin/python scripts/bench_beacon_v2_own.py --pcap-dir <hourly pcaps> --out <counts json> --detail <private json>

All traffic is assumed benign, so every pair scoring >= 0.8 (with >= 20 flows) is a false alert.  Each 24 h day is scored
with its own tracker (internal = RFC 1918), as the set A/B scripts do per capture.  --out holds counts only and may be
committed; --detail lists the alerting destinations (server names) and must stay private: it reveals what the network talks to.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import bench_beacon_v2_cic as cicv2  # noqa: E402
import bench_beacon_v2_setb as setb  # noqa: E402

setb.INTERNAL = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
MIN_FLOWS, THR = 20, 0.8


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--detail", required=True)
    ap.add_argument("--cache", default=os.path.expanduser("~/Projects/Spectra_bench_data/.beacon-v2-cache"))
    a = ap.parse_args()
    os.makedirs(a.cache, exist_ok=True)
    files = sorted(glob.glob(os.path.join(a.pcap_dir, "*.pcap")))
    days, detail = [], []
    for d in range(0, len(files), 24):
        recs = []
        for f in files[d:d + 24]:
            recs += cicv2.read_meta(f, a.cache)[1]
        rows, info = setb.spectra_pairs(recs)
        elig = [r for r in rows if r["flows"] >= MIN_FLOWS]
        alert = sorted((r for r in elig if r["score"] >= THR), key=lambda r: -r["score"])
        days.append({"day": d // 24 + 1, "files": len(files[d:d + 24]), "flow_records": info["flow_records"],
                     "pairs_tracked": info["tracked_pairs"], "pairs_ge_20_flows": len(elig),
                     "pairs_with_verdict": sum(r["verdict"] for r in elig), "false_pairs_ge_0_8": len(alert)})
        detail.append({"day": d // 24 + 1, "alerting": [{"dst": r["pair"][1], "flows": r["flows"], "score": r["score"],
                                                           "components": r["components"]} for r in alert]})
        print(days[-1], file=sys.stderr)
    persistent = set.intersection(*[{x["dst"] for x in dd["alerting"]} for dd in detail]) if detail else set()
    out = {"benchmark": "beacon v2a1 (frozen) on own benign capture: false pairs per day", "threshold": THR, "min_flows": MIN_FLOWS,
           "internal_nets": setb.INTERNAL, "days": days, "alerting_on_every_day": len(persistent),
           "git_commit": cicv2.cic.git("rev-parse", "HEAD"), "note": "counts only; destinations are in the private detail file"}
    json.dump(out, open(a.out, "w"), indent=1)
    json.dump({"alerting_on_every_day": sorted(persistent), "days": detail}, open(a.detail, "w"), indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
