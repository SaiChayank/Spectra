#!/usr/bin/env python
"""Beaconing scorer v2 smoke on the CIC-2018 Bot day - SEEN DATA, dev only, NOT gate evidence (ci/prereg/e21.json).

    cd backend
    python scripts/bench_beacon_v2_cic.py --root ~/Projects/Spectra_bench_data --out <json>

Reads the ten Bot-victim captures with the tolerant reader of bench_rita_cic.py (a cut-off tail is tolerated), keeps only metadata per flow
(src, dst, start_ts, forward bytes, duration, SNI) in a cache next to the feature cache, and feeds each capture's flows in start-time order
to a fresh v2 BeaconTracker (threshold -1 so the final score is always visible; the product threshold 0.8 is applied only when counting).
Pair = (victim host, SNI or destination IP), pairs with >= 20 flows.  Positives = pairs whose destination IPs include 18.219.211.138.
Nothing here changes the scorer; a pair with no verdict (too little evidence) scores 0.
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

import bench_cic2018 as cic  # noqa: E402

from spectra.capture import open_source  # noqa: E402
from spectra.eval.metrics import recall_at_fpr, score_metrics  # noqa: E402
from spectra.modules.corr.beacon import DEFAULT_THRESHOLD, BeaconTracker  # noqa: E402
from spectra.parse.flow import FlowTracker  # noqa: E402

MIN_FLOWS, SEED, BOOT = 20, 1337, 1000


def read_meta(path: str, cache: str) -> tuple[str, list[dict]]:
    """Metadata-only flow records of one capture (no payload bytes are kept), cached as JSON."""
    digest = cic.sha256(path)
    js = os.path.join(cache, digest + ".beacon-v2.json")
    if os.path.isfile(js):
        return digest, json.load(open(js))
    out: list = []
    tr = FlowTracker(idle_timeout=30.0, on_complete=out.append)
    try:
        for pkt in open_source("pcap", path=path).packets():
            tr.process(pkt, float(pkt.time))
    except Exception as exc:  # noqa: BLE001 - only a cut-off tail is tolerated
        if "truncated" not in str(exc):
            raise
    list(tr.flush_all())
    recs = [{k: r[k] for k in ("src", "dst", "start_ts", "last_ts", "duration", "bytes_fwd", "sni")} for r in (f.record() for f in out)]
    json.dump(recs, open(js, "w"))
    return digest, recs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    cic_root = os.path.join(os.path.expanduser(a.root), "cic2018")
    cache = os.path.join(cic_root, ".feature-cache")
    os.makedirs(cache, exist_ok=True)
    fri = sorted(p for p in glob.glob(os.path.join(cic_root, "Friday-02-03-2018__*")) if not p.endswith(".log"))
    victims = [p for p in fri if cic.host_octet(os.path.basename(p)) in cic.VICTIMS and "EC2AMAZ-O4EL3NG" in p]
    hashes, rows = {}, []
    for p in victims:
        name = os.path.basename(p)
        digest, recs = read_meta(p, cache)
        hashes[name] = digest
        tr, counts = BeaconTracker(threshold=-1.0), {}
        last: dict = {}
        for r in sorted(recs, key=lambda r: r["start_ts"]):
            host, ip = r["src"].rsplit(":", 1)[0], r["dst"].rsplit(":", 1)[0]
            key = (host, (r["sni"] or "").lower().rstrip(".") or ip)
            counts[key] = counts.get(key, 0) + 1
            v = tr.observe(r)
            if v is not None:
                last[key] = v
        for key, n in counts.items():
            if n < MIN_FLOWS:
                continue
            v = last.get(key)
            ips = sorted(tr.pairs[key]["ips"])
            rows.append({"capture": name, "pair": list(key), "flows": n, "dst_ips": ips, "positive": cic.C2 in ips,
                         "score": v["score"] if v else 0.0, "components": v["components"] if v else None,
                         "span_h": v["span_h"] if v else None, "verdict": v is not None})
    pos = [r for r in rows if r["positive"]]
    neg = [r for r in rows if not r["positive"]]
    sp, sn = [r["score"] for r in pos], [r["score"] for r in neg]
    m = score_metrics(sp, sn, BOOT, SEED)
    out = {"benchmark": "CIC-2018 Bot day, scorer v2 smoke", "status": "SEEN DATA, dev/smoke only, NOT gate evidence (ci/prereg/e21.json)",
           "git_commit": cic.git("rev-parse", "HEAD"), "threshold": DEFAULT_THRESHOLD, "min_flows": MIN_FLOWS,
           "bootstrap": BOOT, "seed": SEED, "victim_capture_sha256": hashes,
           "pairs": len(rows), "c2_pairs": len(pos), "other_pairs": len(neg),
           "positives_without_verdict": sum(1 for r in pos if not r["verdict"]),
           "negatives_without_verdict": sum(1 for r in neg if not r["verdict"]),
           "negatives_scoring_ge_threshold": sum(1 for x in sn if x >= DEFAULT_THRESHOLD),
           "positives_scoring_ge_threshold": sum(1 for x in sp if x >= DEFAULT_THRESHOLD),
           "roc_auc": m and m["roc_auc"], "roc_auc_ci95": m and m["roc_auc_ci95"],
           "recall_at_zero_false_pairs": (recall_at_fpr(sp, sn, 0.0) or {}).get("recall"),
           "metrics": m, "positives": sorted(pos, key=lambda r: -r["score"]),
           "top_negatives": sorted(neg, key=lambda r: -r["score"])[:10]}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(out, open(a.out, "w"), indent=1)
    print({k: out[k] for k in out if k not in ("positives", "top_negatives", "victim_capture_sha256", "metrics")}, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
