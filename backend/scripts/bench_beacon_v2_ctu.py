#!/usr/bin/env python
"""Held-out set A: beaconing scorer v2a1 vs real RITA v5.1.2 on CTU-13 (C2 pairs) and CTU-Normal 2017 (benign pairs), ci/prereg/e21.json.

    cd backend
    python scripts/bench_beacon_v2_ctu.py --root ~/Projects/Spectra_bench_data --out <json>

* Spectra: flow metadata (no payload) of every capture, one BeaconTracker per capture, flows in start-time order, threshold -1 so the final score
  is visible; the allow-list is EMPTY.  Inside network: 10/8, 172.16/12, 192.168/16, fc00::/7 + 147.32.0.0/16 for the CTU-13 captures.
* RITA: Zeek logs in <root>/zeek/out imported per capture (as bench_rita_cic.py does); score = beacon_score of threat_mixtape, SNI-based rows
  (blank dst, addresses in server_ips) expanded to every address behind them.
* Pair set and join: the evaluated pairs are SPECTRA's pairs (internal host, SNI-or-destination-IP) with >= 20 flows.  Spectra's SNI pair maps
  to the set of destination IPs it saw; its RITA score is the maximum RITA score over (host, ip) for those IPs; its label is positive when any
  of those IPs is a C2 address of that host in the dataset's own labels.  A pair with no verdict / absent from RITA scores 0 (a miss).
* Labels: Stratosphere *.binetflow.2format files (text only, parsed with csv): a flow whose label contains "CC" gives the pair (the endpoint inside
  147.32.0.0/16 -> the other endpoint); in scenario 3 the record points server -> bot, so the label's own direction is not used.  Gate: positives vs CTU-Normal pairs.  Botnet non-C2 pairs are reported outside it.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import bench_beacon_v2_cic as cicv2  # noqa: E402
import bench_rita_cic as rc  # noqa: E402

from spectra.eval.metrics import recall_at_fpr, score_metrics  # noqa: E402
from spectra.modules.corr.beacon import DEFAULT_THRESHOLD, INTERNAL_NETS, BeaconTracker  # noqa: E402

MIN_FLOWS, SEED, BOOT = 20, 1337, 1000
INSIDE = ipaddress.ip_network("147.32.0.0/16")
RITA_BASE, RITA_LOW = 0.5, 0.7        # scoring.beacon.score_thresholds base 50 / low 70 in RITA's config.hjson (our config is the default)
BOTNETS = {   # pcap -> (label file, scenario note)
    "ctu13--botnet-capture-20110810-neris.pcap": ("capture20110810.binetflow.2format", "CTU-13 scenario 1, Botnet-42"),
    "ctu13--botnet-capture-20110811-neris.pcap": ("capture20110811.binetflow.2format", "CTU-13 scenario 2, Botnet-43"),
    "ctu_botnet--botnet-capture-20110812-rbot.pcap": ("capture20110812.binetflow.2format", "CTU-13 scenario 3, Botnet-44"),
    "ctu_botnet--botnet-capture-20110815-fast-flux.pcap": ("capture20110815-2.binetflow.2format", "CTU-13 scenario 5, Botnet-46"),
}
NORMALS = sorted(f"ctu_normal--{n}.pcap" for n in
                 ("2017-04-18_win-normal", "2017-04-19_win-normal", "2017-04-28_normal", "2017-04-30_win-normal",
                  "2017-05-01_normal", "2017-05-02_kali-normal"))


def sha(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def c2_pairs(path: str) -> tuple[dict, dict]:
    """(host -> set of C2 addresses, label counts) from a binetflow label file; text only."""
    out: dict[str, set] = {}
    counts = {"rows": 0, "cc_rows": 0}
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        rd = csv.reader(fh)
        head = next(rd)
        i_s, i_d, i_l = head.index("SrcAddr"), head.index("DstAddr"), head.index("Label")
        for row in rd:
            counts["rows"] += 1
            lab = row[i_l]
            if "CC" not in lab:
                continue
            counts["cc_rows"] += 1
            ends = [ip for ip in (row[i_s], row[i_d]) if ipaddress.ip_address(ip) in INSIDE]
            if len(ends) != 1:                       # not exactly one end inside the capture network: cannot orient, counted
                counts["cc_rows_unoriented"] = counts.get("cc_rows_unoriented", 0) + 1
                continue
            other = row[i_d] if ends[0] == row[i_s] else row[i_s]
            out.setdefault(ends[0], set()).add(other)      # (infected inside host -> C2), whichever way the flow record points
    return out, counts


def spectra_pairs(recs: list[dict], nets: list[str]) -> tuple[list[dict], int]:
    tr, counts, last = BeaconTracker(threshold=-1.0, internal_nets=nets), {}, {}
    for r in sorted(recs, key=lambda r: r["start_ts"]):
        host, ip = r["src"].rsplit(":", 1)[0], r["dst"].rsplit(":", 1)[0]
        key = (host, (r["sni"] or "").lower().rstrip(".") or ip)
        v = tr.observe(r)
        if key not in tr.pairs:
            continue
        counts[key] = counts.get(key, 0) + 1
        if v is not None:
            last[key] = v
    rows = []
    for key, n in counts.items():
        if n < MIN_FLOWS:
            continue
        v = last.get(key)
        rows.append({"pair": list(key), "flows": n, "dst_ips": sorted(tr.pairs[key]["ips"]),
                     "score": v["score"] if v else 0.0, "components": v["components"] if v else None,
                     "span_h": v["span_h"] if v else None, "verdict": v is not None})
    return rows, len(counts)


def rita_scores(root: str, name: str) -> tuple[dict, dict]:
    rita = os.path.join(root, "tools", "rita")
    db = "ctu_" + "".join(c if c.isalnum() else "_" for c in name.removesuffix(".pcap")).lower()
    rc.rita_import(rita, os.path.join(root, "zeek", "out", name.removesuffix(".pcap")), db)
    info = {"conn_rows": int(rc.ch(rita, f"select count() from {db}.conn")[0][0])}
    scores: dict = {}
    q = (f"select src, if(dst = toIPv6('::'), arrayJoin(server_ips), dst) as d, max(beacon_score) "
         f"from {db}.threat_mixtape group by src, d")
    for src, dst, s in rc.ch(rita, q):
        k = (rc.ip(src), rc.ip(dst))
        scores[k] = max(scores.get(k, 0.0), float(s))
    info["scored_pairs"] = len(scores)
    return scores, info


def fixed(pos, neg, t):
    return {"threshold": t, "recall": sum(1 for x in pos if x >= t) / len(pos) if pos else None,
            "false_pairs": sum(1 for x in neg if x >= t), "of_negatives": len(neg)}


def per_tool(pos, neg, thresholds):
    m = score_metrics(pos, neg, BOOT, SEED)
    op = recall_at_fpr(pos, neg, 0.001)
    return {"metrics": m, "gate_operating_point": op, "fixed": [fixed(pos, neg, t) for t in thresholds]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    root = os.path.expanduser(a.root)
    ds, lab_dir = os.path.join(root, "datasets"), os.path.join(root, "datasets", "labels")
    cache = os.path.join(root, ".beacon-v2-cache")
    os.makedirs(cache, exist_ok=True)
    manifest = {e["filename"]: e["sha256"] for e in json.load(open(os.path.join(ds, "manifest.json")))["entries"]}
    rows, caps, rita_info, label_info, hashes = [], {}, {}, {}, {}
    cc = {}
    for pcap, (lf, _note) in BOTNETS.items():
        label_info[lf] = {"sha256": sha(os.path.join(lab_dir, lf)), "size": os.path.getsize(os.path.join(lab_dir, lf))}
        cc[pcap], label_info[lf]["counts"] = c2_pairs(os.path.join(lab_dir, lf))
        label_info[lf]["c2_hosts"] = {h: sorted(v) for h, v in cc[pcap].items()}
    for group, files in (("botnet", list(BOTNETS)), ("normal", NORMALS)):
        for pcap in files:
            digest, recs = cicv2.read_meta(os.path.join(ds, pcap), cache)
            if digest != manifest[pcap]:
                raise SystemExit(f"SHA-256 mismatch for {pcap}")
            hashes[pcap] = digest
            nets = list(INTERNAL_NETS) + (["147.32.0.0/16"] if group == "botnet" else [])
            prs, tracked = spectra_pairs(recs, nets)
            rs, rita_info[pcap] = rita_scores(root, pcap)
            for r in prs:
                host = r["pair"][0]
                r["capture"], r["group"] = pcap, group
                r["c2"] = group == "botnet" and any(i in cc[pcap].get(host, ()) for i in r["dst_ips"])
                r["rita"] = max([rs.get((host, i), 0.0) for i in r["dst_ips"]] or [0.0])
            rows += prs
            caps[pcap] = {"group": group, "flow_records": len(recs), "tracked_pairs": tracked, "pairs_ge_20_flows": len(prs),
                          "c2_pairs": sum(1 for r in prs if r["c2"]), "no_verdict": sum(1 for r in prs if not r["verdict"])}
    pos = [r for r in rows if r["c2"]]
    neg = [r for r in rows if r["group"] == "normal"]
    bnc = [r for r in rows if r["group"] == "botnet" and not r["c2"]]
    res = {}
    for tool, key, th in (("spectra_v2a1", "score", [DEFAULT_THRESHOLD]), ("rita_v5.1.2", "rita", [RITA_BASE, RITA_LOW])):
        res[tool] = per_tool([r[key] for r in pos], [r[key] for r in neg], th)
        res[tool]["botnet_non_c2_pairs"] = {"n": len(bnc), **{f"scoring_ge_{t}": sum(1 for r in bnc if r[key] >= t) for t in th}}
    sp, ri = res["spectra_v2a1"], res["rita_v5.1.2"]
    rec = (sp["metrics"] or {}).get("recall_at_fpr_0_1pct")
    ci = (sp["metrics"] or {}).get("recall_at_fpr_0_1pct_ci95")
    rrec = (ri["metrics"] or {}).get("recall_at_fpr_0_1pct")
    gate = None
    if rec is not None:
        gate = {"recall_at_gate_operating_point": rec, "bootstrap_lower_bound": ci[0] if ci else None, "rita_recall_same_rule": rrec,
                "n_pos": len(pos), "n_neg": len(neg), "n_neg_lt_1000_so_zero_false_pairs_required": len(neg) < 1000,
                "checks": {"recall_ge_0.8": rec >= 0.8, "lower_bound_ge_0.6": bool(ci) and ci[0] >= 0.6,
                           "not_more_than_0.05_below_rita": rrec is not None and rec >= rrec - 0.05}}
        gate["pass"] = all(gate["checks"].values())
        gate["fixed_threshold_default_on_condition"] = {"recall_at_0.8": sp["fixed"][0]["recall"], "false_pairs_at_0.8": sp["fixed"][0]["false_pairs"],
                                                         "met": (sp["fixed"][0]["recall"] or 0) >= 0.8 and sp["fixed"][0]["false_pairs"] == 0}
    top = lambda rs, k: [  # noqa: E731
        {x: r[x] for x in ("capture", "pair", "flows", "dst_ips", "score", "components", "rita")} for r in sorted(rs, key=lambda r: -r[k])[:10]]
    out = {"benchmark": "Held-out set A (CTU-13 C2 pairs vs CTU-Normal 2017 benign pairs): Spectra beacon v2a1 vs RITA v5.1.2",
           "git_commit": cicv2.cic.git("rev-parse", "HEAD"), "min_flows": MIN_FLOWS, "bootstrap": BOOT, "seed": SEED,
           "spectra_threshold": DEFAULT_THRESHOLD, "rita_alert_levels": {"default_base": RITA_BASE, "low": RITA_LOW,
                                                                         "note": "scoring.beacon.score_thresholds base=50 low=70 in RITA's config.hjson (beacon_score is 0-1 here)"},
           "capture_sha256": hashes, "label_files": label_info, "captures": caps, "rita_import": rita_info,
           "n_pos": len(pos), "n_neg": len(neg), "n_botnet_non_c2": len(bnc),
           "positives_without_verdict": sum(1 for r in pos if not r["verdict"]),
           "negatives_without_verdict": sum(1 for r in neg if not r["verdict"]),
           "results": res, "gate_set_a": gate,
           "positives": sorted(pos, key=lambda r: -r["score"]), "top_negatives_spectra": top(neg, "score"),
           "top_negatives_rita": top(neg, "rita"), "top_botnet_non_c2_spectra": top(bnc, "score")}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(out, open(a.out, "w"), indent=1)
    print(json.dumps({k: out[k] for k in ("n_pos", "n_neg", "n_botnet_non_c2", "positives_without_verdict", "gate_set_a")}, indent=1), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
