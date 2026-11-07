#!/usr/bin/env python
"""Phase B benchmark on CSE-CIC-IDS2018, Bot day (Friday 2018-03-02), docs/34 B.2.

    cd backend
    python scripts/bench_cic2018.py --root <cic2018 dir> --suricata-out <dir> --out <json>

Labels come from the attack schedule published on https://www.unb.ca/cic/datasets/ids-2018.html (NOT the processed
CICFlowMeter CSV: it has no IP columns and stops at 12:59 local, see the report).  Bot: C2 address 18.219.211.138,
victims 172.31.69.{6,8,10,12,14,17,23,26,29,30}, local windows 10:11-11:34 and 14:24-15:55.  Local time = UTC + OFFSET;
OFFSET is chosen from {-8..-3} as the value putting most C2 flows inside the windows (reported, not assumed).
 * positive  = a flow of a victim host that has the C2 address as an endpoint, inside a window (+/-120 s);
 * negative  = every flow of the NON-victim hosts' captures of the same day (no flow with the C2 address);
 * excluded  = other flows of the victim hosts (ambiguous: they may be benign or part of the infection) and C2 flows
   outside the windows - counted in the report, never scored.
Training: benign client hosts of Wednesday 2018-02-14 (an earlier day; their captures hold no attack from the schedule).
The per-host captures are cut off mid-record (tcpdump stopped); this script reads the packets before the cut, which the
product's strict reader refuses, and counts how many files were cut.
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import hashlib
import json
import os
import platform
import subprocess
import sys

import numpy as np

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND)

from spectra.capture import open_source  # noqa: E402
from spectra.eval.metrics import score_metrics  # noqa: E402
from spectra.features.extractor import flows_to_matrix  # noqa: E402
from spectra.ml.model import SpectraDetector  # noqa: E402
from spectra.parse.flow import FlowTracker  # noqa: E402

C2 = "18.219.211.138"
VICTIMS = {6, 8, 10, 12, 14, 17, 23, 26, 29, 30}
WINDOWS = [((10, 11), (11, 34)), ((14, 24), (15, 55))]
SLACK_S = 120
SEED, N_BOOT = 1337, 1000
TRAIN_HOSTS = ["Wednesday-14-02-2018__capDESKTOP-AN3U28N-172.31.67.15", "Wednesday-14-02-2018__capWIN-J6GMIG1DQE5-172.31.67.109"]


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def git(*a: str) -> str:
    try:
        return subprocess.run(["git", *a], capture_output=True, text=True, cwd=BACKEND, check=True).stdout.strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def tolerant_flows(path: str, cache: str) -> dict:
    digest = sha256(path)
    npz = os.path.join(cache, digest + ".npz")
    if os.path.isfile(npz):
        d = np.load(npz, allow_pickle=True)
        return {"sha256": digest, "X": d["X"], "meta": [tuple(m) for m in d["meta"].tolist()], "cut": bool(d["cut"])}
    out: list = []
    tr = FlowTracker(idle_timeout=30.0, on_complete=out.append)
    cut = False
    try:
        for pkt in open_source("pcap", path=path).packets():
            tr.process(pkt, float(pkt.time))
    except Exception as exc:  # noqa: BLE001 - only a cut-off tail is tolerated
        if "truncated" not in str(exc):
            raise
        cut = True
    list(tr.flush_all())
    X = flows_to_matrix(out) if out else np.empty((0, 39))
    meta = [(f.src_ip, int(f.src_port), f.dst_ip, int(f.dst_port), float(f.start_ts)) for f in out]
    np.savez(npz, X=X, meta=np.array(meta, dtype=object), cut=cut)
    return {"sha256": digest, "X": X, "meta": meta, "cut": cut}


def in_window(ts: float, off: int) -> bool:
    local = dt.datetime.fromtimestamp(ts, dt.UTC).replace(tzinfo=None) + dt.timedelta(hours=off)
    s = local.hour * 3600 + local.minute * 60 + local.second
    return any(a[0] * 3600 + a[1] * 60 - SLACK_S <= s <= b[0] * 3600 + b[1] * 60 + SLACK_S for a, b in WINDOWS)


def is_rule_alert(e: dict) -> bool:
    """A real signature hit: an ET rule that is not informational. Excludes Suricata engine/decoder events
    (e.g. 'SURICATA IPv4 invalid checksum', a capture artefact) and 'ET INFO' rules."""
    sig = e.get("alert", {}).get("signature", "")
    return sig.startswith("ET ") and not sig.startswith("ET INFO ")


def suricata_hits(eve: str, rules_only: bool) -> set:
    hits = set()
    if os.path.isfile(eve):
        for line in open(eve, encoding="utf-8"):
            if '"event_type":"alert"' in line:
                e = json.loads(line)
                if "src_port" in e and (not rules_only or is_rule_alert(e)):
                    hits.add((e["src_ip"], int(e["src_port"]), e["dest_ip"], int(e["dest_port"])))
                    hits.add((e["dest_ip"], int(e["dest_port"]), e["src_ip"], int(e["src_port"])))
    return hits


def host_octet(name: str) -> int | None:
    tail = name.rsplit("172.31.", 1)[-1]
    parts = tail.split(".")
    try:
        return int(parts[1]) if parts[0] == "69" else None
    except (IndexError, ValueError):
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", required=True)
    ap.add_argument("--suricata-out", default=None)
    ap.add_argument("--out", required=True)
    ap.add_argument("--contamination", type=float, default=0.02)
    a = ap.parse_args()
    cache = os.path.join(a.root, ".feature-cache")
    os.makedirs(cache, exist_ok=True)
    fri = sorted(p for p in glob.glob(os.path.join(a.root, "Friday-02-03-2018__*")) if not p.endswith(".log"))
    victims = [p for p in fri if host_octet(os.path.basename(p)) in VICTIMS and "EC2AMAZ-O4EL3NG" in p]
    others = [p for p in fri if p not in victims]
    train = [os.path.join(a.root, n) for n in TRAIN_HOSTS]
    files, data = {}, {}
    for p in train + victims + others:
        d = tolerant_flows(p, cache)
        data[p] = d
        files[os.path.basename(p)] = {"sha256": d["sha256"], "flows": len(d["meta"]), "cut_off_mid_record": d["cut"]}
        print(f"  {os.path.basename(p)}: {len(d['meta'])} flows{' (cut)' if d['cut'] else ''}", flush=True)

    c2_ts = [m[4] for p in victims for m in data[p]["meta"] if C2 in (m[0], m[2])]
    if not c2_ts:
        print("no flow with the C2 address in the victim captures - nothing to label as Bot", file=sys.stderr)
        return 3
    offsets = {off: sum(in_window(t, off) for t in c2_ts) for off in range(-8, -2)}
    off = max(offsets, key=offsets.get)

    Xtr = np.vstack([data[p]["X"] for p in train])
    det = SpectraDetector(contamination=a.contamination, random_state=42)
    fit = det.fit(Xtr)
    thr = det._threshold
    pos_rows, neg_rows, excl_victim, excl_c2 = [], [], 0, 0
    pos_keys, neg_keys = [], []
    for p in victims:
        for x, m in zip(data[p]["X"], data[p]["meta"], strict=True):
            if C2 in (m[0], m[2]):
                if in_window(m[4], off):
                    pos_rows.append(x)
                    pos_keys.append(m[:4])
                else:
                    excl_c2 += 1
            else:
                excl_victim += 1
    for p in others:
        for x, m in zip(data[p]["X"], data[p]["meta"], strict=True):
            if C2 not in (m[0], m[2]):
                neg_rows.append(x)
                neg_keys.append(m[:4])
    if len(pos_rows) < 20 or len(neg_rows) < 100:
        print(f"too few labelled flows (pos {len(pos_rows)}, neg {len(neg_rows)})", file=sys.stderr)
        return 3
    Xp, Xn = np.array(pos_rows), np.array(neg_rows)
    s_pos, s_neg = np.asarray(det._raw(Xp), float), np.asarray(det._raw(Xn), float)
    rng = np.random.default_rng(SEED)

    def rate(v):
        v = np.asarray(v, float)
        b = [v[rng.integers(0, len(v), len(v))].mean() for _ in range(N_BOOT)]
        return {"n": int(len(v)), "rate": round(float(v.mean()), 4),
                "ci95": [round(float(np.percentile(b, 2.5)), 4), round(float(np.percentile(b, 97.5)), 4)]}

    rep = {
        "kind": "REAL captures; labels from the published attack schedule (C2 address + time windows), NOT per-flow ground truth",
        "environment": {"commit": git("rev-parse", "--short", "HEAD"), "python": platform.python_version(),
                        "numpy": np.__version__, "seed": SEED, "bootstrap": N_BOOT,
                        "contamination": a.contamination, "model_fit": fit},
        "labelling": {"c2": C2, "victims": sorted(VICTIMS), "windows_local": "10:11-11:34, 14:24-15:55 (+/-120 s)",
                      "utc_offset_chosen_h": off, "c2_flows_inside_window_by_offset": offsets, "c2_flows_total": len(c2_ts)},
        "files": files,
        "counts": {"positive_flows": len(pos_rows), "negative_flows": len(neg_rows),
                   "excluded_victim_flows_without_c2": excl_victim, "excluded_c2_flows_outside_windows": excl_c2,
                   "captures_cut_mid_record": sum(1 for f in files.values() if f["cut_off_mid_record"]), "captures": len(files)},
        "spectra_unsupervised": {
            "scores": score_metrics(list(map(float, s_pos)), list(map(float, s_neg)), N_BOOT, SEED),
            "benign_flag_rate_at_default_threshold": rate(s_neg > thr),
            "bot_flag_rate_at_default_threshold": rate(s_pos > thr)},
        "benign_score_percentiles_p50_p90_p99_p999": [round(float(x), 4) for x in np.percentile(s_neg, [50, 90, 99, 99.9])],
        "default_threshold": round(float(thr), 4),
        "caveats": [
            "Positives are flows that touch the documented C2 address inside the documented windows; other Bot-related flows are not labelled.",
            "Negatives are all flows of non-victim hosts from the same day; the schedule lists no attack on them, but that is not an audit of their traffic.",
            "Local time is UTC + the offset chosen from the data, not documented.",
            "Per-host captures are cut off mid-record; flows after the cut are missing.",
            "Same AWS lab for train and test hosts; positives are one botnet (Ares) on ten victim hosts."],
    }
    from sklearn.ensemble import RandomForestClassifier
    half = len(Xp) // 2
    pidx = rng.permutation(len(Xp))
    nidx = rng.permutation(len(Xn))
    hn = len(Xn) // 2
    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced", n_jobs=-1, random_state=42).fit(
        np.vstack([Xp[pidx[:half]], Xn[nidx[:hn]]]), np.concatenate([np.ones(half), np.zeros(hn)]))
    rep["supervised_random_forest_upper_bound"] = {
        "note": "random 50/50 flow split of the SAME labelled flows (same hosts, same day): optimistic by construction",
        "scores": score_metrics(list(map(float, rf.predict_proba(Xp[pidx[half:]])[:, 1])),
                                list(map(float, rf.predict_proba(Xn[nidx[hn:]])[:, 1])), N_BOOT, SEED)}
    if a.suricata_out:
        rep["suricata_et_open"] = {}
        for label, rules_only in (("all_alerts", False), ("et_rules_only_excluding_info_and_engine_events", True)):
            hits = {p: suricata_hits(os.path.join(a.suricata_out, os.path.basename(p), "eve.json"), rules_only)
                    for p in victims + others}
            tp = sum(1 for p in victims for m in data[p]["meta"] if C2 in (m[0], m[2]) and in_window(m[4], off) and m[:4] in hits[p])
            fp = sum(1 for p in others for m in data[p]["meta"] if C2 not in (m[0], m[2]) and m[:4] in hits[p])
            rep["suricata_et_open"][label] = {"bot_flows_alerted": tp, "bot_flows": len(pos_rows),
                                              "recall": round(tp / len(pos_rows), 4), "benign_flows_alerted": fp,
                                              "benign_flows": len(neg_rows), "benign_flag_rate": round(fp / len(neg_rows), 4)}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(rep, open(a.out, "w", encoding="utf-8"), indent=2)
    s = rep["spectra_unsupervised"]["scores"]
    print(f"offset {off} h; pos {len(pos_rows)} neg {len(neg_rows)}; roc_auc {s['roc_auc']:.4f} {s['roc_auc_ci95']} "
          f"pr_auc {s['pr_auc']:.4f} recall@1% {s['recall_at_fpr_1pct']:.4f}")
    print("wrote", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
