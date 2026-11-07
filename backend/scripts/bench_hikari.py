#!/usr/bin/env python
"""Phase B per-flow benchmark on HIKARI-2021 (attacks inside TLS, benign background), docs/34 B.2.

    cd backend
    python scripts/bench_hikari.py --root <hikari dir> --out ../docs/evidence/<date>/bench/hikari-bench.json

Labels come from ALLFLOWMETER_HIKARI2021.csv (columns originh/originp/responh/responp, Label 0/1, traffic_category).
The CSV has NO timestamps, so a flow is labelled by its 4-tuple; a tuple that carries conflicting labels is dropped and
counted.  Flows with no CSV row are unlabelled and excluded (counted).  Protocol: the unsupervised detector is trained on
label-0 flows of the EARLIER captures only (2021-04-11/12) and tested on LATER captures (2021-04-17, 2022-04-10/11).
Baselines: Suricata + ET Open (alerts joined on the 4-tuple, same flows) and a supervised RandomForest on the same
features (upper bound).  Everything is joined on the same labelled test flows.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import subprocess
import sys
from collections import Counter

import numpy as np

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND)

from spectra.eval.metrics import score_metrics  # noqa: E402
from spectra.features.extractor import flows_to_matrix  # noqa: E402
from spectra.ml.model import SpectraDetector  # noqa: E402
from spectra.tools import collect_flows  # noqa: E402

TRAIN = ["BRUTEFORCE_HTTPS__pcap__Sunday_2021-04-11_2154.pcap", "BRUTEFORCE_XML__pcap__Monday_2021-04-12_0611.pcap"]
TEST = ["BRUTEFORCE_XML__pcap__Saturday_2021-04-17_0357.pcap", "Sunday_2022-04-10_2335_BRUTEFORCE_HTTPS_150s.pcap",
        "Monday_2022-04-11_0622_BRUTEFORCE_XML_150s.pcap"]
SEED, N_BOOT = 1337, 1000


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


def load_labels(paths: list[str]) -> tuple[dict, dict]:
    seen: dict[tuple, set] = {}
    for path in paths:                       # the 2021 CSV says traffic_category, the 2022 one attack_category
        for r in csv.DictReader(open(path, encoding="utf-8")):
            cat = r.get("traffic_category") or r.get("attack_category")
            seen.setdefault((r["originh"], int(r["originp"]), r["responh"], int(r["responp"])), set()).add(
                (int(r["Label"]), cat))
    ok, amb = {}, 0
    for k, v in seen.items():
        if len({lab for lab, _ in v}) == 1:
            ok[k] = sorted(v)[0]
        else:
            amb += 1
    return ok, {"tuples": len(seen), "ambiguous_dropped": amb}


def flows_for(path: str, labels: dict, cache: str) -> dict:
    digest = sha256(path)
    npz = os.path.join(cache, digest + ".npz")
    if os.path.isfile(npz):
        d = np.load(npz, allow_pickle=True)
        return {"sha256": digest, "X": d["X"], "tuples": [tuple(t) for t in d["tuples"].tolist()]}
    flows = collect_flows(path, max_flows=2_000_000)
    X = flows_to_matrix(flows)
    tuples = [(f.src_ip, int(f.src_port), f.dst_ip, int(f.dst_port)) for f in flows]
    np.savez(npz, X=X, tuples=np.array(tuples, dtype=object))
    return {"sha256": digest, "X": X, "tuples": tuples}


def label_of(t: tuple, labels: dict):
    return labels.get(t) or labels.get((t[2], t[3], t[0], t[1]))


def is_rule_alert(e: dict) -> bool:
    """A real signature hit: an ET rule that is not informational. Excludes Suricata engine/decoder events
    (e.g. 'SURICATA IPv4 invalid checksum', a capture artefact) and 'ET INFO' rules."""
    sig = e.get("alert", {}).get("signature", "")
    return sig.startswith("ET ") and not sig.startswith("ET INFO ")


def suricata_hits(eve_path: str, rules_only: bool = False) -> set:
    hits = set()
    if not os.path.isfile(eve_path):
        return hits
    with open(eve_path, encoding="utf-8") as fh:
        for line in fh:
            if '"event_type":"alert"' not in line:
                continue
            e = json.loads(line)
            if "src_ip" in e and "src_port" in e and (not rules_only or is_rule_alert(e)):
                hits.add((e["src_ip"], int(e["src_port"]), e["dest_ip"], int(e["dest_port"])))
                hits.add((e["dest_ip"], int(e["dest_port"]), e["src_ip"], int(e["src_port"])))
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", required=True)
    ap.add_argument("--suricata-out", default=None, help="directory with <pcap stem>/eve.json per capture")
    ap.add_argument("--out", required=True)
    ap.add_argument("--contamination", type=float, default=0.02)
    a = ap.parse_args()
    cache = os.path.join(a.root, ".feature-cache")
    os.makedirs(cache, exist_ok=True)
    label_files = [os.path.join(a.root, "ALLFLOWMETER_HIKARI2021.csv"), os.path.join(a.root, "labels2022.csv")]
    labels, lab_info = load_labels(label_files)
    data, per_file = {}, {}
    for name in TRAIN + TEST:
        d = flows_for(os.path.join(a.root, name), labels, cache)
        lab = [label_of(t, labels) for t in d["tuples"]]
        d["lab"] = lab
        data[name] = d
        c = Counter("unlabelled" if x is None else x[1] for x in lab)
        per_file[name] = {"sha256": d["sha256"], "flows": len(lab), "label_categories": dict(c)}
        print(f"  {name}: {len(lab)} flows {dict(c)}", flush=True)

    def split(names, want):
        rows, cats = [], []
        for n in names:
            for i, x in enumerate(data[n]["lab"]):
                if x is not None and x[0] == want:
                    rows.append(data[n]["X"][i])
                    cats.append(x[1])
        return (np.array(rows), cats) if rows else (np.empty((0, data[names[0]]["X"].shape[1])), [])

    Xb, _ = split(TRAIN, 0)
    det = SpectraDetector(contamination=a.contamination, random_state=42)
    fit = det.fit(Xb)
    thr = det._threshold
    Xneg, neg_cat = split(TEST, 0)
    Xpos, pos_cat = split(TEST, 1)
    s_neg, s_pos = np.asarray(det._raw(Xneg), float), np.asarray(det._raw(Xpos), float)
    rng = np.random.default_rng(SEED)

    def rate(v):
        v = np.asarray(v, float)
        b = [v[rng.integers(0, len(v), len(v))].mean() for _ in range(N_BOOT)]
        return {"n": int(len(v)), "rate": round(float(v.mean()), 4),
                "ci95": [round(float(np.percentile(b, 2.5)), 4), round(float(np.percentile(b, 97.5)), 4)]}

    rep = {
        "kind": "REAL captures; per-flow labels from HIKARI ALLFLOWMETER CSV joined on the 4-tuple (no timestamps)",
        "environment": {"commit": git("rev-parse", "--short", "HEAD"), "python": platform.python_version(),
                        "numpy": np.__version__, "seed": SEED, "bootstrap": N_BOOT,
                        "contamination": a.contamination, "model_fit": fit},
        "label_files": {os.path.basename(f): sha256(f) for f in label_files} | lab_info,
        "files": per_file,
        "split": {"train_benign_from": TRAIN, "test": TEST},
        "test_flows": {"benign": int(len(Xneg)), "attack": int(len(Xpos)),
                       "benign_categories": dict(Counter(neg_cat)), "attack_categories": dict(Counter(pos_cat))},
        "spectra_unsupervised": {
            "scores": score_metrics(list(map(float, s_pos)), list(map(float, s_neg)), N_BOOT, SEED),
            "benign_flag_rate_at_default_threshold": rate(s_neg > thr),
            "attack_flag_rate_at_default_threshold": rate(s_pos > thr),
            "per_attack_category": {},
        },
        "benign_score_percentiles_p50_p90_p99_p999": [round(float(x), 4) for x in np.percentile(s_neg, [50, 90, 99, 99.9])],
        "default_threshold": round(float(thr), 4),
        "caveats": [
            "Labels are joined on the 4-tuple only; repeated tuples with conflicting labels are dropped, flows absent from the CSV are excluded.",
            "HIKARI's attacks are synthetic-in-the-lab (brute force, probing, miner) against a few servers; this is not a general encrypted-traffic claim.",
            "Train and test come from the same lab and servers, so this is closer to in-distribution than a cross-network deployment.",
        ],
    }
    for cat in sorted(set(pos_cat)):
        m = np.array([c == cat for c in pos_cat])
        rep["spectra_unsupervised"]["per_attack_category"][cat] = {
            "n": int(m.sum()), "flag_rate": rate(s_pos[m] > thr),
            "fraction_above_benign_p90": round(float((s_pos[m] > np.percentile(s_neg, 90)).mean()), 4),
            "fraction_above_benign_p99": round(float((s_pos[m] > np.percentile(s_neg, 99)).mean()), 4),
            "score_p05_p50_p95": [round(float(x), 4) for x in np.percentile(s_pos[m], [5, 50, 95])],
            "scores_vs_all_benign": score_metrics(list(map(float, s_pos[m])), list(map(float, s_neg)), N_BOOT, SEED)}
    # supervised RF upper bound: labelled flows of the training captures, tested on the same test flows
    from sklearn.ensemble import RandomForestClassifier
    Xa0, _ = split(TRAIN, 0)
    Xa1, _ = split(TRAIN, 1)
    if len(Xa1):
        rf = RandomForestClassifier(n_estimators=200, class_weight="balanced", n_jobs=-1, random_state=42).fit(
            np.vstack([Xa0, Xa1]), np.concatenate([np.zeros(len(Xa0)), np.ones(len(Xa1))]))
        rp = rf.predict_proba(Xpos)[:, 1]
        rn = rf.predict_proba(Xneg)[:, 1]
        rep["supervised_random_forest_upper_bound"] = {
            "train_flows": {"benign": int(len(Xa0)), "attack": int(len(Xa1))},
            "scores": score_metrics(list(map(float, rp)), list(map(float, rn)), N_BOOT, SEED),
            "benign_flag_rate_at_0.5": rate(rn >= 0.5), "attack_flag_rate_at_0.5": rate(rp >= 0.5)}
    # Suricata + ET Open on the same labelled test flows
    if a.suricata_out:
        rep["suricata_et_open"] = {}
        for label, rules_only in (("all_alerts", False), ("et_rules_only_excluding_info_and_engine_events", True)):
            tp = fp = fn = tn = 0
            for n in TEST:
                hits = suricata_hits(os.path.join(a.suricata_out, n[:-5], "eve.json"), rules_only)
                for t, x in zip(data[n]["tuples"], data[n]["lab"], strict=True):
                    if x is None:
                        continue
                    hit = t in hits
                    if x[0] == 1:
                        tp += hit
                        fn += not hit
                    else:
                        fp += hit
                        tn += not hit
            rep["suricata_et_open"][label] = {
                "flows_with_alert_and_attack": tp, "attack_flows_missed": fn, "benign_flows_alerted": fp,
                "benign_flows_quiet": tn, "recall": round(tp / max(tp + fn, 1), 4),
                "benign_flag_rate": round(fp / max(fp + tn, 1), 4), "precision": round(tp / max(tp + fp, 1), 4)}
        rep["suricata_et_open"]["note"] = ("alert joined to a flow by its 4-tuple; Suricata 7.0.8, ET Open fetched 2026-11-07; "
                                           "'all_alerts' includes engine/decoder events and ET INFO rules")
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(rep, open(a.out, "w", encoding="utf-8"), indent=2)
    s = rep["spectra_unsupervised"]["scores"]
    print(f"\nSpectra roc_auc {s['roc_auc']:.4f} {s['roc_auc_ci95']} pr_auc {s['pr_auc']:.4f} "
          f"recall@1%FPR {s['recall_at_fpr_1pct']:.4f} recall@0.1%FPR {s['recall_at_fpr_0_1pct']:.4f}")
    if "suricata_et_open" in rep:
        print("Suricata:", {k: v for k, v in rep["suricata_et_open"].items() if k != "note"})
    print("wrote", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
