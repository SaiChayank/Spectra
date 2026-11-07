#!/usr/bin/env python
"""Phase B benchmark on real Stratosphere captures (CTU-Normal vs CTU botnet), protocol of docs/34 B.2.

    cd backend
    SPECTRA_DATA_DIR=<bench data dir> python scripts/bench_ctu.py --out ../docs/evidence/<date>/bench/ctu-bench.json

* Train: benign CTU-Normal captures from EARLIER dates only.  Test: CTU-Normal captures from LATER dates
  (benign side) vs botnet captures (positive side).  Files are verified against the dataset manifest SHA-256.
* Metrics: raw isolation-forest score (the 0-100 score saturates), ROC-AUC, PR-AUC, recall at benign FPR 1% /
  0.1%, 95% bootstrap intervals (1000 resamples, seed 1337).
* Honest controls written into the report: a null AUC (benign test split in two halves), the TLS share of every
  capture (the benign side is HTTPS, the 2011 botnets mostly are not), the score restricted to flows that carry a
  parsed TLS handshake, and a supervised RandomForest trained with labels, tested on a botnet capture it never saw
  (upper bound AND a measure of how much capture-environment alone separates the classes).
* Positives are pcap-level: every flow of a botnet capture counts as malicious; there are no per-flow labels.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys

import numpy as np

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND)

from spectra.eval.metrics import score_metrics  # noqa: E402
from spectra.features.extractor import FEATURE_NAMES, flows_to_matrix  # noqa: E402
from spectra.ml.model import SpectraDetector  # noqa: E402
from spectra.tools import collect_flows  # noqa: E402

TRAIN = ["ctu_normal--2017-04-18_win-normal.pcap", "ctu_normal--2017-04-19_win-normal.pcap",
         "ctu_normal--2017-04-28_normal.pcap", "ctu_normal--2017-04-30_win-normal.pcap"]
TEST_BENIGN = ["ctu_normal--2017-05-01_normal.pcap", "ctu_normal--2017-05-02_kali-normal.pcap"]
BOTNET = ["ctu13--botnet-capture-20110810-neris.pcap", "ctu13--botnet-capture-20110811-neris.pcap",
          "ctu_botnet--botnet-capture-20110812-rbot.pcap", "ctu_botnet--botnet-capture-20110815-fast-flux.pcap",
          "ctu_botnet--capture.botnet2.infected.1.pcap"]
# ctu_botnet--2014-12-20_capture-win5.pcap is EXCLUDED: Spectra's reader reports "the file ends inside a record"
# (the file as published is cut short); it is listed in the report under "excluded".
SEED, N_BOOT = 1337, 1000
TLS_IDX = FEATURE_NAMES.index("tls_present")


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def features(path: str, expected: str, cache: str) -> np.ndarray:
    actual = sha256(path)
    if actual != expected:
        raise SystemExit(f"SHA-256 mismatch for {os.path.basename(path)}: manifest {expected}, file {actual}")
    npz = os.path.join(cache, actual + ".npy")
    if os.path.isfile(npz):
        return np.load(npz)
    X = flows_to_matrix(collect_flows(path, max_flows=2_000_000))
    np.save(npz, X)
    return X


def git(*a: str) -> str:
    try:
        return subprocess.run(["git", *a], capture_output=True, text=True, cwd=BACKEND, check=True).stdout.strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--datasets", default=os.path.join(os.environ.get("SPECTRA_DATA_DIR", ""), "datasets"))
    ap.add_argument("--out", required=True)
    ap.add_argument("--cache", default=None)
    ap.add_argument("--contamination", type=float, default=0.02)
    args = ap.parse_args()
    cache = args.cache or os.path.join(args.datasets, ".feature-cache")
    os.makedirs(cache, exist_ok=True)
    manifest = {e["filename"]: e for e in json.load(open(os.path.join(args.datasets, "manifest.json")))["entries"]}

    X: dict[str, np.ndarray] = {}
    files: dict[str, dict] = {}
    for name in TRAIN + TEST_BENIGN + BOTNET:
        ent = manifest[name]
        X[name] = features(os.path.join(args.datasets, name), ent["sha256"], cache)
        files[name] = {"sha256": ent["sha256"], "bytes": ent["size"], "source": ent["source_note"],
                       "flows": int(len(X[name])), "tls_share": round(float(X[name][:, TLS_IDX].mean()), 4)}
        print(f"  {name}: {len(X[name])} flows, TLS {files[name]['tls_share']:.1%}", flush=True)

    Xtr = np.vstack([X[n] for n in TRAIN])
    det = SpectraDetector(contamination=args.contamination, random_state=42)
    fit = det.fit(Xtr)
    raw = {n: np.asarray(det._raw(X[n]), dtype=float) for n in X}     # higher = more anomalous
    neg = np.concatenate([raw[n] for n in TEST_BENIGN])
    neg_tls = np.concatenate([raw[n][X[n][:, TLS_IDX] > 0] for n in TEST_BENIGN])
    thr = det._threshold
    rng = np.random.default_rng(SEED)

    def rate(v: np.ndarray) -> dict:
        v = np.asarray(v, dtype=float)
        boots = [v[rng.integers(0, len(v), len(v))].mean() for _ in range(N_BOOT)]
        return {"n": int(len(v)), "rate": round(float(v.mean()), 4),
                "ci95": [round(float(np.percentile(boots, 2.5)), 4), round(float(np.percentile(boots, 97.5)), 4)]}

    report: dict = {
        "kind": "REAL captures; pcap-level labels (every flow of a botnet capture = positive); "
                "unsupervised detector trained on benign only",
        "environment": {"commit": git("rev-parse", "--short", "HEAD"), "python": platform.python_version(),
                        "numpy": np.__version__, "seed": SEED, "bootstrap": N_BOOT,
                        "contamination": args.contamination, "model_fit": fit},
        "files": files,
        "excluded": {"ctu_botnet--2014-12-20_capture-win5.pcap": "CaptureError: the file ends inside a record (truncated "
                     "capture) - reported, not silently partially used"},
        "split": {"train": TRAIN, "test_benign": TEST_BENIGN, "botnet": BOTNET,
                  "note": "train = captures dated 2017-04-18..30; benign test = 2017-05-01..02 (later in time)"},
        "benign_flag_rate_at_default_threshold": rate(neg > thr),
        "pooled": {}, "per_botnet_capture": {}, "controls": {},
        "caveats": [
            "Benign = scripted visits to Alexa top-1000 HTTPS sites from lab hosts (CTU-Normal README), not user diversity.",
            "Botnet captures are 2011/2014/2015 host traces, mostly NOT TLS; capture environment, era and protocol mix differ "
            "from the benign side, so AUC here partly measures 'looks unlike CTU-Normal HTTPS', not 'is malicious'.",
            "Positives are pcap-level; botnet captures may contain benign background flows, which lowers measured recall.",
            "No Suricata/Zeek baseline or cross-dataset run is in this report (see the Phase B ledger for status).",
        ],
    }
    pos_all = np.concatenate([raw[n] for n in BOTNET])
    report["pooled"] = score_metrics(list(map(float, pos_all)), list(map(float, neg)), N_BOOT, SEED)
    report["pooled"]["recall_at_default_threshold"] = rate(pos_all > thr)
    for n in BOTNET:
        sm = score_metrics(list(map(float, raw[n])), list(map(float, neg)), N_BOOT, SEED)
        sm["recall_at_default_threshold"] = rate(raw[n] > thr)
        report["per_botnet_capture"][n] = sm
    # control 1: null AUC - two disjoint random halves of the benign test flows
    perm = rng.permutation(len(neg))
    half = len(neg) // 2
    report["controls"]["null_benign_vs_benign"] = score_metrics(
        list(map(float, neg[perm[:half]])), list(map(float, neg[perm[half:]])), N_BOOT, SEED)
    # control 2: TLS-only (botnet flows that carry a parsed TLS handshake vs benign TLS flows)
    pos_tls = np.concatenate([raw[n][X[n][:, TLS_IDX] > 0] for n in BOTNET])
    report["controls"]["tls_flows_only"] = ({"n_pos": int(len(pos_tls)), "n_neg": int(len(neg_tls)),
                                             **(score_metrics(list(map(float, pos_tls)), list(map(float, neg_tls)), N_BOOT, SEED) or {})}
                                            if len(pos_tls) >= 20 else
                                            {"skipped": f"only {len(pos_tls)} botnet flows carry a parsed TLS handshake"})
    # control 3: supervised RandomForest, leave-one-botnet-capture-out (upper bound / environment separability)
    from sklearn.ensemble import RandomForestClassifier
    rf_rows = {}
    for held in BOTNET:
        others = [n for n in BOTNET if n != held]
        Xa = np.vstack([Xtr] + [X[n] for n in others])
        ya = np.concatenate([np.zeros(len(Xtr))] + [np.ones(len(X[n])) for n in others])
        rf = RandomForestClassifier(n_estimators=200, class_weight="balanced", n_jobs=-1, random_state=42).fit(Xa, ya)
        s_pos = rf.predict_proba(X[held])[:, 1]
        s_neg = rf.predict_proba(np.vstack([X[n] for n in TEST_BENIGN]))[:, 1]
        sm = score_metrics(list(map(float, s_pos)), list(map(float, s_neg)), 200, SEED)
        rf_rows[held] = {k: sm[k] for k in ("roc_auc", "pr_auc", "recall_at_fpr_1pct", "recall_at_fpr_0_1pct",
                                              "roc_auc_ci95") if k in sm}
    report["controls"]["supervised_random_forest_leave_one_botnet_out"] = {
        "note": "trained WITH labels on benign train slice vs the other botnet captures; tested on the held-out botnet "
                "capture vs benign test. An upper bound, not a competitor; a high value here also shows how separable "
                "the capture environments are.", "per_held_out_capture": rf_rows}
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    p = report["pooled"]
    print(f"\nbenign flag rate @default thr: {report['benign_flag_rate_at_default_threshold']}")
    print(f"pooled roc_auc {p['roc_auc']:.4f} {p['roc_auc_ci95']}  pr_auc {p['pr_auc']:.4f}  "
          f"recall@1%FPR {p['recall_at_fpr_1pct']:.4f}  recall@0.1%FPR {p['recall_at_fpr_0_1pct']:.4f}")
    print(f"null benign-vs-benign roc_auc {report['controls']['null_benign_vs_benign']['roc_auc']:.4f}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
