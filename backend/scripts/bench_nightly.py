#!/usr/bin/env python
"""Nightly regression benchmark (Phase B, docs/34 B.3): small, fixed, real captures; fails on regression.

    cd backend
    python scripts/bench_nightly.py --data <dir> --thresholds ../ci/nightly_thresholds.json [--write-measured out.json]

Files (SHA-256 pinned below; downloaded by the workflow, never stored in git): train on CTU-Normal-26 (2017-04-28), test
benign = CTU-Normal-28 (2017-05-01), positives = CTU-13 scenario 2 botnet capture.  The thresholds file holds the
measured value, a tolerance and a direction per metric; a run fails when a metric moves the wrong way past its tolerance.
This guards against regressions in parsing, features and scoring.  It is not a claim about detection quality.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spectra.eval.metrics import score_metrics  # noqa: E402
from spectra.features.extractor import flows_to_matrix  # noqa: E402
from spectra.ml.model import SpectraDetector  # noqa: E402
from spectra.tools import collect_flows  # noqa: E402

FILES = {
    "train": ("2017-04-28_normal.pcap", "b66103fd89c8f0fc53b76e718f53320f3af27edd302c58695fc1870ede3663c5"),
    "benign": ("2017-05-01_normal.pcap", "a2f3e60fa0eb2a924a3795644ac09a0f1ea48c45c30ebcc663af9641580b9a5c"),
    "botnet": ("botnet-capture-20110811-neris.pcap", "189b38247b614ae51feee0e75b360552eecdee0b68843b88c7d9ed88d7be7631"),
}


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def measure(data: str) -> dict:
    X = {}
    for role, (name, digest) in FILES.items():
        path = os.path.join(data, name)
        if sha256(path) != digest:
            raise SystemExit(f"SHA-256 mismatch for {name}")
        X[role] = flows_to_matrix(collect_flows(path, max_flows=2_000_000))
    det = SpectraDetector(contamination=0.02, random_state=42)
    det.fit(X["train"])
    neg = np.asarray(det._raw(X["benign"]), float)
    pos = np.asarray(det._raw(X["botnet"]), float)
    rng = np.random.default_rng(1337)
    half = rng.permutation(len(neg))
    null = score_metrics(list(map(float, neg[half[: len(neg) // 2]])), list(map(float, neg[half[len(neg) // 2:]])), 0)
    sm = score_metrics(list(map(float, pos)), list(map(float, neg)), 0)
    return {"flows_train": int(len(X["train"])), "flows_benign": int(len(neg)), "flows_botnet": int(len(pos)),
            "benign_flag_rate": round(float((neg > det._threshold).mean()), 4),
            "botnet_flag_rate": round(float((pos > det._threshold).mean()), 4),
            "roc_auc": round(sm["roc_auc"], 4), "null_roc_auc": round(null["roc_auc"], 4)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", required=True)
    ap.add_argument("--thresholds", required=True)
    ap.add_argument("--write-measured", default=None)
    a = ap.parse_args()
    got = measure(a.data)
    print(json.dumps(got, indent=1))
    if a.write_measured:
        json.dump(got, open(a.write_measured, "w"), indent=1)
    spec = json.load(open(a.thresholds))
    bad = []
    for key, rule in spec["metrics"].items():
        v, ref, tol = got[key], rule["measured"], rule["tolerance"]
        if rule["fail_if"] == "higher" and v > ref + tol:
            bad.append(f"{key}: {v} > {ref} + {tol}")
        elif rule["fail_if"] == "lower" and v < ref - tol:
            bad.append(f"{key}: {v} < {ref} - {tol}")
        elif rule["fail_if"] == "either" and abs(v - ref) > tol:
            bad.append(f"{key}: {v} outside {ref} +/- {tol}")
    for key in ("flows_train", "flows_benign", "flows_botnet"):
        if got[key] != spec["counts"][key]:
            bad.append(f"{key}: {got[key]} != {spec['counts'][key]} (parser or flow tracker changed)")
    if bad:
        print("REGRESSION:\n  " + "\n  ".join(bad), file=sys.stderr)
        return 1
    print("nightly benchmark: within thresholds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
