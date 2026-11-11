#!/usr/bin/env python
"""Spectra-Bench E0: leave-attack-family-out (docs/35 §3), CTU botnet families.

    cd backend
    .venv/bin/python scripts/bench_lofo.py --datasets ~/Projects/Spectra_bench_data/datasets --out <json>

For each held-out family F: a supervised RandomForest trains on benign (CTU-Normal train slice) vs the OTHER families and is tested on
F vs the later benign test slice; the benign-only isolation forest (no family labels) is scored on the same test.  Families: neris
(two captures), rbot, fast-flux, botnet2 ("capture.botnet2.infected.1").  Positives are pcap-level labels.  CAVEAT, measured not
assumed: the botnet captures are 2011-era and mostly non-TLS while the benign captures are 2017 HTTPS, so a supervised model can win
by recognising the capture environment; a second supervised model drops the TLS, SNI, ALPN, handshake-timing and port features (the most obvious era
differences) to show how much of the separation survives without them.  Survival is not proof of attack knowledge: packet sizes
and timing also differ between capture environments.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import bench_ctu as ctu  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402

from spectra.features.extractor import FEATURE_NAMES  # noqa: E402
from spectra.eval.metrics import score_metrics  # noqa: E402
from spectra.ml.model import SpectraDetector  # noqa: E402

FAMILIES = {
    "neris": ["ctu13--botnet-capture-20110810-neris.pcap", "ctu13--botnet-capture-20110811-neris.pcap"],
    "rbot": ["ctu_botnet--botnet-capture-20110812-rbot.pcap"],
    "fast-flux": ["ctu_botnet--botnet-capture-20110815-fast-flux.pcap"],
    "botnet2": ["ctu_botnet--capture.botnet2.infected.1.pcap"],
}
SEED, BOOT, CAP = 1337, 300, 20_000
DROP = [i for i, n in enumerate(FEATURE_NAMES) if n.startswith(('tls_', 'sni_', 'alpn')) or n in ('handshake_ms', 'server_hello_ms', 'dst_port_norm')]
KEEP = [i for i in range(len(FEATURE_NAMES)) if i not in DROP]


def cap(a: np.ndarray, rng: np.random.Generator) -> np.ndarray:
    return a if len(a) <= CAP else a[rng.choice(len(a), CAP, replace=False)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--datasets", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    man = {e["filename"]: e for e in json.load(open(os.path.join(a.datasets, "manifest.json")))["entries"]}
    cache = os.path.join(a.datasets, ".feature-cache")
    X = {n: ctu.features(os.path.join(a.datasets, n), man[n]["sha256"], cache)
         for n in ctu.TRAIN + ctu.TEST_BENIGN + sum(FAMILIES.values(), [])}
    rng = np.random.default_rng(SEED)
    train_b = np.vstack([X[n] for n in ctu.TRAIN])
    test_b = cap(np.vstack([X[n] for n in ctu.TEST_BENIGN]), rng)
    fam = {k: np.vstack([X[n] for n in v]) for k, v in FAMILIES.items()}
    iso = SpectraDetector(contamination=0.02, random_state=42)
    iso.fit(train_b)
    res = {}
    for held, pos_all in fam.items():
        pos = cap(pos_all, rng)
        others = cap(np.vstack([v for k, v in fam.items() if k != held]), rng)
        tb = cap(train_b, rng)
        rf = RandomForestClassifier(n_estimators=200, random_state=SEED, n_jobs=-1, class_weight="balanced")
        rf.fit(np.vstack([tb, others]), np.r_[np.zeros(len(tb)), np.ones(len(others))])
        p, n = rf.predict_proba(pos)[:, 1], rf.predict_proba(test_b)[:, 1]
        trn = np.vstack([tb, others])[:, KEEP]
        rf2 = RandomForestClassifier(n_estimators=200, random_state=SEED, n_jobs=-1, class_weight="balanced")
        rf2.fit(trn, np.r_[np.zeros(len(tb)), np.ones(len(others))])
        p2, n2 = rf2.predict_proba(pos[:, KEEP])[:, 1], rf2.predict_proba(test_b[:, KEEP])[:, 1]
        res[held] = {
            "n_pos": int(len(pos)), "n_neg": int(len(test_b)),
            "supervised_leave_family_out": score_metrics(list(map(float, p)), list(map(float, n)), BOOT, SEED),
            "supervised_without_tls_port_features": score_metrics(list(map(float, p2)), list(map(float, n2)), BOOT, SEED),
            "isolation_forest": score_metrics(list(map(float, iso._raw(pos))), list(map(float, iso._raw(test_b))), BOOT, SEED),
        }
        print(held, round(res[held]["supervised_leave_family_out"]["roc_auc"], 3), round(res[held]["supervised_without_tls_port_features"]["roc_auc"], 3),
              round(res[held]["isolation_forest"]["roc_auc"], 3),
              file=sys.stderr)
    out = {"benchmark": "ctu leave-family-out", "dropped_features": [FEATURE_NAMES[i] for i in DROP], "cap": CAP, "bootstrap": BOOT, "seed": SEED, "families": FAMILIES,
           "inputs_sha256": {n: man[n]["sha256"] for n in X}, "python": platform.python_version(), "results": res}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(out, open(a.out, "w"), indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
