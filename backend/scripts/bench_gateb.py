#!/usr/bin/env python
"""Phase B, Gate B remainder (docs/34 B.2 items 4, 5, 7 and the JA3 reference), on the three real datasets.

    cd backend
    python scripts/bench_gateb.py --bench-data <dir> --out ../docs/evidence/<date>/bench/gateb.json

Reuses the cached features of bench_ctu / bench_hikari / bench_cic2018 (run those first).
 A cross  : train on one dataset's benign slice, test on the others (benign flag rate = the "baseline matching" warning
            measured; attack ranking per dataset).
 B 9C     : with / without synthetic benign augmentation (1000 flows) at train time.
 C 9D     : host-pair beaconing regularity (modules.corr.graph.cadence_stats) on the CIC-2018 Bot day, pair level.
 D 9B     : the evasion attack (modules.adv.evasion.attack_batch) on flows the detector flags, per dataset.
 E JA3    : Spectra's own JA3 of every TLS flow vs the abuse.ch SSLBL list ("fingerprint list" reference; NOT Zeek).
Score metrics use at most 20,000 flows per class (fixed-seed subsample) and 300 bootstrap resamples to keep the run
tractable; the cap and resample count are written into the output.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import tempfile

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import bench_cic2018 as cic  # noqa: E402
import bench_ctu as ctu  # noqa: E402
import bench_hikari as hik  # noqa: E402

from spectra.eval.metrics import score_metrics  # noqa: E402
from spectra.ml.model import SpectraDetector  # noqa: E402

SEED, BOOT, CAP = 1337, 300, 20_000


def cap(a: np.ndarray, rng: np.random.Generator) -> np.ndarray:
    return a if len(a) <= CAP else a[rng.choice(len(a), CAP, replace=False)]


def load_all(root: str) -> dict:
    rng = np.random.default_rng(SEED)
    out: dict = {}
    # CTU
    ddir = os.path.join(root, "datasets")
    man = {e["filename"]: e for e in json.load(open(os.path.join(ddir, "manifest.json")))["entries"]}
    cache = os.path.join(ddir, ".feature-cache")
    X = {n: ctu.features(os.path.join(ddir, n), man[n]["sha256"], cache) for n in ctu.TRAIN + ctu.TEST_BENIGN + ctu.BOTNET}
    out["ctu"] = {"train": np.vstack([X[n] for n in ctu.TRAIN]), "neg": np.vstack([X[n] for n in ctu.TEST_BENIGN]),
                  "pos": np.vstack([X[n] for n in ctu.BOTNET])}
    # HIKARI
    hroot = os.path.join(root, "hikari")
    labels, _ = hik.load_labels([os.path.join(hroot, "ALLFLOWMETER_HIKARI2021.csv"), os.path.join(hroot, "labels2022.csv")])
    hc = os.path.join(hroot, ".feature-cache")
    hd = {}
    for n in hik.TRAIN + hik.TEST:
        d = hik.flows_for(os.path.join(hroot, n), labels, hc)
        d["lab"] = [hik.label_of(t, labels) for t in d["tuples"]]
        hd[n] = d

    def hsel(names, want):
        rows = [hd[n]["X"][i] for n in names for i, x in enumerate(hd[n]["lab"]) if x and x[0] == want]
        return np.array(rows)

    out["hikari"] = {"train": hsel(hik.TRAIN, 0), "neg": hsel(hik.TEST, 0), "pos": hsel(hik.TEST, 1)}
    # CIC-2018
    croot = os.path.join(root, "cic2018")
    cc = os.path.join(croot, ".feature-cache")
    import glob
    fri = sorted(p for p in glob.glob(os.path.join(croot, "Friday-02-03-2018__*")) if not p.endswith(".log"))
    vict = [p for p in fri if cic.host_octet(os.path.basename(p)) in cic.VICTIMS and "EC2AMAZ-O4EL3NG" in p]
    oth = [p for p in fri if p not in vict]
    cd = {p: cic.tolerant_flows(p, cc) for p in vict + oth}
    tr = [cic.tolerant_flows(os.path.join(croot, n), cc)["X"] for n in cic.TRAIN_HOSTS]
    off = -4
    posr = []
    for p in vict:
        for x, m in zip(cd[p]["X"], cd[p]["meta"], strict=True):
            if cic.C2 in (m[0], m[2]) and cic.in_window(m[4], off):
                posr.append(x)
    negr = [x for p in oth for x, m in zip(cd[p]["X"], cd[p]["meta"], strict=True) if cic.C2 not in (m[0], m[2])]
    out["cic"] = {"train": np.vstack(tr), "neg": np.array(negr), "pos": np.array(posr)}
    out["_cic_flows"] = {"victims": vict, "data": cd, "off": off}
    for k in ("ctu", "hikari", "cic"):
        out[k] = {kk: (cap(v, rng) if kk != "train" else v) for kk, v in out[k].items()}
    return out


def fit(X: np.ndarray, contamination: float = 0.02) -> SpectraDetector:
    d = SpectraDetector(contamination=contamination, random_state=42)
    d.fit(X)
    return d


def evaluate(det: SpectraDetector, d: dict) -> dict:
    sn = np.asarray(det._raw(d["neg"]), float)
    sp = np.asarray(det._raw(d["pos"]), float)
    thr = det._threshold
    sm = score_metrics(list(map(float, sp)), list(map(float, sn)), BOOT, SEED)
    return {"n_neg": int(len(sn)), "n_pos": int(len(sp)), "benign_flag_rate": round(float((sn > thr).mean()), 4),
            "attack_flag_rate": round(float((sp > thr).mean()), 4),
            "roc_auc": sm["roc_auc"], "roc_auc_ci95": sm["roc_auc_ci95"], "pr_auc": sm["pr_auc"],
            "recall_at_fpr_1pct": sm["recall_at_fpr_1pct"]}


def stage_cross(D: dict) -> dict:
    res: dict = {}
    for src in ("ctu", "hikari", "cic"):
        det = fit(D[src]["train"])
        row = {"train_flows": int(len(D[src]["train"]))}
        for tgt in ("ctu", "hikari", "cic"):
            r = evaluate(det, D[tgt])
            r["same_dataset"] = src == tgt
            # distribution shift: how far target benign sits from the source train slice
            r["shift_auc_target_benign_vs_source_train"] = round(float(
                score_metrics(list(map(float, det._raw(D[tgt]["neg"]))), list(map(float, det._raw(cap(D[src]["train"], np.random.default_rng(SEED))))), 0)["roc_auc"]), 4)
            row[tgt] = r
        res[src] = row
        print(f"  cross: trained on {src}: " + ", ".join(f"{t} benign-flag {row[t]['benign_flag_rate']:.3f}" for t in ("ctu", "hikari", "cic")), flush=True)
    return res


def stage_augment(D: dict) -> dict:
    from spectra.demo import make_benign_diversity_pcap
    from spectra.features.extractor import flows_to_matrix
    from spectra.tools import collect_flows
    with tempfile.TemporaryDirectory() as tmp:
        pc = make_benign_diversity_pcap(os.path.join(tmp, "s.pcap"), 1000, seed=0)
        aug = flows_to_matrix(collect_flows(pc))
    res = {"synthetic_flows_added": int(len(aug)), "note": "demo-profile synthetic TLS/QUIC benign flows, as `spectra train --augment 1000`"}
    for k in ("ctu", "hikari", "cic"):
        base = evaluate(fit(D[k]["train"]), D[k])
        withaug = evaluate(fit(np.vstack([D[k]["train"], aug])), D[k])
        res[k] = {"without": base, "with_augmentation": withaug}
        print(f"  9C {k}: AUC {base['roc_auc']:.3f} -> {withaug['roc_auc']:.3f}; benign flag {base['benign_flag_rate']:.3f} -> {withaug['benign_flag_rate']:.3f}", flush=True)
    return res


def stage_beacon(D: dict) -> dict:
    from spectra.modules.corr.graph import cadence_stats
    fl = D["_cic_flows"]
    pairs: dict[tuple, list] = {}
    c2pairs = set()
    for p in fl["victims"]:
        for m in fl["data"][p]["meta"]:
            key = (m[0], m[2]) if m[0].startswith("172.31.") else (m[2], m[0])
            pairs.setdefault(key, []).append(m[4])
            if cic.C2 in (m[0], m[2]):
                c2pairs.add(key)
    pos, neg = [], []
    for key, ts in pairs.items():
        st = cadence_stats(sorted(ts))
        if st is None:
            continue
        (pos if key in c2pairs else neg).append(st["regularity"])
    out = {"pairs_with_enough_history": len(pos) + len(neg), "c2_pairs": len(pos), "other_pairs": len(neg),
           "note": "pairs among the ten Bot-victim captures; 'c2 pair' = victim <-> 18.219.211.138; all flows of the pair, not only in-window"}
    if pos and neg:
        sm = score_metrics(pos, neg, 1000, SEED)
        out |= {"regularity_median_c2": round(float(np.median(pos)), 4), "regularity_median_other": round(float(np.median(neg)), 4),
                "roc_auc_c2_vs_other": sm["roc_auc"], "roc_auc_ci95": sm["roc_auc_ci95"]}
    print("  9D:", {k: v for k, v in out.items() if k != "note"}, flush=True)
    return out


def stage_evasion(D: dict) -> dict:
    from spectra.modules.adv.evasion import attack_batch
    rng = np.random.default_rng(SEED)
    res = {}
    for k in ("ctu", "hikari", "cic"):
        det = fit(D[k]["train"])
        flagged = D[k]["pos"][det.predict(D[k]["pos"])]
        n_flag = int(len(flagged))
        sample = flagged[rng.choice(n_flag, min(n_flag, 300), replace=False)] if n_flag else flagged
        if n_flag == 0:
            res[k] = {"attack_flows": int(len(D[k]["pos"])), "flagged": 0, "note": "nothing flagged, so nothing to evade (the detector already misses every attack flow)"}
        else:
            r = attack_batch(det, sample)
            res[k] = {"attack_flows": int(len(D[k]["pos"])), "flagged": n_flag, "attacked": int(len(sample)),
                      "evasion_rate": r["evasion_rate"], "evaded": r["evaded"], "median_relative_l1": r["median_relative_l1"],
                      "level": r["level"], "most_targeted_features": r["most_targeted_features"][:5]}
        print("  9B", k, {a: b for a, b in res[k].items() if a != "most_targeted_features"}, flush=True)
    return res


def stage_ja3(root: str) -> dict:
    import glob
    sslbl = set()
    for line in open(os.path.join(root, "intel", "ja3_fingerprints.csv"), encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        h = line.split(",")[0].strip().lower()
        if len(h) == 32:
            sslbl.add(h)
    from spectra.tools import stream_flows
    stats = {"sslbl_entries": len(sslbl), "files": {}}
    pcaps = sorted(glob.glob(os.path.join(root, "datasets", "*.pcap")))
    for p in pcaps:
        n = tls = hit = 0

        def cb(f):
            nonlocal n, tls, hit
            n += 1
            j = f.record().get("ja3")
            if j:
                tls += 1
                hit += j.lower() in sslbl
        try:
            stream_flows(p, cb, max_flows=2_000_000)
        except Exception as exc:  # noqa: BLE001 - a cut-off file still reports what was read
            stats["files"].setdefault("errors", []).append(f"{os.path.basename(p)}: {str(exc)[:60]}")
        stats["files"][os.path.basename(p)] = {"flows": n, "with_ja3": tls, "sslbl_hits": hit}
    print("  JA3: total hits", sum(v["sslbl_hits"] for k, v in stats["files"].items() if k != "errors"), flush=True)
    return stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bench-data", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", default="cross,augment,beacon,evasion,ja3")
    a = ap.parse_args()
    want = set(a.only.split(","))
    D = load_all(a.bench_data) if want - {"ja3"} else {k: {} for k in ("ctu", "hikari", "cic")}
    rep: dict = {"environment": {"python": platform.python_version(), "numpy": np.__version__, "seed": SEED,
                                 "bootstrap_resamples": BOOT, "max_flows_per_class": CAP},
                 "data": {k: {kk: int(len(vv)) for kk, vv in D[k].items()} for k in ("ctu", "hikari", "cic")}}
    if "cross" in want:
        rep["cross_dataset"] = stage_cross(D)
    if "augment" in want:
        rep["ablation_9c_augmentation"] = stage_augment(D)
    if "beacon" in want:
        rep["ablation_9d_beaconing_cic2018"] = stage_beacon(D)
    if "evasion" in want:
        rep["adversarial_9b"] = stage_evasion(D)
    if "ja3" in want:
        rep["ja3_list_reference"] = stage_ja3(a.bench_data)
    if want == {"ja3"}:      # patch mode: merge into the existing report
        old = json.load(open(a.out))
        old["ja3_list_reference"] = rep["ja3_list_reference"]
        rep = old
    rep["ablation_9h_ja4"] = {"applicable": False, "reason": "JA4/JA4+ values are not among the 39 model features; they feed intel matching "
                              "(`spectra intel`) only, and no JA4 list relevant to these captures exists, so there is no scoring effect to ablate."}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(rep, open(a.out, "w", encoding="utf-8"), indent=2)
    print("wrote", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
