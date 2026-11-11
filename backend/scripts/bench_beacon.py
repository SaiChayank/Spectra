#!/usr/bin/env python
"""Pair-level beaconing benchmark (docs/plan-beaconing-detector.md, protocol "as run" in that file).

    cd backend
    python scripts/bench_beacon.py extract --root ~/Projects/Spectra_bench_data     # cache flow metadata per pcap
    python scripts/bench_beacon.py run --root ~/Projects/Spectra_bench_data --out ../docs/evidence/<date>/bench/beaconing-bench.json

``extract`` streams each pcap once (flat memory) and stores only metadata per flow (endpoints, SNI, start time, byte count,
duration) under <root>/.beacon-cache/.  CIC-2018 reuses the existing feature cache (it holds duration and bytes, no SNI).
``run`` builds (source, destination IP) pairs, scores them with ``spectra.modules.corr.beacon`` exactly as the product does
(streaming, trailing 64-flow window, a pair alerts the first time its window scores >= threshold), and reports the
metrics.  The threshold is chosen ONLY from benign pairs of the CIC-2018 calibration captures (no positive label is used).
"""
from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import json
import os
import platform
import subprocess
import sys
from multiprocessing import Pool

import numpy as np

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND)

from spectra.eval.metrics import score_metrics  # noqa: E402
from spectra.modules.corr.beacon import MIN_FLOWS, WINDOW, BeaconTracker, score_pair  # noqa: E402

sys.path.insert(0, os.path.join(BACKEND, "scripts"))
from bench_cic2018 import C2, VICTIMS, host_octet  # noqa: E402

SEED, N_BOOT = 1337, 1000
CALIB_FAR = 0.01            # pair-level false-alert rate the threshold is set for
CTU_NORMAL = ["ctu_normal--2017-04-18_win-normal.pcap", "ctu_normal--2017-04-19_win-normal.pcap",
              "ctu_normal--2017-04-28_normal.pcap", "ctu_normal--2017-04-30_win-normal.pcap",
              "ctu_normal--2017-05-01_normal.pcap", "ctu_normal--2017-05-02_kali-normal.pcap"]
CTU_BOTNET = ["ctu13--botnet-capture-20110810-neris.pcap", "ctu13--botnet-capture-20110811-neris.pcap",
              "ctu_botnet--botnet-capture-20110812-rbot.pcap", "ctu_botnet--botnet-capture-20110815-fast-flux.pcap",
              "ctu_botnet--capture.botnet2.infected.1.pcap"]
HIKARI = ["BRUTEFORCE_HTTPS__pcap__Sunday_2021-04-11_2154.pcap", "BRUTEFORCE_XML__pcap__Monday_2021-04-12_0611.pcap",
          "BRUTEFORCE_XML__pcap__Saturday_2021-04-17_0357.pcap", "Sunday_2022-04-10_2335_BRUTEFORCE_HTTPS_150s.pcap",
          "Monday_2022-04-11_0622_BRUTEFORCE_XML_150s.pcap"]
COLS = ("src", "sport", "dst", "dport", "sni", "start", "bytes", "dur")


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


# -- extraction -----------------------------------------------------------------------------------

def extract_one(job: tuple[str, str]) -> str:
    """Stream one pcap into <cache>/<sha>.npz (metadata only)."""
    path, cache = job
    from spectra.tools import stream_flows
    digest = sha256(path)
    out = os.path.join(cache, digest + ".npz")
    if os.path.isfile(out):
        return f"cached {os.path.basename(path)}"
    rows: list = []

    def keep(f) -> None:
        tls = f.tls
        rows.append((f.src_ip, f.src_port, f.dst_ip, f.dst_port, (tls.sni or "") if tls else "",
                     f.start_ts, f.bytes_fwd + f.bytes_bwd, f.duration))
    stream_flows(path, keep)
    cols = list(zip(*rows, strict=True)) if rows else [[] for _ in COLS]
    np.savez(out, src=np.array(cols[0], dtype=str), sport=np.array(cols[1], dtype=np.int32),
             dst=np.array(cols[2], dtype=str), dport=np.array(cols[3], dtype=np.int32),
             sni=np.array(cols[4], dtype=str), start=np.array(cols[5], dtype=np.float64),
             bytes=np.array(cols[6], dtype=np.int64), dur=np.array(cols[7], dtype=np.float64))
    return f"extracted {os.path.basename(path)}: {len(rows)} flows"


def cmd_extract(a) -> int:
    cache = os.path.join(a.root, ".beacon-cache")
    os.makedirs(cache, exist_ok=True)
    jobs = [(os.path.join(a.root, "datasets", n), cache) for n in CTU_NORMAL + CTU_BOTNET]
    jobs += [(os.path.join(a.root, "hikari", n), cache) for n in HIKARI]
    if a.only:
        jobs = [j for j in jobs if a.only in j[0]]
    with Pool(a.jobs) as pool:
        for msg in pool.imap_unordered(extract_one, jobs):
            print(msg, flush=True)
    return 0


def load_flows(path: str, cache: str) -> dict:
    d = np.load(os.path.join(cache, sha256(path) + ".npz"))
    return {k: d[k] for k in COLS}


def load_cic(path: str, root: str) -> dict:
    """CIC-2018 flows from the Phase B feature cache (tolerant reader; no SNI)."""
    d = np.load(os.path.join(root, "cic2018", ".feature-cache", sha256(path) + ".npz"), allow_pickle=True)
    meta, X = d["meta"].tolist(), d["X"]
    return {"src": np.array([m[0] for m in meta], dtype=str), "sport": np.array([m[1] for m in meta], dtype=np.int32),
            "dst": np.array([m[2] for m in meta], dtype=str), "dport": np.array([m[3] for m in meta], dtype=np.int32),
            "sni": np.full(len(meta), "", dtype=str), "start": np.array([m[4] for m in meta], dtype=np.float64),
            "bytes": X[:, 4].astype(np.int64), "dur": X[:, 0].astype(np.float64)}


# -- pair scoring ---------------------------------------------------------------------------------

def group_pairs(fl: dict) -> dict:
    """(src, dst) -> sorted [(start, bytes, dur)] plus first dst port / sni seen."""
    order = np.argsort(fl["start"], kind="stable")
    pairs: dict = {}
    for i in order.tolist():
        k = (str(fl["src"][i]), str(fl["dst"][i]))
        p = pairs.get(k)
        if p is None:
            p = pairs[k] = {"flows": [], "dport": int(fl["dport"][i]), "sni": str(fl["sni"][i])}
        p["flows"].append((float(fl["start"][i]), int(fl["bytes"][i]), float(fl["dur"][i])))
    return pairs


def pair_peak(flows: list, window: int = WINDOW, min_flows: int = MIN_FLOWS) -> dict | None:
    """Highest window score over the pair's life = what the streaming tracker would reach (threshold 0)."""
    best = None
    for end in range(min_flows, len(flows) + 1):
        s = score_pair(flows[max(0, end - window):end], min_flows)
        if s is not None and (best is None or s["score"] > best["score"]):
            best = s
    return best


def score_set(pairs: dict) -> list[dict]:
    rows = []
    for k, p in pairs.items():
        peak = pair_peak(p["flows"])
        rows.append({"pair": k, "n_flows": len(p["flows"]), "dport": p["dport"], "sni": p["sni"],
                     "score": peak["score"] if peak else 0.0, "scorable": peak is not None,
                     "median_gap_s": peak["median_gap_s"] if peak else None,
                     "components": {c: peak[c] for c in ("regularity", "jitter_ratio", "size_cv")} if peak else None})
    return rows


def streaming_check(pairs: dict, thr: float, sample: int = 25) -> int:
    """Count pairs where the product's BeaconTracker disagrees with the offline peak (should be 0)."""
    bad = 0
    for k, p in list(pairs.items())[:sample]:
        tr = BeaconTracker(threshold=thr)
        fired = False
        for t, b, d in p["flows"]:
            fired |= tr.observe({"src": f"{k[0]}:1", "dst": f"{k[1]}:2", "start_ts": t, "bytes": b, "duration": d}) is not None
        peak = pair_peak(p["flows"])
        bad += fired != (peak is not None and peak["score"] >= thr)
    return bad


def scorable_scores(rows: list[dict]) -> list[float]:
    return [r["score"] for r in rows if r["scorable"]]


def rate(v, rng) -> dict:
    v = np.asarray(v, float)
    if not len(v):
        return {"n": 0, "rate": None, "ci95": None}
    b = [v[rng.integers(0, len(v), len(v))].mean() for _ in range(N_BOOT)]
    return {"n": int(len(v)), "rate": round(float(v.mean()), 4),
            "ci95": [round(float(np.percentile(b, 2.5)), 4), round(float(np.percentile(b, 97.5)), 4)]}


def evaluate(name: str, pos: list[dict], neg: list[dict], thr: float, rng) -> dict:
    ps, ns = scorable_scores(pos), scorable_scores(neg)
    out = {"dataset": name, "positive_pairs": len(pos), "positive_pairs_scorable": len(ps),
           "negative_pairs": len(neg), "negative_pairs_scorable": len(ns), "threshold": thr}
    out["ranking_scorable_pairs"] = score_metrics(ps, ns, N_BOOT, SEED) if ps and ns else None
    out["at_threshold"] = {
        "recall_of_scorable_positive_pairs": rate([s >= thr for s in ps], rng),
        "recall_of_all_positive_pairs": rate([r["score"] >= thr for r in pos], rng),
        "false_alert_rate_scorable_negative_pairs": rate([s >= thr for s in ns], rng),
        "false_alert_rate_all_negative_pairs": rate([r["score"] >= thr for r in neg], rng),
    }
    out["positive_score_quantiles_p10_p50_p90"] = ([round(float(x), 4) for x in np.percentile(ps, [10, 50, 90])] if ps else None)
    out["negative_score_quantiles_p50_p90_p99"] = ([round(float(x), 4) for x in np.percentile(ns, [50, 90, 99])] if ns else None)
    for comp in ("regularity", "jitter_ratio", "size_cv"):     # ablation of the score's parts - reporting only, no re-tuning
        pc = [r["components"][comp] for r in pos if r["scorable"]]
        nc = [r["components"][comp] for r in neg if r["scorable"]]
        if pc and nc:
            sign = -1.0 if comp != "regularity" else 1.0
            sm = score_metrics([sign * x for x in pc], [sign * x for x in nc], N_BOOT, SEED)
            out.setdefault("component_roc_auc", {})[comp] = {"roc_auc": sm["roc_auc"], "ci95": sm["roc_auc_ci95"]}
    out["top_false_alert_pairs"] = [
        {"pair": list(r["pair"]), "dst_port": r["dport"], "sni": r["sni"], "flows": r["n_flows"],
         "median_gap_s": r["median_gap_s"], "score": r["score"]}
        for r in sorted((r for r in neg if r["score"] >= thr), key=lambda r: -r["score"])[:15]]
    return out


def synthetic_jitter(thr: float) -> dict:
    """SYNTHETIC beacons (labelled as such): detection rate vs gap jitter at the fixed threshold."""
    rng = np.random.default_rng(SEED)
    res = {}
    for jit in (0.0, 0.1, 0.2, 0.3, 0.5, 0.8):
        hit = 0
        for _ in range(200):
            gaps = 30.0 * (1.0 + rng.uniform(-jit, jit, 63))
            starts = np.concatenate([[0.0], np.cumsum(gaps)])
            sizes = rng.normal(600, 60, 64).clip(50)
            s = score_pair([(float(t), float(b), 0.2) for t, b in zip(starts, sizes, strict=True)])
            hit += s is not None and s["score"] >= thr
        res[f"jitter_{int(jit * 100)}pct_of_30s_period"] = {"trials": 200, "detected": hit}
    return {"kind": "SYNTHETIC: 64 flows, 30 s period, uniform jitter, sizes ~N(600, 60); not network data", "results": res}


# -- datasets -------------------------------------------------------------------------------------

def cic_sets(root: str) -> dict:
    base = os.path.join(root, "cic2018")
    fri = sorted(p for p in glob.glob(os.path.join(base, "Friday-02-03-2018__*")) if not p.endswith(".log"))
    victims = [p for p in fri if host_octet(os.path.basename(p)) in VICTIMS and "EC2AMAZ-O4EL3NG" in p]
    others = [p for p in fri if p not in victims]
    pos, neg_v, neg_calib, neg_test = [], [], [], []
    for p in victims:
        for r in score_set(group_pairs(load_cic(p, root))):
            if C2 in r["pair"]:
                pos.append(r)
            else:
                neg_v.append(r)
    for i, p in enumerate(others):
        rows = [r for r in score_set(group_pairs(load_cic(p, root))) if C2 not in r["pair"]]
        (neg_calib if i % 2 == 0 else neg_test).extend(rows)
    return {"pos": pos, "neg_victim_other": neg_v, "neg_calib": neg_calib, "neg_test": neg_test,
            "captures": {"victims": len(victims), "others": len(others), "calibration": (len(others) + 1) // 2}}


def ctu_sets(root: str) -> dict:
    cache, d = os.path.join(root, ".beacon-cache"), os.path.join(root, "datasets")
    pos, neg = [], []
    for n in CTU_BOTNET:
        pos += score_set(group_pairs(load_flows(os.path.join(d, n), cache)))
    for n in CTU_NORMAL:
        neg += score_set(group_pairs(load_flows(os.path.join(d, n), cache)))
    return {"pos": pos, "neg": neg}


def hikari_sets(root: str) -> dict:
    cache, d = os.path.join(root, ".beacon-cache"), os.path.join(root, "hikari")
    flows = {n: load_flows(os.path.join(d, n), cache) for n in HIKARI}
    want = set()
    for fl in flows.values():
        for s, sp, t, tp in zip(fl["src"].tolist(), fl["sport"].tolist(), fl["dst"].tolist(), fl["dport"].tolist(), strict=True):
            want.add((s, sp, t, tp))
    lab: dict = {}
    for name in ("ALLFLOWMETER_HIKARI2021.csv", "labels2022.csv"):          # streamed; only tuples we extracted are kept
        with open(os.path.join(d, name), encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                k = (r["originh"], int(r["originp"]), r["responh"], int(r["responp"]))
                if k in want:
                    lab.setdefault(k, set()).add(int(r["Label"]))
                elif (k[2], k[3], k[0], k[1]) in want:
                    lab.setdefault((k[2], k[3], k[0], k[1]), set()).add(int(r["Label"]))
    pos, neg, unl = [], [], 0
    for fl in flows.values():
        votes: dict = {}
        for k in (zip(fl["src"].tolist(), fl["sport"].tolist(), fl["dst"].tolist(), fl["dport"].tolist(), strict=True)):
            ls = lab.get(k)
            if ls and len(ls) == 1:
                votes.setdefault((k[0], k[2]), []).append(next(iter(ls)))
        for r in score_set(group_pairs(fl)):
            v = votes.get(r["pair"])
            if not v:
                unl += 1
            elif sum(v) * 2 > len(v):
                pos.append(r)
            elif sum(v) == 0:
                neg.append(r)
            else:
                unl += 1            # mixed pair (some attack, no majority): excluded and counted
    return {"pos": pos, "neg": neg, "unlabelled_or_mixed_pairs": unl}


def cmd_run(a) -> int:
    rng = np.random.default_rng(SEED)
    cic = cic_sets(a.root)
    calib = scorable_scores(cic["neg_calib"])
    if len(calib) < 100:
        print("too few scorable calibration pairs", file=sys.stderr)
        return 3
    thr = round(float(np.quantile(calib, 1.0 - CALIB_FAR, method="higher")), 4)
    rep = {
        "kind": "REAL captures; pair-level labels (see caveats); SYNTHETIC rows are marked",
        "environment": {"commit": git("rev-parse", "--short", "HEAD"), "python": platform.python_version(),
                        "numpy": np.__version__, "seed": SEED, "bootstrap": N_BOOT},
        "detector": {"min_flows": MIN_FLOWS, "window": WINDOW, "score": "mean(regularity, 1-min(1,MAD/median), 1-min(1,size cv))",
                     "threshold_rule": f"{1.0 - CALIB_FAR:.2f} quantile of scorable benign pair scores of the CIC-2018 "
                                       "calibration captures (every even-indexed non-victim capture); no positive label used",
                     "threshold": thr, "calibration_scorable_pairs": len(calib)},
        "cic2018_captures": cic["captures"],
        "cic2018_test": evaluate("CIC-2018 Bot day (10 C2 pairs vs held-out non-victim captures)", cic["pos"], cic["neg_test"], thr, rng),
        "cic2018_vs_victim_other_pairs": evaluate("CIC-2018: C2 pairs vs the victims' other pairs (ambiguous negatives)",
                                                  cic["pos"], cic["neg_victim_other"], thr, rng),
        "cic2018_calibration_set_far": rate([s >= thr for s in calib], rng),
    }
    rep["ctu"] = evaluate("CTU botnet captures (all pairs of the 5 captures) vs CTU-Normal pairs", **ctu_sets(a.root), thr=thr, rng=rng)
    hk = hikari_sets(a.root)
    rep["hikari"] = evaluate("HIKARI (pairs by majority 4-tuple label) ", hk["pos"], hk["neg"], thr, rng)
    rep["hikari"]["pairs_unlabelled_or_mixed_excluded"] = hk["unlabelled_or_mixed_pairs"]
    rep["synthetic_jitter"] = synthetic_jitter(thr)
    rep["caveats"] = [
        "Pair resampling in the bootstrap ignores that pairs of one host are correlated; intervals are optimistic.",
        "CIC-2018 has 10 positive pairs; CTU and HIKARI labels are pcap-level / majority-of-flows, not per-pair ground truth.",
        "Threshold comes from CIC-2018 benign pairs of one AWS lab; other networks will have different periodic benign traffic.",
        "A pair alerts if ANY trailing 64-flow window crosses the threshold, so long-lived busy benign pairs get many chances."]
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=2, default=str)
    for k in ("cic2018_test", "ctu", "hikari"):
        r = rep[k]
        print(k, "pos", r["positive_pairs"], f"(scorable {r['positive_pairs_scorable']})", "neg", r["negative_pairs"],
              f"(scorable {r['negative_pairs_scorable']})", "auc", (r["ranking_scorable_pairs"] or {}).get("roc_auc"),
              "recall", r["at_threshold"]["recall_of_scorable_positive_pairs"]["rate"],
              "far", r["at_threshold"]["false_alert_rate_scorable_negative_pairs"]["rate"])
    print("threshold", thr, "wrote", a.out)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("extract")
    e.add_argument("--root", required=True)
    e.add_argument("--jobs", type=int, default=3)
    e.add_argument("--only", default=None)
    r = sub.add_parser("run")
    r.add_argument("--root", required=True)
    r.add_argument("--out", required=True)
    a = ap.parse_args()
    a.root = os.path.expanduser(a.root)
    return cmd_extract(a) if a.cmd == "extract" else cmd_run(a)


if __name__ == "__main__":
    sys.exit(main())
