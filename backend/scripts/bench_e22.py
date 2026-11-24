#!/usr/bin/env python
"""E22: corroborated beaconing v3 (ci/prereg/e22.json) - calibration and every evaluation set, one code path.

    cd backend
    python scripts/bench_e22.py calibrate --root ~/Projects/Spectra_bench_data --out <json>
    python scripts/bench_e22.py ctu   --root ~/Projects/Spectra_bench_data --tau <tau_I> --out <json>
    python scripts/bench_e22.py hikari --root ~/Projects/Spectra_bench_data --tau <tau_I> --out <json>
    python scripts/bench_e22.py setc  --run-dir <setc run dir> --tau <tau_I> --out <json>
    python scripts/bench_e22.py own   --pcap-dir <hourly pcaps> --tau <tau_I> --out <counts json> --detail <private json>

Metadata only: flows come from Spectra's own parser; records keep addresses, times, byte counts, SNI and JA3/JA4, never payload.
Every set is scored by :class:`spectra.modules.corr.hostctx.CorroboratedBeacon` with the preregistered constants.  For each set
the same rows give four variants: v2a1 alone (B), B and not P, B and (R or F or I), and the fused rule (B and not P and (R or F or
I)), with recall and false-alert rate (95 % bootstrap CIs, 1000 resamples, seed 1337) at pair and host level.
"""
from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import ipaddress
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from spectra.capture import open_source  # noqa: E402
from spectra.eval.metrics import bootstrap_ci, score_metrics  # noqa: E402
from spectra.features.extractor import flows_to_matrix  # noqa: E402
from spectra.ml.model import SpectraDetector  # noqa: E402
from spectra.modules.corr.beacon import INTERNAL_NETS  # noqa: E402
from spectra.modules.corr.hostctx import CorroboratedBeacon  # noqa: E402
from spectra.parse.flow import FlowTracker  # noqa: E402

MIN_FLOWS, SEED, BOOT = 20, 1337, 1000
KEEP = ("src", "dst", "start_ts", "duration", "bytes_fwd", "sni", "ja3", "ja4")
CTU_INSIDE = "147.32.0.0/16"
VARIANTS = {
    "v2a1_alone": lambda e: e["B"],
    "B_and_not_P": lambda e: e["B"] and not e["P"],
    "B_and_corroboration": lambda e: e["B"] and e["corroborated"],
    "fused_v3": lambda e: e["alert"],
}


# -- data ---------------------------------------------------------------------------------------------------------------

def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def git_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=HERE, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return os.environ.get("E22_GIT_COMMIT", "unknown")


def extract(path: str, cache: str) -> dict:
    """Metadata records + the 39-feature matrix of one capture (a cut-off tail is tolerated), cached by SHA-256."""
    digest = sha256(path)
    js, npz = os.path.join(cache, digest + ".e22.json"), os.path.join(cache, digest + ".e22.npz")
    if os.path.isfile(js) and os.path.isfile(npz):
        return {"sha256": digest, "recs": json.load(open(js)), "X": np.load(npz)["X"], "file": os.path.basename(path), "cut": None}
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
    recs = [{k: r.get(k) for k in KEEP} for r in (f.record() for f in out)]
    X = flows_to_matrix(out) if out else np.empty((0, 39))
    os.makedirs(cache, exist_ok=True)
    json.dump(recs, open(js, "w"))
    np.savez(npz, X=X)
    return {"sha256": digest, "recs": recs, "X": X, "file": os.path.basename(path), "cut": cut}


def train_detector(mats: list) -> SpectraDetector:
    det = SpectraDetector(contamination=0.02, random_state=42)
    det.fit(np.vstack(mats))
    return det


def host_of(addr: str) -> str:
    return addr.rsplit(":", 1)[0]


def pair_key(r: dict) -> tuple[str, str]:
    return host_of(r["src"]), (r["sni"] or "").lower().rstrip(".") or host_of(r["dst"])


def run(stream: list[tuple[dict, bool]], learn_until: float, tau: float | None, nets) -> CorroboratedBeacon:
    cb = CorroboratedBeacon(learn_until, tau, internal_nets=nets)
    for r, flag in sorted(stream, key=lambda x: x[0]["start_ts"]):
        cb.observe(r, flag)
    return cb


def rows_of(cb: CorroboratedBeacon, tag: str) -> list[dict]:
    out = []
    for e in cb.results(MIN_FLOWS):
        st = cb.beacon.pairs.get(e["pair"])
        out.append({"set": tag, "pair": list(e["pair"]), "flows_after_window": e["flows_after_window"],
                    "dst_ips": sorted(st["ips"]) if st else [], "B": e["B"], "B_score": e["B_score"],
                    "components": e["components"], "P": e["P"], "R": e["R"], "F": e["F"], "I": e["I"],
                    "corroborated": e["corroborated"], "alert": e["alert"], "fused_score": e["fused_score"]})
    return out


# -- metrics ------------------------------------------------------------------------------------------------------------

def _mean(xs):
    return sum(xs) / len(xs) if xs else None


def binary(pos: list[int], neg: list[int]) -> dict:
    rec = bootstrap_ci(pos, neg, lambda p, n: _mean(p), BOOT, SEED) if pos else None
    fpr = bootstrap_ci(neg, pos or [0], lambda p, n: _mean(p), BOOT, SEED) if neg else None
    return {"recall": _mean(pos), "recall_ci95": [rec["lo"], rec["hi"]] if rec else None, "n_pos": len(pos),
            "false_alert_rate": _mean(neg), "false_alert_rate_ci95": [fpr["lo"], fpr["hi"]] if fpr else None,
            "n_neg": len(neg), "false_alerts": sum(neg)}


def evaluate(pos_rows: list[dict | None], neg_rows: list[dict], pos_hosts: dict, neg_hosts: dict) -> dict:
    """pos_rows: one entry per labelled positive (None = absent / below 20 flows = miss)."""
    res = {}
    for name, fn in VARIANTS.items():
        p = [int(bool(r) and fn(r)) for r in pos_rows]
        n = [int(fn(r)) for r in neg_rows]
        hp = [int(any(fn(r) for r in rs if r)) for rs in pos_hosts.values()]
        hn = [int(any(fn(r) for r in rs)) for rs in neg_hosts.values()]
        res[name] = {"pair": binary(p, n), "host": binary(hp, hn)}
    fused_pos = [r["fused_score"] if r else 0.0 for r in pos_rows]
    res["fused_v3"]["pair"]["ranking"] = score_metrics(fused_pos, [r["fused_score"] for r in neg_rows], BOOT, SEED)
    res["v2a1_alone"]["pair"]["ranking"] = score_metrics([r["B_score"] if r else 0.0 for r in pos_rows],
                                                         [r["B_score"] for r in neg_rows], BOOT, SEED)
    def fires(r, s):
        return r[s] if isinstance(r[s], bool) else r[s]["fires"]

    sig = {s: {"positives_firing": sum(1 for r in pos_rows if r and fires(r, s)),
               "negatives_firing": sum(1 for r in neg_rows if fires(r, s))} for s in ("P", "R", "F", "I")}
    res["signals_fire_counts"] = sig
    return res


def gate_check(res: dict) -> dict:
    p = res["fused_v3"]["pair"]
    ok = p["recall"] is not None and p["recall"] >= 0.30 and p["false_alert_rate"] is not None and p["false_alert_rate"] <= 0.01
    return {"fused_recall": p["recall"], "fused_false_alert_rate": p["false_alert_rate"], "recall_ge_0.30_at_far_le_0.01": ok}


# -- calibration (tau_I) ------------------------------------------------------------------------------------------------

DEV_TRAIN = ["ctu_normal--2017-04-18_win-normal.pcap", "ctu_normal--2017-04-19_win-normal.pcap",
             "ctu_normal--2017-04-28_normal.pcap", "ctu_normal--2017-04-30_win-normal.pcap"]
DEV_CAL = ["ctu_normal--2017-05-01_normal.pcap", "ctu_normal--2017-05-02_kali-normal.pcap"]


def ctu_detector(root: str) -> tuple[SpectraDetector, dict]:
    ds, cache = os.path.join(root, "datasets"), os.path.join(root, "e22", ".cache")
    caps = [extract(os.path.join(ds, n), cache) for n in DEV_TRAIN]
    return train_detector([c["X"] for c in caps]), {c["file"]: c["sha256"] for c in caps}


def cmd_calibrate(a) -> dict:
    det, train_hashes = ctu_detector(a.root)
    shares, cal_hashes = [], {}
    for n in DEV_CAL:
        c = extract(os.path.join(a.root, "datasets", n), os.path.join(a.root, "e22", ".cache"))
        cal_hashes[n] = c["sha256"]
        flags = det.predict(c["X"]) if len(c["X"]) else []
        t0 = min(r["start_ts"] for r in c["recs"])
        # e22 amendment 2: the calibration captures are shorter than 1 h, so tau_I uses every flow (no learning window)
        cb = run(list(zip(c["recs"], [bool(f) for f in flags], strict=True)), t0, None, INTERNAL_NETS)
        for pair in [e["pair"] for e in cb.results(MIN_FLOWS)]:
            s = cb.ctx.if_share(pair)
            if s is not None:
                shares.append(s)
    tau = float(np.quantile(shares, 0.99)) if shares else None
    return {"benchmark": "e22 tau_I calibration (dev benign only, no positive label)", "rule": "0.99 quantile of the per-pair IF flag share over all flows of the calibration captures (e22 amendment 2)",
            "detector_train": train_hashes, "calibration_captures": cal_hashes, "pairs": len(shares),
            "share_quantiles": {q: float(np.quantile(shares, q)) for q in (0.5, 0.9, 0.95, 0.99)} if shares else None,
            "tau_I": tau}


# -- G1: CTU-13 fresh ---------------------------------------------------------------------------------------------------

G1_BOTNETS = {   # directory -> (pcaps, label file)
    "Botnet-45": (["botnet-capture-20110815-rbot-dos-icmp.pcap", "botnet-capture-20110815-rbot-dos.pcap"], "capture20110815.binetflow.2format"),
    "Botnet-47": (["botnet-capture-20110816-donbot.pcap"], "capture20110816.binetflow.2format"),
    "Botnet-48": (["botnet-capture-20110816-sogou.pcap"], "capture20110816-2.binetflow.2format"),
    "Botnet-49": (["botnet-capture-20110816-qvod.pcap"], "capture20110816-3.binetflow.2format"),
    "Botnet-50": (["botnet-capture-20110817-bot.pcap"], "capture20110817.binetflow.2format"),
    "Botnet-53": (["botnet-capture-20110819-bot.pcap"], "capture20110819.binetflow.2format"),
    "Botnet-54": (["botnet-capture-20110815-fast-flux-2.pcap"], "capture20110815-3.binetflow.2format"),
}
G1_NORMALS = {"CTU-Normal-7": "2013-12-17_capture1.pcap", "CTU-Normal-9": "2016-09-13_win16.pcap",
              "CTU-Normal-13": "2017-07-03_capture-win2.pcap", "CTU-Normal-14": "2017-07-23_capture-winFull.pcap",
              "CTU-Normal-18": "2017-09-05_capture-win4.pcap", "CTU-Normal-25": "2017-04-25_win-normal.pcap",
              "CTU-Normal-27": "2017_04_30-normal.pcap", "CTU-Normal-29": "2017-05-01_normal.pcap",
              "CTU-Normal-33": "capture-new-Windows-7-Full.pcap"}


def c2_of(label_path: str) -> tuple[dict, dict]:
    """(inside host -> C2 addresses) from a Stratosphere binetflow file (label contains 'CC'); text only (e21 amendment 2 rule)."""
    inside = ipaddress.ip_network(CTU_INSIDE)
    out: dict[str, set] = defaultdict(set)
    counts = Counter()
    with open(label_path, newline="", encoding="utf-8", errors="replace") as fh:
        rd = csv.reader(fh)
        head = next(rd)
        i_s, i_d, i_l = head.index("SrcAddr"), head.index("DstAddr"), head.index("Label")
        for row in rd:
            counts["rows"] += 1
            if "CC" not in row[i_l]:
                continue
            counts["cc_rows"] += 1
            try:
                ends = [ip for ip in (row[i_s], row[i_d]) if ipaddress.ip_address(ip) in inside]
            except ValueError:
                counts["cc_rows_bad_address"] += 1
                continue
            if len(ends) != 1:
                counts["cc_rows_unoriented"] += 1
                continue
            out[ends[0]].add(row[i_d] if ends[0] == row[i_s] else row[i_s])
    return out, dict(counts)


def capture_rows(c: dict, det, tau, nets, tag: str, learn_s: float = 3600.0):
    flags = det.predict(c["X"]) if len(c["X"]) else []
    t0 = min(r["start_ts"] for r in c["recs"])
    cb = run(list(zip(c["recs"], [bool(f) for f in flags], strict=True)), t0 + learn_s, tau, nets)
    return cb, rows_of(cb, tag), t0 + learn_s


def cmd_ctu(a) -> dict:
    root = a.root
    det, train_hashes = ctu_detector(root)
    cache = os.path.join(root, "e22", ".cache")
    pos_rows, neg_rows, pos_hosts, neg_hosts, info, hashes, botnet_non_c2 = [], [], defaultdict(list), {}, {}, {}, []
    nets = list(INTERNAL_NETS) + [CTU_INSIDE]
    for d, (pcaps, lab) in G1_BOTNETS.items():
        lp = os.path.join(root, "e22", "ctu13", d, lab)
        c2, lc = c2_of(lp)
        hashes[f"{d}/{lab}"] = sha256(lp)
        for pc in pcaps:
            c = extract(os.path.join(root, "e22", "ctu13", d, pc), cache)
            hashes[f"{d}/{pc}"] = c["sha256"]
            cb, rows, lu = capture_rows(c, det, a.tau, nets, f"{d}/{pc}")
            by_pair = {tuple(r["pair"]): r for r in rows}
            # labelled universe from Spectra's own flows: (inside host, key) whose destination IP is a C2 address of that host
            uni = Counter(pair_key(r) for r in c["recs"]
                          if r["start_ts"] >= lu and host_of(r["dst"]) in c2.get(host_of(r["src"]), ()))
            positives = sorted(k for k, n in uni.items() if n >= MIN_FLOWS)
            for k in positives:
                r = by_pair.get(k)
                pos_rows.append(r)
                pos_hosts[(d, k[0])].append(r)
            botnet_non_c2 += [r for k, r in by_pair.items() if k not in set(positives)]
            info[f"{d}/{pc}"] = {"flows": len(c["recs"]), "eligible_pairs": len(rows), "c2_pairs_ge_20": len(positives),
                                 "c2_pairs_without_eligible_row": sum(1 for k in positives if k not in by_pair),
                                 "learned_periodic": len(cb.learner.learned), "label_counts": lc}
    for d, pc in G1_NORMALS.items():
        c = extract(os.path.join(root, "e22", "ctu_normal", d, pc), cache)
        hashes[f"{d}/{pc}"] = c["sha256"]
        cb, rows, _ = capture_rows(c, det, a.tau, list(INTERNAL_NETS), f"{d}/{pc}")
        neg_rows += rows
        for r in rows:
            neg_hosts.setdefault((d, r["pair"][0]), []).append(r)
        info[f"{d}/{pc}"] = {"flows": len(c["recs"]), "eligible_pairs": len(rows), "learned_periodic": len(cb.learner.learned)}
    res = evaluate(pos_rows, neg_rows, pos_hosts, neg_hosts)
    return {"benchmark": "e22 G1: CTU-13 fresh scenarios vs fresh CTU-Normal (pair and host level)", "tau_I": a.tau,
            "detector_train": train_hashes, "file_sha256": hashes, "captures": info, "results": res, "gate_G1": gate_check(res),
            "botnet_non_c2_pairs": {name: sum(1 for r in botnet_non_c2 if fn(r)) for name, fn in VARIANTS.items()} | {"n": len(botnet_non_c2)},
            "positives": [r or {"missing": True} for r in pos_rows],
            "negatives_alerting": [r for r in neg_rows if r["alert"]]}


# -- G2: HIKARI ---------------------------------------------------------------------------------------------------------

H_TRAIN = ["Sunday_2021-04-11_2154.pcap", "Monday_2021-04-12_0611.pcap"]
H_TEST = ["Saturday_2021-04-17_0357.pcap", "Sunday_2022-04-10_2335_BRUTEFORCE_HTTPS_150s.pcap", "Monday_2022-04-11_0622_BRUTEFORCE_XML_150s.pcap"]


def hikari_labels(root: str) -> dict:
    seen: dict[tuple, set] = {}
    for f in ("ALLFLOWMETER_HIKARI2021.csv", "ALLFLOWMETER_HIKARI2022.csv"):
        for r in csv.DictReader(open(os.path.join(root, "hikari", f), encoding="utf-8")):
            seen.setdefault((r["originh"], int(r["originp"]), r["responh"], int(r["responp"])), set()).add(int(r["Label"]))
    return {k: next(iter(v)) for k, v in seen.items() if len(v) == 1}


def tuple_label(r: dict, labels: dict):
    s, sp = r["src"].rsplit(":", 1)
    d, dp = r["dst"].rsplit(":", 1)
    t = (s, int(sp), d, int(dp))
    v = labels.get(t)
    return v if v is not None else labels.get((d, int(dp), s, int(sp)))


def cmd_hikari(a) -> dict:
    root, cache = a.root, os.path.join(a.root, "e22", ".cache")
    labels = hikari_labels(root)
    train = [extract(os.path.join(root, "hikari", n), cache) for n in H_TRAIN]
    test = [extract(os.path.join(root, "hikari", n), cache) for n in H_TEST]
    tl = [[tuple_label(r, labels) for r in c["recs"]] for c in train]
    det = train_detector([c["X"][np.array([lab == 0 for lab in ls], dtype=bool)] for c, ls in zip(train, tl, strict=True)])
    learn_until = max(r["start_ts"] for c in train for r in c["recs"]) + 1e-6
    stream, lab_of = [], {}
    for c in train + test:
        flags = det.predict(c["X"]) if len(c["X"]) else []
        stream += list(zip(c["recs"], [bool(f) for f in flags], strict=True))
    cb = run(stream, learn_until, a.tau, list(INTERNAL_NETS))
    rows = {tuple(r["pair"]): r for r in rows_of(cb, "hikari")}
    for c in test:
        for r in c["recs"]:
            lab = tuple_label(r, labels)
            if lab is not None:
                lab_of.setdefault(pair_key(r), Counter())[lab] += 1
    attack = {k for k, c in lab_of.items() if c[1] > c[0] and c[1] >= MIN_FLOWS}
    benign = {k for k, c in lab_of.items() if c[1] == 0}
    pos_rows = [rows.get(k) for k in sorted(attack)]
    neg_rows = [r for k, r in rows.items() if k in benign]
    pos_hosts, neg_hosts = defaultdict(list), defaultdict(list)
    for k in sorted(attack):
        pos_hosts[k[0]].append(rows.get(k))
    for r in neg_rows:
        if r["pair"][0] not in {k[0] for k in attack}:
            neg_hosts[r["pair"][0]].append(r)
    res = evaluate(pos_rows, neg_rows, pos_hosts, neg_hosts)
    return {"benchmark": "e22 G2: HIKARI-2021/2022 (pair and host level)", "tau_I": a.tau,
            "file_sha256": {c["file"]: c["sha256"] for c in train + test}, "learn_until": learn_until,
            "labelled_pairs": len(lab_of), "attack_pairs_ge_20": len(attack), "attack_pairs_without_eligible_row": sum(1 for k in attack if k not in rows),
            "mixed_pairs_dropped": sum(1 for k, c in lab_of.items() if c[1] and c[0] and k not in attack),
            "eligible_pairs": len(rows), "results": res, "gate_G2": gate_check(res),
            "positives": [r or {"missing": True} for r in pos_rows]}


# -- H1: simulator set C ------------------------------------------------------------------------------------------------

def cmd_setc(a) -> dict:
    man = json.load(open(os.path.join(a.run_dir, "manifest.json")))
    cache = os.path.join(a.run_dir, ".e22-cache")
    caps = [extract(p, cache) for p in sorted(glob.glob(os.path.join(a.run_dir, "host-*.pcap")))]
    t0 = min(r["start_ts"] for c in caps for r in c["recs"])
    learn_until = t0 + man["learn_s"]
    train = [c["X"][np.array([r["start_ts"] < learn_until for r in c["recs"]], dtype=bool)] for c in caps]
    det = train_detector([x for x in train if len(x)])
    stream = []
    for c in caps:
        flags = det.predict(c["X"]) if len(c["X"]) else []
        stream += list(zip(c["recs"], [bool(f) for f in flags], strict=True))
    cb = run(stream, learn_until, a.tau, ["203.0.113.128/25"])
    rows = {tuple(r["pair"]): r for r in rows_of(cb, "setc")}
    beacons = [(h["ip"], p) for h in man["hosts"] for p in h["profiles"] if p["class"] == "beacon"]
    gated = [(ip, p) for ip, p in beacons if p["jitter"] <= 50]
    pos_rows = [rows.get((ip, p["sni"])) for ip, p in gated]
    pos_keys = {(ip, p["sni"]) for ip, p in beacons}
    neg_rows = [r for k, r in rows.items() if k not in pos_keys]
    pos_hosts, neg_hosts = defaultdict(list), defaultdict(list)
    for (ip, _p), r in zip(gated, pos_rows, strict=True):
        pos_hosts[ip].append(r)
    for r in neg_rows:
        neg_hosts[r["pair"][0]].append(r)
    res = evaluate(pos_rows, neg_rows, pos_hosts, neg_hosts)
    curve = {}
    for ip, p in beacons:
        r = rows.get((ip, p["sni"]))
        cell = f"{p['interval']}s/{p['jitter']}%"
        curve.setdefault(cell, []).append(bool(r and r["alert"]))
    cls = {}
    for h in man["hosts"]:
        for p in h["profiles"]:
            if p["class"] == "beacon":
                continue
            for sni in (p["sni"] if isinstance(p["sni"], list) else [p["sni"]]):
                r = rows.get((h["ip"], sni))
                if r:
                    c = cls.setdefault(p["class"], {"eligible": 0, "v2a1": 0, "fused": 0})
                    c["eligible"] += 1
                    c["v2a1"] += int(r["B"])
                    c["fused"] += int(r["alert"])
    return {"benchmark": "e22 H1: simulator set C (pair and host level)", "run_id": man.get("run_id"), "tau_I": a.tau,
            "file_sha256": {c["file"]: c["sha256"] for c in caps}, "learn_until": learn_until,
            "learned_periodic": sorted(cb.learner.learned), "results": res, "gate_H1": gate_check(res),
            "fused_hits_by_cell": {k: f"{sum(v)}/{len(v)}" for k, v in sorted(curve.items())},
            "negatives_by_class": cls, "positives": [r or {"missing": True} for r in pos_rows]}


# -- H2: own network ----------------------------------------------------------------------------------------------------

def cmd_own(a) -> tuple[dict, dict]:
    files = sorted(glob.glob(os.path.join(a.pcap_dir, "*.pcap")))
    cache = a.cache or os.path.join(a.pcap_dir, ".e22-cache")
    caps = [extract(p, cache) for p in files]
    recs = [r for c in caps for r in c["recs"]]
    t0 = min(r["start_ts"] for r in recs)
    learn_until = t0 + 86400.0
    X = np.vstack([c["X"] for c in caps])
    det = train_detector([X[np.array([r["start_ts"] < learn_until for r in recs], dtype=bool)]])
    fl = det.predict(X)
    cb = CorroboratedBeacon(learn_until, a.tau, internal_nets=INTERNAL_NETS)
    days, detail, per_day = [], [], defaultdict(Counter)
    order = sorted(range(len(recs)), key=lambda i: recs[i]["start_ts"])
    boundary = learn_until + 86400.0

    def close_day(day: int):
        elig = [cb.evaluate(p) for p, n in per_day[day].items() if n >= MIN_FLOWS]
        alerts = [e for e in elig if e["alert"]]
        days.append({"day": day, "pairs_ge_20_flows": len(elig), "v2a1_alone": sum(e["B"] for e in elig),
                     "fused_alerts": len(alerts), "P_suppressed": sum(1 for e in elig if e["B"] and e["P"]),
                     "learned_periodic": len(cb.learner.learned)})
        detail.append({"day": day, "alerting": [{"dst": e["pair"][1], "score": e["B_score"], "R": e["R"]["fires"],
                                                 "F": e["F"]["fires"], "I": e["I"]["fires"]} for e in alerts]})

    day = 2
    for i in order:
        r = recs[i]
        while r["start_ts"] >= boundary:
            close_day(day)
            day, boundary = day + 1, boundary + 86400.0
        cb.observe(r, bool(fl[i]))
        if r["start_ts"] >= learn_until:
            k = pair_key(r)
            if k in cb.after:
                per_day[day][k] += 1
    close_day(day)
    test = [d for d in days if d["day"] in (2, 3)]
    mean = _mean([d["fused_alerts"] for d in test])
    out = {"benchmark": "e22 H2: own network, fused pair alerts per day", "tau_I": a.tau, "files": len(files),
           "flows": len(recs), "days": days, "mean_fused_alerts_days_2_3": mean, "budget": 1.0,
           "budget_met": mean is not None and mean <= 1.0, "note": "counts only; destinations are in the private detail file"}
    return out, {"days": detail}


# -- main ---------------------------------------------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("calibrate", "ctu", "hikari"):
        p = sub.add_parser(name)
        p.add_argument("--root", required=True)
        p.add_argument("--out", required=True)
        if name != "calibrate":
            p.add_argument("--tau", type=float, required=True)
    p = sub.add_parser("setc")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--tau", type=float, required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("own")
    p.add_argument("--pcap-dir", required=True)
    p.add_argument("--tau", type=float, required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--detail", required=True)
    p.add_argument("--cache", default=None)
    a = ap.parse_args()
    if getattr(a, "root", None):
        a.root = os.path.expanduser(a.root)
    detail = None
    if a.cmd == "calibrate":
        out = cmd_calibrate(a)
    elif a.cmd == "ctu":
        out = cmd_ctu(a)
    elif a.cmd == "hikari":
        out = cmd_hikari(a)
    elif a.cmd == "setc":
        out = cmd_setc(a)
    else:
        out, detail = cmd_own(a)
    out = {"prereg": "ci/prereg/e22.json", "git_commit": git_commit(), "min_flows": MIN_FLOWS, "bootstrap": BOOT, "seed": SEED, **out}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(out, open(a.out, "w"), indent=1, default=list)
    if detail is not None:
        json.dump(detail, open(a.detail, "w"), indent=1)
    summary = {k: out[k] for k in out if k.startswith("gate") or k in ("tau_I", "budget_met", "mean_fused_alerts_days_2_3")}
    if "results" in out:
        summary["variants"] = {v: {lvl: {m: out["results"][v][lvl][m] for m in ("recall", "false_alert_rate", "n_pos", "n_neg")}
                                    for lvl in ("pair", "host")} for v in VARIANTS}
    print(json.dumps(summary, indent=1), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
