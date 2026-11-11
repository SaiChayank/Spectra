#!/usr/bin/env python
"""Spectra-Bench E0: real RITA v5.1.2 vs Spectra's pair regularity on the CIC-2018 Bot day (docs/35 §3).

    cd backend
    .venv/bin/python scripts/bench_rita_cic.py --root ~/Projects/Spectra_bench_data --out <json>

Needs: Zeek logs per victim capture in <root>/zeek/cic-out (zeek/run_zeek_cic.sh) and the benchmark RITA stack in <root>/tools/rita
(docker compose, internal network; ClickHouse queried directly).  Pairs = (victim host, external IP) among the ten Bot-victim captures,
exactly as in bench_gateb stage 9D; positives = pairs with the C2 address 18.219.211.138 (ten at most), negatives = every other pair.
Evaluated set = pairs with >= MIN_CONNS Zeek connections (RITA's own analysed set), so both scorers rank the same pairs.  Spectra scores
a pair with cadence_stats over its flows (0 if < 4 flows); RITA's score is the maximum beacon_score over its fqdn rows (0 if the pair is
absent from threat_mixtape).  RITA runs with threat-intel feeds and update checks OFF (no network).  Ten positives is a tiny sample.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys


HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import bench_cic2018 as cic  # noqa: E402

from spectra.eval.metrics import score_metrics  # noqa: E402
from spectra.modules.corr.graph import cadence_stats  # noqa: E402

MIN_CONNS, SEED, BOOT = 20, 1337, 1000


def ch(rita: str, sql: str) -> list[list[str]]:
    r = subprocess.run(["docker", "compose", "exec", "-T", "clickhouse", "clickhouse-client", "-q", sql, "--format", "TSV"],
                       cwd=rita, capture_output=True, text=True, check=True)
    return [ln.split("\t") for ln in r.stdout.splitlines() if ln]


def rita_import(rita: str, logs: str, db: str) -> None:
    if ch(rita, f"select count() from system.databases where name='{db}'")[0][0] != "0":
        return
    env = dict(os.environ, ZEEK_LOGS=logs)
    subprocess.run(["docker", "compose", "run", "--rm", "rita", "import", "--database", db, "--logs", "/logs", "--rebuild"],
                   cwd=rita, env=env, capture_output=True, check=True)


def ip(v: str) -> str:
    return v.removeprefix("::ffff:")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    rita = os.path.join(a.root, "tools", "rita")
    cic_root = os.path.join(a.root, "cic2018")
    cache = os.path.join(cic_root, ".feature-cache")
    fri = sorted(p for p in glob.glob(os.path.join(cic_root, "Friday-02-03-2018__*")) if not p.endswith(".log"))
    victims = [p for p in fri if cic.host_octet(os.path.basename(p)) in cic.VICTIMS and "EC2AMAZ-O4EL3NG" in p]
    spectra, rita_scores, conns, c2pairs, hashes = {}, {}, {}, set(), {}
    for p in victims:
        name = os.path.basename(p)
        d = cic.tolerant_flows(p, cache)
        hashes[name] = d["sha256"]
        for m in d["meta"]:
            key = (m[0], m[2]) if m[0].startswith("172.31.") else (m[2], m[0])
            spectra.setdefault(key, []).append(m[4])
            if cic.C2 in (m[0], m[2]):
                c2pairs.add(key)
        db = "cic_" + name.rsplit("-", 1)[-1].replace(".", "_")
        zeek = os.path.join(a.root, "zeek", "cic-out", name)
        rita_import(rita, zeek, db)
        for src, dst, n in ch(rita, f"select src, dst, count() from {db}.conn group by src, dst"):
            conns[(ip(src), ip(dst))] = conns.get((ip(src), ip(dst)), 0) + int(n)
        # RITA scores SNI-based beacons per (src, fqdn) with dst blank ('::') and the real addresses in server_ips; expand them
        # so an SNI beacon counts for every IP behind it (otherwise a detected C2 would look like a miss).
        q = (f"select src, if(dst = toIPv6('::'), arrayJoin(server_ips), dst) as d, max(beacon_score) "
             f"from {db}.threat_mixtape group by src, d")
        for src, dst, s in ch(rita, q):
            k = (ip(src), ip(dst))
            rita_scores[k] = max(rita_scores.get(k, 0.0), float(s))
    pairs = [k for k in set(spectra) | set(conns) if conns.get(k, 0) >= MIN_CONNS]
    pos = [k for k in pairs if k in c2pairs]
    neg = [k for k in pairs if k not in c2pairs]

    def spectra_score(k):
        st = cadence_stats(sorted(spectra.get(k, [])))
        return st["regularity"] if st else 0.0

    res = {}
    for name, fn in (("spectra_regularity", spectra_score), ("rita_beacon_score", lambda k: rita_scores.get(k, 0.0))):
        sp, sn = [fn(k) for k in pos], [fn(k) for k in neg]
        allv = sorted([(fn(k), k in c2pairs) for k in pairs], key=lambda t: -t[0])
        ranks = [i + 1 for i, (_, is_pos) in enumerate(allv) if is_pos]
        res[name] = {"metrics": score_metrics(sp, sn, BOOT, SEED), "positive_scores": [round(x, 3) for x in sorted(sp, reverse=True)],
                     "positive_ranks_among_pairs": ranks, "negatives_scoring_above_0_5": int(sum(1 for x in sn if x > 0.5))}
        print(name, {k: res[name]["metrics"][k] for k in ("roc_auc", "pr_auc", "recall_at_fpr_1pct")}, ranks, file=sys.stderr)
    out = {"benchmark": "CIC-2018 Bot day pair-level, Spectra vs real RITA v5.1.2", "min_zeek_conns": MIN_CONNS,
           "pairs": len(pairs), "c2_pairs": len(pos), "other_pairs": len(neg), "victim_capture_sha256": hashes,
           "rita_version": "v5.1.2", "results": res}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(out, open(a.out, "w"), indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
