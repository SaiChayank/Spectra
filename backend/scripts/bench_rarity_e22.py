#!/usr/bin/env python
"""E22 rare-destination scorer on one capture day (ci/prereg/e22.json, frozen 2026-11-20).

    cd backend
    python scripts/bench_rarity_e22.py --set dev   --root ~/Projects/Spectra_bench_data --out <json>
    python scripts/bench_rarity_e22.py --set A-wed --root ~/Projects/Spectra_bench_data --out <json>
    python scripts/bench_rarity_e22.py --set A-thu --root ~/Projects/Spectra_bench_data --out <json>

dev = CIC-2018 Bot day (SEEN, never gate evidence; positives = the ten Bot victims).  A-wed / A-thu = set_A days, hosts and
positives exactly as amendment A1.  Reads every per-host capture of the day with the tolerant metadata reader of
bench_beacon_v2_cic.py (cached by SHA-256), scores the whole day as one window, and reports E22 next to baseline B1.
B2 = RITA's own final_score per host (amendment A2) read from
the day's ClickHouse database (--rita-db; benchmark stack in <root>/tools/rita), B3 = distinct ET-rule signatures per source host
(amendment A3) from per-capture Suricata eve.json files (--suricata-dir).  Hosts a baseline has no evidence for score 0.  Metadata only: no payload bytes are read into the cache.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import bench_cic2018 as cic  # noqa: E402
from bench_beacon_v2_cic import read_meta  # noqa: E402

from spectra.eval.metrics import recall_at_fpr, score_metrics  # noqa: E402
from spectra.modules.corr.rarity import THRESHOLD, score_window  # noqa: E402

SEED, BOOT = 1337, 1000
PREREG = os.path.join(os.path.dirname(os.path.dirname(HERE)), "ci", "prereg", "e22.json")


def b1_scores(pairs_all: dict) -> dict:
    """Baseline B1: number of the host's destinations with prevalence 1 and >= 2 flows; ties broken by their flow count."""
    s = {}
    for h, ev in pairs_all.items():
        u = [e for e in ev if e["prevalence"] == 1 and e["flows"] >= 2]
        f = sum(e["flows"] for e in u)
        s[h] = len(u) + f / (f + 1)
    return s


def files_for(root: str, which: str) -> tuple[list[str], set[str], str]:
    if which == "dev":
        d = os.path.join(root, "cic2018")
        fs = sorted(p for p in glob.glob(os.path.join(d, "Friday-02-03-2018__*")) if not p.endswith((".log", ".csv")))
        return fs, {f"172.31.69.{o}" for o in cic.VICTIMS}, "SEEN DATA, dev only, NOT gate evidence"
    day = {"A-wed": "Wednesday-28-02-2018", "A-thu": "Thursday-01-03-2018"}[which]
    a1 = json.load(open(PREREG))["amendments"][0]
    assert a1["id"] == "A1"
    want = set(a1["positives"][day]) | set(a1["sampling"]["sampled_negatives"][day])
    fs = sorted(glob.glob(os.path.join(root, "cic2018_infil", day, "*")))
    fs = [p for p in fs if not p.endswith(".part") and ip_of(p) in want]
    got = {ip_of(p) for p in fs}
    assert got == want, f"missing hosts: {sorted(want - got)}"
    return fs, set(a1["positives"][day]), "HELD-OUT set_A (ANECDOTAL by amendment A1: < 10 positives)"


def ip_of(p: str) -> str | None:
    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", os.path.basename(p))
    return m.group(1) if m else None


def all_pairs(records) -> dict:
    """Every scored pair per host (score_window keeps only the top 3), for B1's count."""
    from spectra.modules.corr import rarity
    keep, rarity.TOP = rarity.TOP, 10 ** 9
    try:
        w = score_window(records)
    finally:
        rarity.TOP = keep
    return {h: v["top"] for h, v in w["hosts"].items()}


RITA_SQL = """
SELECT src, max(final_score) FROM (
  SELECT src, greatest(beacon_threat_score, long_conn_score, strobe_score, c2_over_dns_score, threat_intel_score) + total_modifier_score
         + prevalence_score + first_seen_score + missing_host_header_score + threat_intel_data_size_score + c2_over_dns_direct_conn_score AS final_score
  FROM (
    SELECT hash, src, dst, fqdn, sum(beacon_threat_score) AS beacon_threat_score, sum(long_conn_score) AS long_conn_score,
           sum(strobe_score) AS strobe_score, sum(c2_over_dns_score) AS c2_over_dns_score, sum(threat_intel_score) AS threat_intel_score,
           sum(modifier_score) AS total_modifier_score, sum(prevalence_score) AS prevalence_score, sum(first_seen_score) AS first_seen_score,
           sum(missing_host_header_score) AS missing_host_header_score, sum(threat_intel_data_size_score) AS threat_intel_data_size_score,
           sum(c2_over_dns_direct_conn_score) AS c2_over_dns_direct_conn_score
    FROM {db}.threat_mixtape t
    INNER JOIN (SELECT hash, argMax(import_id, last_seen) AS import_id, max(last_seen) AS max_last_seen FROM {db}.threat_mixtape GROUP BY hash) x
      ON t.hash = x.hash AND t.last_seen = x.max_last_seen AND t.import_id = x.import_id
    GROUP BY hash, src, dst, fqdn)
) GROUP BY src
"""


def b2_scores(rita: str, db: str, hosts) -> dict:
    """Baseline B2 (amendment A2): max RITA final_score per source host, exactly as RITA's viewer computes it."""
    assert re.fullmatch(r"[a-z0-9_]+", db)
    r = subprocess.run(["docker", "compose", "exec", "-T", "clickhouse", "clickhouse-client", "--format", "TSV",
                        "-q", RITA_SQL.format(db=db)], cwd=rita, capture_output=True, text=True, check=True)
    got = {}
    for line in r.stdout.splitlines():
        src, v = line.split("\t")
        got[src.removeprefix("::ffff:")] = float(v)
    return {h: got.get(h, 0.0) for h in hosts}


def b3_scores(sdir: str, files, hosts) -> tuple[dict, dict]:
    """Baseline B3 (amendment A3): distinct ET-rule signatures per source host; all-alert signature counts beside it."""
    from bench_baselines_ctu import is_rule_alert
    rules, every = {h: set() for h in hosts}, {h: set() for h in hosts}
    for p in files:
        eve = os.path.join(sdir, os.path.basename(p), "eve.json")
        if not os.path.isfile(eve):
            raise SystemExit(f"missing Suricata output {eve}")
        for line in open(eve):
            e = json.loads(line)
            if e.get("event_type") != "alert" or e.get("src_ip") not in rules:
                continue
            every[e["src_ip"]].add(e["alert"]["signature"])
            if is_rule_alert(e):
                rules[e["src_ip"]].add(e["alert"]["signature"])
    return {h: float(len(v)) for h, v in rules.items()}, {h: len(v) for h, v in every.items()}


def summary(scores: dict, pos: set) -> dict:
    order = sorted(scores)      # fixed order: the seeded bootstrap must not depend on set iteration (hash seed)
    sp = [scores[h] for h in order if h in pos]
    sn = [scores[h] for h in order if h not in pos]
    budget = 0.0 if len(sn) < 100 else 0.01
    ranked = sorted(scores, key=lambda h: -scores[h])
    rank = {h: 1 + sum(1 for x in scores.values() if x > scores[h]) for h in pos if h in scores}
    return {"positives": len(sp), "negatives": len(sn), "fp_budget_fpr": budget,
            "recall_at_budget": recall_at_fpr(sp, sn, budget), "positive_ranks": rank,
            "metrics": score_metrics(sp, sn, BOOT, SEED), "top10": [[h, scores[h], h in pos] for h in ranked[:10]]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--set", required=True, choices=["dev", "A-wed", "A-thu"])
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--rita-db", help="ClickHouse database of this day's RITA import (B2)")
    ap.add_argument("--suricata-dir", help="directory with <capture name>/eve.json per capture (B3)")
    a = ap.parse_args()
    root = os.path.expanduser(a.root)
    files, pos, status = files_for(root, a.set)
    cache = os.path.join(root, "cic2018", ".feature-cache")
    os.makedirs(cache, exist_ok=True)
    recs, hashes = [], {}
    for p in files:
        digest, r = read_meta(p, cache)
        hashes[os.path.basename(p)] = digest
        recs.extend(r)
    w = score_window(recs)
    if w is None:
        out = {"set": a.set, "status": status, "verdict": "no verdict: N < 10", "capture_sha256": hashes}
    else:
        e22 = {h: v["score"] for h, v in w["hosts"].items()}
        base = b1_scores(all_pairs(recs))
        missing = sorted(pos - set(e22))
        extra = {}
        if a.rita_db:
            extra["b2_rita"] = summary(b2_scores(os.path.join(root, "tools", "rita"), a.rita_db, e22), pos)
        if a.suricata_dir:
            b3, b3_all = b3_scores(os.path.expanduser(a.suricata_dir), files, e22)
            extra["b3_suricata_et_rules"] = summary(b3, pos)
            extra["b3_all_alert_signatures"] = summary({h: float(v) for h, v in b3_all.items()}, pos)
        out = {"set": a.set, "status": status, "prereg": "ci/prereg/e22.json", "git_commit": cic.git("rev-parse", "HEAD"),
               "N": w["N"], "positives_without_external_traffic": missing, "threshold": THRESHOLD,
               "e22": summary(e22, pos), "b1": summary(base, pos),
               "e22_at_threshold": {"alerts_pos": sum(1 for h in pos if w["hosts"].get(h, {}).get("alert")),
                                    "alerts_neg": sum(1 for h, v in w["hosts"].items() if v["alert"] and h not in pos)},
               **extra,
               "positive_evidence": {h: w["hosts"][h] for h in pos if h in w["hosts"]},
               "capture_sha256": hashes}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(out, open(a.out, "w"), indent=1)
    print(json.dumps({k: out[k] for k in out if k not in ("capture_sha256", "positive_evidence")}, indent=1)[:4000], file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
