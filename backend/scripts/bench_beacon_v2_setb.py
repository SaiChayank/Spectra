#!/usr/bin/env python
"""Held-out set B: beaconing scorer v2a1 vs real RITA v5.1.2 on the harmless-simulator corpus, ci/prereg/e21.json amendments 2 and 3.

    cd backend
    python scripts/bench_beacon_v2_setb.py --run ~/Projects/Spectra_bench_data/setb/<run-id> --out <json> \
        [--cache <dir>] [--zeek-dir <dir>] [--rita-root <dir>] [--allow-gaps] [--dry-run-ok] [--skip-rita] [--rita-hosts host-00,...]

Order of the real run (written before the data existed; nothing here is fitted to data):

1. Zeek, one directory of logs per host capture (same pattern as ~/Projects/Spectra_bench_data/zeek/run_zeek_cic.sh; -C = ignore checksums):

       RUN=~/Projects/Spectra_bench_data/setb/<run-id>; Z=~/Projects/Spectra_bench_data/zeek/setb-out; mkdir -p $Z
       for h in $(cd $RUN && ls host-*.pcap | sed 's/\\.pcap//'); do mkdir -p $Z/$h
         docker run --rm --user $(id -u):$(id -g) -v $RUN:/pcaps:ro -v $Z/$h:/out -w /out zeek/zeek:7.0.5 \
           sh -c "zeek -C -r /pcaps/$h.pcap > /out/stdout.txt 2>&1"; done

2. RITA stack (a different compose project from the simulator): `cd ~/Projects/Spectra_bench_data/tools/rita && docker compose up -d clickhouse`.
   Set B needs RITA's internal subnet to be 203.0.113.128/25.  The existing etc/config.hjson is NOT edited: this script writes a copy
   etc/config.setb.hjson (only the internal_subnets array replaced) and a compose override docker-compose.setb.yml that mounts it over
   /config.hjson, and runs the importer with `docker compose -f docker-compose.yml -f docker-compose.setb.yml run --rm rita import ...`.
   Each host capture goes into its own database setb_<run-id>_<host>.  Threat-intel feeds and update checks stay off (as in set A).
3. This script (Spectra scoring + the RITA imports + the metrics).  `--allow-gaps` only if the run had a suspend; it is then recorded
   prominently in the output.  `--dry-run-ok` skips the completeness refusal (plumbing tests on a short run only).

What it does (spec: amendment 3 and the task for this script):
* Refuses a run directory containing VOID.txt before opening anything else (unconditional).
* Refuses to run unless every manifest host has a non-empty pcap and heartbeat log, the heartbeats reach the planned duration, the end record
  exists, the pcap's flows span the planned duration, and no suspend happened (wall-clock minus monotonic drift between consecutive heartbeats
  above GAP_S).  Client ok/err counters are always reported.
* SHA-256 of every pcap and the manifest go into the output (for the data-only prereg amendment).
* Spectra: flow metadata of each host pcap (no payload kept), one BeaconTracker per host capture, threshold -1 (final score visible),
  beaconing_internal_nets = ["203.0.113.128/25"], allow-list EMPTY, flows fed in start-time order; a pair's score is its last verdict.
  A pair with no verdict scores 0.  Negatives (B1-B3) and the periodic class need >= 20 flows (below-20 counts reported);
  beacons ALWAYS count (amendment 4): fewer than 20 flows or absent = score 0 for both tools, flagged below_min_flows / absent.
* Labels from the manifest by (host, SNI or server IP): beacons by (interval, jitter), gate negatives B1-B3, periodic benign B4-B6,
  anything else "other" (reported, e.g. multicast, excluded from every class).
* RITA: same labelled pairs.  Join as in set A: RITA scores SNI beacons with a blank dst and the addresses in server_ips; those rows are expanded
  to every address, and a Spectra pair's RITA score is the max over (host, ip) for the IPs it saw.  Absent from RITA = 0.  RITA alert levels as in
  set A (0.5 default, 0.7 low); 0.8 is also shown.  If RITA analysed nothing for a capture that is reported loudly (stderr and `rita.*.analysed`).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import bench_beacon_v2_cic as cicv2  # noqa: E402
import bench_beacon_v2_ctu as setA  # noqa: E402
import bench_rita_cic as rc  # noqa: E402

from spectra.eval.metrics import recall_at_fpr, score_metrics  # noqa: E402
from spectra.modules.corr.beacon import DEFAULT_THRESHOLD, BeaconTracker  # noqa: E402

MIN_FLOWS, SEED, BOOT = setA.MIN_FLOWS, setA.SEED, setA.BOOT
INTERNAL = ["203.0.113.128/25"]
GAP_S = 5.0                 # wall-minus-monotonic drift between consecutive heartbeats that counts as a suspend
HB_HOLE_S = 150.0           # heartbeats are 60 s apart; more than this between two of them = missing heartbeats
GATE_JITTER_MAX = 50        # gated at jitter <= 50 %; 75 % is the degradation curve only
EXPECTED_GATED_POSITIVES = 36
RITA_LEVELS = [setA.RITA_BASE, setA.RITA_LOW, DEFAULT_THRESHOLD]
NEG_CLASSES, PERIODIC_CLASSES = ("B1", "B2", "B3"), ("B4", "B5", "B6")


def sha(path: str) -> str:
    return setA.sha(path)


# ---------------------------------------------------------------- completeness
def check_run(run: str, man: dict) -> dict:
    """File and heartbeat checks (the pcap-span check is added after the pcaps are read)."""
    dur = float(man["duration_s"])
    checks: dict = {}
    hosts: dict = {}
    for h in man["hosts"]:
        name = f"host-{h['host']:02d}"
        pcap, hb = os.path.join(run, name + ".pcap"), os.path.join(run, name + ".heartbeat.log")
        info: dict = {"pcap_bytes": os.path.getsize(pcap) if os.path.isfile(pcap) else None,
                      "heartbeat_present": os.path.isfile(hb)}
        beats, start, end = [], None, None
        if info["heartbeat_present"]:
            for ln in open(hb, encoding="utf-8", errors="replace"):
                try:
                    j = json.loads(ln)
                except ValueError:
                    continue
                if "start_wall" in j:
                    start = j
                elif "end_wall" in j:
                    end = j
                elif "mono" in j:
                    beats.append(j)
        gaps = [{"since_start_s": b["since_start_s"], "suspend_s": round((b["wall"] - a["wall"]) - (b["mono"] - a["mono"]), 2)}
                for a, b in zip(beats, beats[1:], strict=False) if abs((b["wall"] - a["wall"]) - (b["mono"] - a["mono"])) > GAP_S]
        holes = [{"after_s": a["since_start_s"], "mono_gap_s": round(b["mono"] - a["mono"], 1)}
                 for a, b in zip(beats, beats[1:], strict=False) if b["mono"] - a["mono"] > HB_HOLE_S]
        last = beats[-1] if beats else None
        info.update({
            "heartbeats": len(beats), "last_heartbeat_s": last["since_start_s"] if last else None, "end_record": end is not None,
            "wall_span_s": round(end["end_wall"] - start["start_wall"], 1) if end and start else None,
            "ok": (end or last or {}).get("ok"), "err": (end or last or {}).get("err"),
            "suspend_gaps": gaps, "heartbeat_holes": holes})
        info["covers_duration"] = bool(last and end and last["since_start_s"] >= dur - 60 and info["wall_span_s"] is not None
                                       and info["wall_span_s"] >= dur - GAP_S and not holes)
        hosts[name] = info
    checks["pcaps_present_nonempty"] = all(i["pcap_bytes"] for i in hosts.values())
    checks["heartbeat_logs_present"] = all(i["heartbeat_present"] for i in hosts.values())
    checks["heartbeats_cover_planned_duration"] = all(i["covers_duration"] for i in hosts.values())
    checks["no_suspend_gaps"] = not any(i["suspend_gaps"] for i in hosts.values())
    return {"planned_duration_s": dur, "gap_threshold_s": GAP_S, "checks": checks, "hosts": hosts,
            "client_errors_total": sum(i["err"] or 0 for i in hosts.values()),
            "client_ok_total": sum(i["ok"] or 0 for i in hosts.values())}


# ---------------------------------------------------------------- labels
def labels_for(man: dict) -> dict:
    """host ip -> {'sni': {sni: lab}, 'ip': {ip: lab}} with lab = {cls, interval, jitter}."""
    out: dict = {}
    for h in man["hosts"]:
        m = out.setdefault(h["ip"], {"sni": {}, "ip": {}, "host": f"host-{h['host']:02d}"})
        for p in h["profiles"]:
            lab = {"cls": p["class"], "interval": p.get("interval") if p["class"] == "beacon" else None,
                   "jitter": p.get("jitter") if p["class"] == "beacon" else None}
            for k, v in (("sni", p["sni"]), ("ip", p["ip"])):
                for x in (v if isinstance(v, list) else [v]):
                    m[k][x] = lab
    return out


def label_of(lab_host: dict | None, key: str, dst_ips: list) -> tuple[dict, str]:
    """Label of a pair (host, key) and how it joined: 'sni', 'ip' (pair keyed by IP) or 'dst_ip' (an IP behind the pair)."""
    if lab_host:
        if key in lab_host["sni"]:
            return lab_host["sni"][key], "sni"
        if key in lab_host["ip"]:
            return lab_host["ip"][key], "ip"
        for i in dst_ips:
            if i in lab_host["ip"]:
                return lab_host["ip"][i], "dst_ip"
    return {"cls": "other", "interval": None, "jitter": None}, "none"


def group_of(lab: dict) -> str:
    c = lab["cls"]
    if c == "beacon":
        return "beacon_gated" if lab["jitter"] <= GATE_JITTER_MAX else "beacon_curve"
    return "gate_negative" if c in NEG_CLASSES else "periodic_benign" if c in PERIODIC_CLASSES else "other"


# ---------------------------------------------------------------- spectra
def spectra_pairs(recs: list[dict]) -> tuple[list[dict], dict]:
    """Every tracked pair of one host capture with its flow count and last verdict (no flow threshold applied here)."""
    tr, counts, last = BeaconTracker(threshold=-1.0, internal_nets=INTERNAL), {}, {}
    for r in sorted(recs, key=lambda r: r["start_ts"]):
        host, ip = r["src"].rsplit(":", 1)[0], r["dst"].rsplit(":", 1)[0]
        key = (host, (r["sni"] or "").lower().rstrip(".") or ip)
        v = tr.observe(r)
        if key not in tr.pairs:
            continue
        counts[key] = counts.get(key, 0) + 1
        if v is not None:
            last[key] = v
    rows = []
    for key, n in counts.items():
        v = last.get(key)
        rows.append({"host_ip": key[0], "pair": list(key), "flows": n, "dst_ips": sorted(tr.pairs[key]["ips"]),
                     "score": v["score"] if v else 0.0, "components": v["components"] if v else None,
                     "span_h": v["span_h"] if v else None, "verdict": v is not None})
    return rows, {"flow_records": len(recs), "tracked_pairs": len(counts)}


# ---------------------------------------------------------------- rita
def rita_setb_files(rita: str) -> list[str]:
    """Write (never edit the existing files) etc/config.setb.hjson and docker-compose.setb.yml; return the -f arguments."""
    src = open(os.path.join(rita, "etc", "config.hjson"), encoding="utf-8").read()
    new, n = re.subn(r'"internal_subnets"\s*:\s*\[[^\]]*\]', '"internal_subnets": ["203.0.113.128/25"]', src, count=1)
    if n != 1:
        raise SystemExit("RITA etc/config.hjson has no internal_subnets array to replace")
    cfg, ovr = os.path.join(rita, "etc", "config.setb.hjson"), os.path.join(rita, "docker-compose.setb.yml")
    open(cfg, "w", encoding="utf-8").write(new)
    open(ovr, "w", encoding="utf-8").write(f"services:\n  rita:\n    volumes:\n      - {cfg}:/config.hjson:ro\n")
    return ["-f", os.path.join(rita, "docker-compose.yml"), "-f", ovr]


def rita_scores(rita: str, files: list[str], logs: str, db: str) -> tuple[dict, dict]:
    if rc.ch(rita, f"select count() from system.databases where name='{db}'")[0][0] == "0":
        subprocess.run(["docker", "compose", *files, "run", "--rm", "rita", "import", "--database", db, "--logs", "/logs", "--rebuild"],
                       cwd=rita, env=dict(os.environ, ZEEK_LOGS=logs), capture_output=True, check=True)
    info = {"conn_rows": int(rc.ch(rita, f"select count() from {db}.conn")[0][0]),
            "threat_mixtape_rows": int(rc.ch(rita, f"select count() from {db}.threat_mixtape")[0][0]),
            "rows_with_beacon_score_gt_0": int(rc.ch(rita, f"select countIf(beacon_score > 0) from {db}.threat_mixtape")[0][0])}
    scores: dict = {}
    q = (f"select src, if(dst = toIPv6('::'), arrayJoin(server_ips), dst) as d, max(beacon_score) "
         f"from {db}.threat_mixtape group by src, d")
    for src, dst, s in rc.ch(rita, q):
        k = (rc.ip(src), rc.ip(dst))
        scores[k] = max(scores.get(k, 0.0), float(s))
    info["scored_pairs"] = len(scores)
    info["analysed"] = info["conn_rows"] > 0 and info["threat_mixtape_rows"] > 0
    return scores, info


# ---------------------------------------------------------------- metrics
def rec_at(rows, key, thr):
    return None if not rows or thr is None else sum(1 for r in rows if r[key] >= thr) / len(rows)


def per_tool(rows, key, fixed_levels):
    pos = [r[key] for r in rows if r["group"] == "beacon_gated" and r["eligible"]]
    neg = [r[key] for r in rows if r["group"] == "gate_negative" and r["eligible"]]
    op = recall_at_fpr(pos, neg, 0.001)
    thr = op["threshold"] if op else None
    sub = lambda f: [r for r in rows if r["group"] in ("beacon_gated", "beacon_curve") and r["eligible"] and f(r)]  # noqa: E731

    def curve(f):
        s = sub(f)
        return {"n": len(s), "recall_at_gate_threshold": rec_at(s, key, thr),
                **{f"recall_at_{t}": rec_at(s, key, t) for t in fixed_levels}}
    return {
        "n_pos": len(pos), "n_neg": len(neg), "metrics": score_metrics(pos, neg, BOOT, SEED), "gate_operating_point": op,
        "fixed": [setA.fixed(pos, neg, t) for t in fixed_levels],
        "per_cell": {f"{i}s_{j}pct": curve(lambda r, i=i, j=j: (r["interval"], r["jitter"]) == (i, j))
                     for i in (10, 60, 300, 1800) for j in (0, 25, 50, 75)},
        "per_jitter_curve": {f"{j}pct": curve(lambda r, j=j: r["jitter"] == j) for j in (0, 25, 50, 75)},
        "per_interval": {f"{i}s": curve(lambda r, i=i: r["interval"] == i and r["jitter"] <= GATE_JITTER_MAX) for i in (10, 60, 300, 1800)},
        "periodic_benign_outside_gate": {c: {"pairs": sum(1 for r in rows if r["cls"] == c and r["eligible"]),
                                             **{f"scoring_ge_{t}": sum(1 for r in rows if r["cls"] == c and r["eligible"] and r[key] >= t)
                                                for t in fixed_levels}} for c in PERIODIC_CLASSES},
    }


def class_counts(rows):
    out: dict = {}
    for r in rows:
        c = out.setdefault(r["cls"], {"labelled_pairs": 0, "below_20_flows": 0, "absent": 0, "eligible": 0, "no_verdict": 0})
        c["labelled_pairs"] += 1
        c["absent"] += r["flag"] == "absent"
        c["below_20_flows"] += r["flag"] == "below_min_flows"
        if r["eligible"]:
            c["eligible"] += 1
            c["no_verdict"] += 0 if r["verdict"] else 1
        else:
            c["below_20_flows"] += 1
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--cache", default="~/Projects/Spectra_bench_data/.beacon-v2-cache")
    ap.add_argument("--zeek-dir", default="~/Projects/Spectra_bench_data/zeek/setb-out")
    ap.add_argument("--rita-root", default="~/Projects/Spectra_bench_data/tools/rita")
    ap.add_argument("--allow-gaps", action="store_true", help="accept suspend gaps (recorded prominently)")
    ap.add_argument("--dry-run-ok", action="store_true", help="skip the completeness refusal (plumbing tests on a short run only)")
    ap.add_argument("--skip-rita", action="store_true")
    ap.add_argument("--rita-hosts", help="comma list of host names to import into RITA (default all)")
    a = ap.parse_args()
    run, cache = os.path.expanduser(a.run), os.path.expanduser(a.cache)
    zeek, rita = os.path.expanduser(a.zeek_dir), os.path.expanduser(a.rita_root)
    if os.path.exists(os.path.join(run, "VOID.txt")):    # a voided run is never scored (not even with --dry-run-ok); nothing else is opened
        raise SystemExit(f"{run} contains VOID.txt: this run is void and must not be scored")
    os.makedirs(cache, exist_ok=True)
    mpath = os.path.join(run, "manifest.json")
    man = json.load(open(mpath))
    dur = float(man["duration_s"])

    comp = check_run(run, man)
    comp["dry_run_ok_flag"], comp["allow_gaps_flag"] = a.dry_run_ok, a.allow_gaps
    bad = [k for k, v in comp["checks"].items() if not v and not (k == "no_suspend_gaps" and a.allow_gaps)]
    if a.allow_gaps and not comp["checks"]["no_suspend_gaps"]:
        comp["WARNING"] = "SUSPEND GAPS PRESENT AND ACCEPTED VIA --allow-gaps: the run is not continuous wall-clock traffic"
        print("!!! " + comp["WARNING"], file=sys.stderr)
    if bad and not a.dry_run_ok:
        print(json.dumps({"refused": bad, "hosts": comp["hosts"]}, indent=1), file=sys.stderr)
        raise SystemExit(f"run is not complete and sound: failed {bad} (--dry-run-ok skips this for plumbing tests only)")

    labs = labels_for(man)
    hashes = {"manifest.json": sha(mpath)}
    rows, caps = [], {}
    join_check = {}
    for h in man["hosts"]:
        name = f"host-{h['host']:02d}"
        digest, recs = cicv2.read_meta(os.path.join(run, name + ".pcap"), cache)
        hashes[name + ".pcap"] = digest
        prs, cap = spectra_pairs(recs)
        starts = [r["start_ts"] for r in recs]
        cap["flow_span_s"] = round(max(starts) - min(starts), 1) if starts else 0.0
        caps[name] = cap
        lab_host = labs[h["ip"]]
        seen_keys = {p["pair"][1] for p in prs} | {i for p in prs for i in p["dst_ips"]}
        join_check[name] = {  # every profile of the host: was its destination seen in the pcap?
            f"{p['class']}:{x}": (x in seen_keys) for p in h["profiles"]
            for x in (p["sni"] if isinstance(p["sni"], list) else [p["sni"]])}
        for r in prs:
            lab, how = label_of(lab_host if r["host_ip"] == h["ip"] else None, r["pair"][1], r["dst_ips"])
            r.update({"host": name, "cls": lab["cls"], "interval": lab["interval"], "jitter": lab["jitter"], "joined_by": how,
                      "eligible": r["flows"] >= MIN_FLOWS, "rita": None})
            r["group"] = group_of(lab)
            r["flag"] = None
            if r["cls"] == "beacon":     # amendment 4: a beacon always counts; below 20 flows it is a miss (score 0), not an exclusion
                r["eligible"] = True
                if r["flows"] < MIN_FLOWS:
                    r.update(flag="below_min_flows", score=0.0, components=None, verdict=False)
        for p in h["profiles"]:          # manifest beacon absent from the pcap: a miss with score 0
            if p["class"] == "beacon" and not any(r["cls"] == "beacon" and p["sni"] in (r["pair"][1], *r["dst_ips"]) for r in prs):
                prs.append({"host_ip": h["ip"], "pair": [h["ip"], p["sni"]], "flows": 0, "dst_ips": [], "score": 0.0, "components": None,
                            "span_h": None, "verdict": False, "host": name, "cls": "beacon", "interval": p["interval"],
                            "jitter": p["jitter"], "joined_by": "manifest", "eligible": True, "rita": None, "flag": "absent",
                            "group": group_of({"cls": "beacon", "jitter": p["jitter"]})})
        rows += prs
    comp["checks"]["pcap_flows_span_planned_duration"] = all(c["flow_span_s"] >= dur - 300 for c in caps.values())
    comp["pcap_flow_span_s"] = {k: v["flow_span_s"] for k, v in caps.items()}
    if not comp["checks"]["pcap_flows_span_planned_duration"] and not a.dry_run_ok:
        raise SystemExit("a pcap's flows do not span the planned duration (--dry-run-ok skips this for plumbing tests only)")

    rita_info: dict = {}
    wanted = [x for x in (a.rita_hosts or "").split(",") if x] or [f"host-{h['host']:02d}" for h in man["hosts"]]
    if not a.skip_rita:
        files = rita_setb_files(rita)
        rid = re.sub(r"[^a-z0-9]", "_", man["run_id"].lower())
        for name in wanted:
            db = f"setb_{rid}_{name.replace('-', '_')}"
            ip_ = next(h["ip"] for h in man["hosts"] if f"host-{h['host']:02d}" == name)
            rs, rita_info[name] = rita_scores(rita, files, os.path.join(zeek, name), db)
            rita_info[name]["database"] = db
            if not rita_info[name]["analysed"]:
                print(f"!!! RITA PRODUCED NO SCORES for {name}: {rita_info[name]}", file=sys.stderr)
            for r in rows:
                if r["host"] == name and r["host_ip"] == ip_:
                    r["rita"] = max([rs.get((ip_, i), 0.0) for i in r["dst_ips"]] or [0.0])
                    if r["flag"]:
                        r["rita"] = 0.0      # amendment 4: below_min_flows / absent beacons score 0 for RITA too
    rita_all = (not a.skip_rita and sorted(wanted) == sorted(caps) and all(i["analysed"] for i in rita_info.values()))

    lab_rows = [r for r in rows if r["group"] != "other"]
    for r in lab_rows:
        if r["rita"] is None:
            r["rita"] = 0.0 if rita_all else None
    other = [r for r in rows if r["group"] == "other"]
    res = {"spectra_v2a1": per_tool(lab_rows, "score", [DEFAULT_THRESHOLD])}
    if rita_all:
        res["rita_v5.1.2"] = per_tool(lab_rows, "rita", RITA_LEVELS)
    sp = res["spectra_v2a1"]
    rec = (sp["metrics"] or {}).get("recall_at_fpr_0_1pct")
    ci = (sp["metrics"] or {}).get("recall_at_fpr_0_1pct_ci95")
    rrec = ((res.get("rita_v5.1.2") or {}).get("metrics") or {}).get("recall_at_fpr_0_1pct")
    gate = {"n_pos": sp["n_pos"], "n_pos_expected": EXPECTED_GATED_POSITIVES, "n_pos_as_expected": sp["n_pos"] == EXPECTED_GATED_POSITIVES,
            "n_neg": sp["n_neg"], "n_neg_lt_1000_so_zero_false_pairs_required": sp["n_neg"] < 1000,
            "recall_at_gate_operating_point": rec, "bootstrap_lower_bound": ci[0] if ci else None, "rita_recall_same_rule": rrec,
            "rita_comparison_evaluable": rita_all}
    gate["checks"] = {"recall_ge_0.8": rec is not None and rec >= 0.8, "lower_bound_ge_0.6": bool(ci) and ci[0] >= 0.6,
                      "not_more_than_0.05_below_rita": rrec is not None and rec is not None and rec >= rrec - 0.05}
    gate["pass"] = all(gate["checks"].values()) and gate["n_pos_as_expected"]
    fx = sp["fixed"][0]
    gate["fixed_threshold_default_on_condition"] = {"recall_at_0.8": fx["recall"], "false_pairs_at_0.8": fx["false_pairs"],
                                                    "met": (fx["recall"] or 0) >= 0.8 and fx["false_pairs"] == 0}
    gate["overall_e21_gate"] = ("The overall E21 gate needs both A and B and already FAILED on set A regardless of this block; "
                                "this block is the set B part only.")
    out = {"benchmark": "Held-out set B (harmless simulator, 12 hosts): Spectra beacon v2a1 vs RITA v5.1.2",
           "git_commit": cicv2.cic.git("rev-parse", "HEAD"), "run_id": man["run_id"], "min_flows": MIN_FLOWS, "bootstrap": BOOT,
           "seed": SEED, "spectra_threshold": DEFAULT_THRESHOLD, "beaconing_internal_nets": INTERNAL, "allow_list": [],
           "rita_alert_levels": RITA_LEVELS, "completeness": comp, "sha256": hashes, "captures": caps,
           "label_join_check_destination_seen_in_pcap": join_check, "class_counts": class_counts(lab_rows),
           "other_pairs": {"n": len(other), "pairs": [{k: r[k] for k in ("host", "pair", "flows", "dst_ips", "score")} for r in other]},
           "rita": rita_info, "rita_all_hosts_analysed": rita_all, "results": res, "gate_set_b": gate,
           "pairs": sorted(lab_rows, key=lambda r: (r["host"], r["cls"], str(r["pair"])))}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(out, open(a.out, "w"), indent=1)
    print(json.dumps({k: out[k] for k in ("class_counts", "rita_all_hosts_analysed", "gate_set_b")} | {"other_pairs": len(other),
          "completeness_checks": comp["checks"]}, indent=1), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
