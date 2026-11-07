#!/usr/bin/env python
"""Summarise the Suricata (ET Open) and stock Zeek baselines run over the CTU captures (docs/34 B.2 item 3).

    python scripts/bench_baselines_ctu.py --bench-data <dir with suricata/out and zeek/out> --out <json>

Flow denominator = Zeek conn.log rows; a flow counts as "alerted" when its 4-tuple appears in a Suricata alert (either
direction).  Positives are pcap-level (every flow of a botnet capture), like bench_ctu.py.  Wilson 95% intervals.
"""
from __future__ import annotations

import argparse
import json
import math
import os

BENIGN = ["ctu_normal--2017-05-01_normal", "ctu_normal--2017-05-02_kali-normal"]
BOTNET = ["ctu13--botnet-capture-20110810-neris", "ctu13--botnet-capture-20110811-neris",
          "ctu_botnet--botnet-capture-20110812-rbot", "ctu_botnet--botnet-capture-20110815-fast-flux",
          "ctu_botnet--capture.botnet2.infected.1"]


def wilson(k: int, n: int) -> list[float]:
    if n == 0:
        return [0.0, 0.0]
    z, p = 1.96, k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(c - h, 4), round(c + h, 4)]


def conn_tuples(path: str) -> set:
    out, fields = set(), []
    for line in open(path, encoding="utf-8", errors="replace"):
        if line.startswith("#fields"):
            fields = line.rstrip("\n").split("\t")[1:]
        elif not line.startswith("#"):
            r = dict(zip(fields, line.rstrip("\n").split("\t"), strict=False))
            if r.get("id.orig_p", "-") != "-":
                out.add((r["id.orig_h"], int(r["id.orig_p"]), r["id.resp_h"], int(r["id.resp_p"])))
    return out


def alerts(path: str) -> tuple[set, int, dict]:
    hits, n, sigs = set(), 0, {}
    if os.path.isfile(path):
        for line in open(path, encoding="utf-8"):
            if '"event_type":"alert"' not in line:
                continue
            e = json.loads(line)
            n += 1
            if "src_port" in e:
                hits.add((e["src_ip"], int(e["src_port"]), e["dest_ip"], int(e["dest_port"])))
                hits.add((e["dest_ip"], int(e["dest_port"]), e["src_ip"], int(e["src_port"])))
            s = e["alert"]["signature"]
            sigs[s] = sigs.get(s, 0) + 1
    return hits, n, sigs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bench-data", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    rows, tot = {}, {"benign": [0, 0, 0], "botnet": [0, 0, 0]}
    for group, names in (("benign", BENIGN), ("botnet", BOTNET)):
        for n in names:
            flows = conn_tuples(os.path.join(a.bench_data, "zeek", "out", n, "conn.log"))
            hits, n_alerts, sigs = alerts(os.path.join(a.bench_data, "suricata", "out", n, "eve.json"))
            alerted = sum(1 for t in flows if t in hits)
            notice = os.path.join(a.bench_data, "zeek", "out", n, "notice.log")
            rows[n] = {"group": group, "zeek_flows": len(flows), "suricata_alert_events": n_alerts,
                       "flows_with_suricata_alert": alerted,
                       "suricata_flow_rate": round(alerted / max(len(flows), 1), 4),
                       "suricata_flow_rate_ci95": wilson(alerted, len(flows)),
                       "zeek_notices": sum(1 for line in open(notice) if not line.startswith("#")) if os.path.isfile(notice) else 0,
                       "top_signatures": sorted(sigs.items(), key=lambda kv: -kv[1])[:3]}
            tot[group][0] += alerted
            tot[group][1] += len(flows)
            tot[group][2] += rows[n]["zeek_notices"]
    pooled = {g: {"flows": v[1], "alerted": v[0], "rate": round(v[0] / max(v[1], 1), 4),
                  "ci95": wilson(v[0], v[1]), "zeek_notices": v[2]} for g, v in tot.items()}
    rep = {"suricata": "7.0.8, ET Open via suricata-update on 2026-11-07 (69,342 rules, 53,373 enabled), -k none",
           "zeek": "7.0.5 stock scripts, no packages (the JA3 package install was not run)",
           "per_capture": rows, "pooled": pooled,
           "caveats": ["Positives are pcap-level; a 'miss' may be benign background in a botnet capture.",
                       "ET Open 2026 rules against 2011-2017 captures: old signatures may still be present, but rule/era mismatch is uncontrolled.",
                       "Stock Zeek is not an IDS: zero notices is expected and is not a tuned-Zeek result."]}
    json.dump(rep, open(a.out, "w", encoding="utf-8"), indent=2)
    print(json.dumps(pooled, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
