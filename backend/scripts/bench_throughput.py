#!/usr/bin/env python
"""Offline parse + feature + score throughput on real pcaps (single process, no NIC, no sudo).

    cd backend
    python scripts/bench_throughput.py --pcap <file> [--pcap <file> ...] --out <json>

NOT the live-capture sizing of docs/34 B.2 item 6 (that needs `scripts/bench_perf.sh` run by a human with sudo): this
measures how fast the pipeline core digests a capture from disk on this machine: packets/s, flows/s, CPU seconds and peak RSS.
The detector is trained on the first 5000 flows of the first file only so scoring cost is realistic. Each file is read twice: parse-only, then parse + features + per-flow scoring.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import resource
import subprocess
import sys
import time


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spectra.features.extractor import flows_to_matrix  # noqa: E402
from spectra.ml.model import SpectraDetector  # noqa: E402
from spectra.tools import stream_flows  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap", action="append", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    first: list = []
    stream_flows(a.pcap[0], first.append, max_flows=5000)
    det = SpectraDetector(contamination=0.02, random_state=42)
    det.fit(flows_to_matrix(first))
    rep: dict = {"machine": {"cpu": next((x.split(":", 1)[1].strip() for x in open("/proc/cpuinfo") if x.startswith("model name")), "?"),
                             "cpus": os.cpu_count(), "kernel": platform.release(), "python": platform.python_version()},
                 "runs": []}
    try:
        rep["machine"]["commit"] = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    for path in a.pcap:
        # parse only (packets -> flows), then parse + features + score per flow
        pn = ppk = 0

        def count(f) -> None:
            nonlocal pn, ppk
            pn += 1
            ppk += f.packets_fwd + f.packets_bwd

        t0, c0 = time.perf_counter(), time.process_time()
        stream_flows(path, count, max_flows=3_000_000)
        parse_wall, parse_cpu = time.perf_counter() - t0, time.process_time() - c0
        n = pk = 0

        def cb(f) -> None:
            nonlocal n, pk
            n += 1
            pk += f.packets_fwd + f.packets_bwd
            det.score(flows_to_matrix([f]))

        t0, c0 = time.perf_counter(), time.process_time()
        info = stream_flows(path, cb, max_flows=3_000_000)
        wall, cpu = time.perf_counter() - t0, time.process_time() - c0
        rep["runs"].append({"file": os.path.basename(path), "bytes": os.path.getsize(path), "flows": n, "packets_in_flows": pk,
                            "truncated_by_budget": info["truncated"], "wall_s": round(wall, 2), "cpu_s": round(cpu, 2),
                            "parse_only": {"wall_s": round(parse_wall, 2), "cpu_s": round(parse_cpu, 2), "packets_per_s": round(ppk / parse_wall),
                                       "flows_per_s": round(pn / parse_wall)},
                            "packets_per_s": round(pk / wall), "flows_per_s": round(n / wall), "mb_per_s": round(os.path.getsize(path) / 1e6 / wall, 2),
                            "peak_rss_mb_so_far": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)})
        print(rep["runs"][-1], flush=True)
    json.dump(rep, open(a.out, "w", encoding="utf-8"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
