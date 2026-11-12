"""ADR-011 acceptance: the in-tree pcap reader against scapy's reader on the same file (needs scapy: a dev tool).

Both paths feed the same FlowTracker; only the reader + dissection differ:
  in-tree : spectra.capture.PcapFileSource -> Packet
  scapy   : scapy PcapReader + the pre-ADR dissection rules (first IP/IPv6 layer, first TCP/UDP layer, size from IP.len or
            IPv6 plen+40 else frame length, payload = bytes of the transport payload, flags = TCP flag int)

  python scripts/diff_reader_vs_scapy.py diff  FILE [--cap N]     -> one JSON object on stdout
  python scripts/diff_reader_vs_scapy.py bench FILE [--cap N] [--runs 3]

A file the in-tree reader ends with a CaptureError is read up to the cut-off (recorded as "ours_error"); the scapy side
is stopped after the same number of packets it saw, and its own behaviour at the cut is recorded, never hidden.
Set SPECTRA_DATA_DIR to a temp dir (importing spectra may bootstrap state).
"""
from __future__ import annotations

import argparse
import itertools
import json
import statistics
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spectra.capture import PcapFileSource  # noqa: E402
from spectra.capture.packet import Packet  # noqa: E402
from spectra.features.extractor import flows_to_matrix  # noqa: E402
from spectra.parse.flow import FlowTracker  # noqa: E402


def scapy_packets(path: str):
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.utils import PcapReader

    for b in PcapReader(path):
        p = Packet(b"", float(b.time))
        if b.haslayer(IP):
            ip = b[IP]
            size = int(ip.len) if ip.len is not None else len(b)
        elif b.haslayer(IPv6):
            ip = b[IPv6]
            size = int(ip.plen) + 40 if ip.plen is not None else len(b)
        else:
            yield p
            continue
        if b.haslayer(TCP):
            l4, proto = b[TCP], 6
        elif b.haslayer(UDP):
            l4, proto = b[UDP], 17
        else:
            yield p
            continue
        p.src, p.dst, p.l4, p.sport, p.dport, p.size = ip.src, ip.dst, proto, int(l4.sport), int(l4.dport), size
        p.data, p.poff = bytes(l4.payload) if l4.payload else b"", 0     # payload() == data[0:]
        p.flags = int(l4.flags) if proto == 6 else 0
        yield p


def run_flows(packets, cap):
    """Same loop as spectra.tools.collect_flows (idle 30 s, 5 s expiry buckets). Returns (flows, packets_seen, error)."""
    out: list = []
    tr = FlowTracker(idle_timeout=30.0, on_complete=out.append)
    last = None
    seen = 0
    err = None
    try:
        for pkt in itertools.islice(packets, cap):
            seen += 1
            ts = float(pkt.time)
            tr.process(pkt, ts)
            if last is None:
                last = ts
            elif ts - last >= 5:
                for _ in tr.flush_expired(ts):
                    pass
                last = ts
    except Exception as exc:  # noqa: BLE001 - the reader's own failure is data here
        err = f"{type(exc).__name__}: {exc}"
    list(tr.flush_all())
    return out, seen, err


def diff(path: str, cap: int | None) -> dict:
    ours, n_o, err_o = run_flows(PcapFileSource(path).packets(), cap)
    theirs, n_t, err_t = run_flows(scapy_packets(path), n_o if err_o else cap)
    res = {"file": Path(path).name, "cap_packets": cap, "packets_in_tree": n_o, "packets_scapy": n_t,
           "flows_in_tree": len(ours), "flows_scapy": len(theirs), "in_tree_error": err_o, "scapy_error": err_t,
           "mismatches": []}
    if n_o != n_t:
        res["mismatches"].append(f"packet count differs: in-tree {n_o}, scapy {n_t}")
    if len(ours) != len(theirs):
        res["mismatches"].append(f"flow count differs: {len(ours)} vs {len(theirs)}")
    bad = 0
    for i, (a, b) in enumerate(zip(ours, theirs, strict=False)):
        ra, rb = a.record(), b.record()
        diffs = [k for k in ra if ra[k] != rb.get(k)]
        if diffs:
            bad += 1
            if bad <= 5:
                res["mismatches"].append(f"flow {i} {ra['src']}>{ra['dst']} differs in {diffs}: "
                                         f"{[(ra[k], rb.get(k)) for k in diffs][:3]}")
    res["flow_records_differing"] = bad
    if ours and len(ours) == len(theirs):
        xa, xb = flows_to_matrix(ours), flows_to_matrix(theirs)
        same = xa.shape == xb.shape and np.array_equal(xa, xb, equal_nan=True)
        res["feature_matrix_shape"] = list(xa.shape)
        res["feature_matrix_exactly_equal"] = bool(same)
        if not same and xa.shape == xb.shape:
            res["feature_matrix_max_abs_diff"] = float(np.nanmax(np.abs(xa - xb)))
            res["mismatches"].append("feature matrix differs")
    res["ok"] = not res["mismatches"]
    return res


def bench(path: str, cap: int | None, runs: int) -> dict:
    out: dict = {"file": Path(path).name, "cap_packets": cap, "runs": runs}
    for name, mk in (("in_tree", lambda: PcapFileSource(path).packets()), ("scapy", lambda: scapy_packets(path))):
        read_pps, flow_pps, flow_fps = [], [], []
        for _ in range(runs):
            t = time.perf_counter()
            n = sum(1 for _ in itertools.islice(mk(), cap))
            read_pps.append(n / (time.perf_counter() - t))
            t = time.perf_counter()
            flows, seen, _err = run_flows(mk(), cap)
            dt = time.perf_counter() - t
            flow_pps.append(seen / dt)
            flow_fps.append(len(flows) / dt)
        out[name] = {"packets": n, "flows": len(flows),
                     "read_only_packets_per_s": [round(x) for x in read_pps], "read_only_median": round(statistics.median(read_pps)),
                     "to_flows_packets_per_s": [round(x) for x in flow_pps], "to_flows_median": round(statistics.median(flow_pps)),
                     "flows_per_s": [round(x) for x in flow_fps], "flows_per_s_median": round(statistics.median(flow_fps))}
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["diff", "bench"])
    ap.add_argument("file")
    ap.add_argument("--cap", type=int, default=None, help="stop after this many packets (both readers)")
    ap.add_argument("--runs", type=int, default=3)
    a = ap.parse_args()
    print(json.dumps(diff(a.file, a.cap) if a.mode == "diff" else bench(a.file, a.cap, a.runs)))
