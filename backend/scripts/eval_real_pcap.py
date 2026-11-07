#!/usr/bin/env python
"""Score a REAL capture with the synthetic-trained baselines, with a control.

    cd backend
    python scripts/eval_real_pcap.py --pcap <file> --sha256 <expected> --out report.json

Honest scope (also written into the report): without per-flow ground truth this
measures a **flag rate**, not recall, and the synthetic baselines were trained
on TLS/QUIC traffic only, so *any* plaintext flow looks unusual to them.  The
control below is a set of synthetic, plainly benign HTTP-style TCP flows; if
the control is flagged as often as the capture, the capture's flag rate says
"not TLS", not "malicious".  It also reports parser coverage on real traffic.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import random
import sys
import tempfile

import numpy as np

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND)
sys.path.insert(0, os.path.join(BACKEND, "scripts"))

import eval_synthetic as ev  # noqa: E402
from spectra.demo import BASE, _pkt, make_baseline_pcap, make_benign_diversity_pcap, write_pcap  # noqa: E402
from spectra.features.extractor import flows_to_matrix  # noqa: E402
from spectra.ml.model import SpectraDetector  # noqa: E402
from spectra.tools import collect_flows  # noqa: E402


def plain_http_benign(n: int, rng: random.Random) -> list:
    """SYNTHETIC benign plaintext web flows (no TLS): request, a few response segments, FIN."""
    pkts = []
    for i in range(n):
        src, dst, sport = ev._src(i, 95), "198.51.100.200", 20000 + i
        t, c, s = BASE + i * 5.0, 1000, 5000
        pkts += [_pkt(src, dst, sport, 80, "S", c, 0, t=t),
                 _pkt(dst, src, 80, sport, "SA", s, c + 1, t=t + .02),
                 _pkt(src, dst, sport, 80, "A", c + 1, s + 1, t=t + .021)]
        c, s, t = c + 1, s + 1, t + .05
        req = b"GET /index.html HTTP/1.1\r\nHost: files.example\r\n\r\n"
        pkts.append(_pkt(src, dst, sport, 80, "PA", c, s, payload=req, t=t))
        c += len(req)
        for _ in range(rng.randint(2, 6)):
            t += rng.uniform(0.01, 0.2)
            size = rng.randint(400, 1400)
            pkts.append(_pkt(dst, src, 80, sport, "PA", s, c, payload=b"x" * size, t=t))
            s += size
        pkts += [_pkt(src, dst, sport, 80, "FA", c, s, t=t + .1),
                 _pkt(dst, src, 80, sport, "FA", s, c + 1, t=t + .11)]
    return pkts


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--sha256", required=True, help="expected SHA-256 (refuse to run on other bytes)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--n-control", type=int, default=300)
    ap.add_argument("--max-flows", type=int, default=500_000)
    args = ap.parse_args()

    actual = ev.sha256(args.pcap)
    if actual != args.sha256.lower():
        print(f"SHA-256 mismatch: expected {args.sha256}, got {actual}", file=sys.stderr)
        return 2

    np_rng = np.random.default_rng(ev.SEED)
    tmp = tempfile.mkdtemp(prefix="spectra_real_")
    train_a = os.path.join(tmp, "A.pcap")
    train_b = os.path.join(tmp, "B.pcap")
    make_baseline_pcap(train_a, n_flows=300, seed=7)
    make_benign_diversity_pcap(train_b, n_flows=420, seed=21)
    ctrl = os.path.join(tmp, "control.pcap")
    write_pcap(ctrl, sorted(plain_http_benign(args.n_control, random.Random(ev.SEED)),
                            key=lambda p: float(p.time)))

    flows = collect_flows(args.pcap, max_flows=args.max_flows)
    X = flows_to_matrix(flows)
    tls = np.array([bool(f.client_tls or f.server_tls) for f in flows])
    ports = np.array([f.dst_port for f in flows])
    top = [p for p, _ in collections.Counter(ports.tolist()).most_common(6)]
    Xc = ev.matrix(ctrl)

    report: dict = {
        "kind": "REAL capture scored by SYNTHETIC-trained baselines - flag rate, NOT recall",
        "capture": {"sha256": actual, "bytes": os.path.getsize(args.pcap), "flows": int(len(flows)),
                    "tcp": int(sum(f.proto == 6 for f in flows)), "udp": int(sum(f.proto == 17 for f in flows)),
                    "tls_handshake_parsed": int(tls.sum()), "tls_share": round(float(tls.mean()), 4),
                    "distinct_src": len({f.src_ip for f in flows}), "distinct_dst": len({f.dst_ip for f in flows}),
                    "top_dst_ports": collections.Counter(ports.tolist()).most_common(8)},
        "environment": {"commit": ev.git("rev-parse", "--short", "HEAD"), "seed": ev.SEED,
                        "control_sha256": ev.sha256(ctrl), "control_flows": int(len(Xc)),
                        "control": "synthetic plaintext HTTP-style benign TCP flows (scripts/eval_real_pcap.py)"},
        "baselines": {},
        "caveats": [
            "No per-flow ground truth was used, so this is a flag rate, not recall or precision.",
            "The baselines are synthetic and TLS/QUIC-only; plaintext flows are far outside them by construction.",
            "The capture is botnet-host traffic from 2011 (SMTP spam, DNS, HTTP, IRC), not modern encrypted C2.",
        ],
    }
    for name, path in (("A_demo_baseline", train_a), ("B_benign_diversity", train_b)):
        det = SpectraDetector(contamination=0.02, random_state=42)
        det.fit(ev.matrix(path))
        flag = np.asarray(det.predict(X)).astype(bool)
        flag_c = np.asarray(det.predict(Xc)).astype(bool)
        by_port = {str(p): ev.rate(flag[ports == p], np_rng) for p in top}
        report["baselines"][name] = {
            "flag_rate_capture": ev.rate(flag, np_rng),
            "flag_rate_capture_tls_flows": ev.rate(flag[tls], np_rng) if tls.any() else None,
            "flag_rate_capture_non_tls_flows": ev.rate(flag[~tls], np_rng),
            "flag_rate_by_top_dst_port": by_port,
            "flag_rate_plain_http_benign_control": ev.rate(flag_c, np_rng),
        }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
