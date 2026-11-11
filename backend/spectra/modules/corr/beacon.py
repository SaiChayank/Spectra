"""Module 7b: host-pair beaconing scorer (docs/plan-beaconing-detector.md).

Independent of the isolation forest: one score per (source host, destination
IP) pair from flow *metadata only* (start time, byte count, duration).

    score = (regularity + robust_regularity + size_consistency) / 3

  * regularity        ``1 - cv`` of the start-time gaps (``cadence_stats``)
  * robust_regularity ``1 - min(1, MAD(gaps) / median(gaps))`` - survives one
                      long outage that wrecks the cv
  * size_consistency  ``1 - min(1, cv(flow bytes))``

The weights are equal on purpose: nothing here was fitted to an evaluation
dataset.  A pair is only scored with at least ``min_flows`` flows in its
window and a median gap of at least ``MIN_GAP_S`` (faster is a burst or a
bulk transfer, not a heartbeat).  Flow duration is reported as evidence, not
scored.  Known periodic services belong in the allow-list.
"""

from __future__ import annotations

import ipaddress
import statistics
from collections import OrderedDict, deque

from .graph import PAIR_CAP, _strip_port, cadence_stats

MIN_FLOWS = 8        # flows in the window before a pair is scored (7 gaps)
WINDOW = 64          # newest flows kept per pair
MIN_GAP_S = 1.0      # median start-to-start gap below this is not a beacon
DEFAULT_THRESHOLD = 0.8   # see docs/evaluation-report.md section 15 for how this was chosen


def _clip01(x: float) -> float:
    return max(0.0, min(1.0, x))


def score_pair(flows, min_flows: int = MIN_FLOWS) -> dict | None:
    """Score ``(start_ts, bytes, duration_s)`` tuples sorted by start; None if not scorable."""
    if len(flows) < max(min_flows, 4):
        return None
    times = [f[0] for f in flows]
    cad = cadence_stats(times)
    if cad is None:
        return None
    gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
    med = statistics.median(gaps)
    if med < MIN_GAP_S:
        return None
    jitter = statistics.median(abs(g - med) for g in gaps) / med
    sizes = [float(f[1]) for f in flows]
    mean_b = statistics.fmean(sizes)
    size_cv = statistics.pstdev(sizes) / mean_b if mean_b > 0 else 1.0
    parts = (cad["regularity"], _clip01(1.0 - jitter), _clip01(1.0 - size_cv))
    return {
        "score": round(sum(parts) / 3.0, 4), "n": len(flows),
        "median_gap_s": round(med, 3), "regularity": parts[0],
        "jitter_ratio": round(jitter, 4), "size_cv": round(size_cv, 4),
        "median_duration_s": round(statistics.median(f[2] for f in flows), 3),
    }


def parse_allowlist(entries) -> tuple[list, list[str]]:
    """Split entries into IP networks (address or CIDR) and lower-case domain suffixes."""
    nets, domains = [], []
    for raw in entries or ():
        e = str(raw).strip().lower()
        if not e:
            continue
        try:
            nets.append(ipaddress.ip_network(e, strict=False))
        except ValueError:
            domains.append(e.lstrip("*."))
    return nets, domains


def is_allowed(allow: tuple[list, list[str]], ip: str, sni: str | None) -> bool:
    nets, domains = allow
    try:
        addr = ipaddress.ip_address(ip)
        if any(addr in n for n in nets if n.version == addr.version):
            return True
    except ValueError:
        pass
    s = (sni or "").lower().rstrip(".")
    return bool(s) and any(s == d or s.endswith("." + d) for d in domains)


class BeaconTracker:
    """Streaming wrapper: feed flow records, get a verdict when a pair crosses the threshold."""

    def __init__(self, threshold: float = DEFAULT_THRESHOLD, min_flows: int = MIN_FLOWS,
                 window: int = WINDOW, allowlist=()):
        self.threshold = float(threshold)
        self.min_flows = int(min_flows)
        self.window = max(int(window), self.min_flows)
        self.allow = parse_allowlist(allowlist)
        self.pairs: OrderedDict[tuple[str, str], deque] = OrderedDict()

    def reset(self) -> None:
        self.pairs.clear()

    def observe(self, record: dict) -> dict | None:
        """Count this flow; return the pair verdict (``pair``, ``sni``, stats) if it alerts."""
        host, ip = _strip_port(record.get("src")), _strip_port(record.get("dst"))
        t = record.get("start_ts")
        if t is None:
            t = record.get("last_ts")
        if not host or not ip or t is None:
            return None
        key = (host, ip)
        buf = self.pairs.pop(key, None) or deque(maxlen=self.window)
        buf.append((float(t), int(record.get("bytes") or 0), float(record.get("duration") or 0.0)))
        self.pairs[key] = buf
        while len(self.pairs) > PAIR_CAP:
            self.pairs.popitem(last=False)
        if len(buf) < self.min_flows or is_allowed(self.allow, ip, record.get("sni")):
            return None
        flows = sorted(buf)     # out-of-order replay; windows are tiny
        s = score_pair(flows, self.min_flows)
        if s is None or s["score"] < self.threshold:
            return None
        return {**s, "pair": key, "sni": record.get("sni")}


def as_threat(v: dict) -> dict:
    """Verdict -> the threat dict the alert layer expects (metadata-only evidence)."""
    def sig(name, detail, value, unit):
        return {"signal": name, "weight": 0.5, "detail": detail, "value": value, "unit": unit}
    return {
        "threat_type": "C2_BEACONING",
        "confidence": round(min(0.95, v["score"]), 3),
        "supporting": [
            sig("periodic_forward_timing",
                f"{v['n']} flows from {v['pair'][0]} to {v['pair'][1]}, one every "
                f"~{v['median_gap_s']:.1f}s (jitter {v['jitter_ratio']:.2f} of the gap)",
                v["median_gap_s"], "s"),
            sig("pair_beacon_score", f"pair score {v['score']:.2f} (gap regularity "
                f"{v['regularity']:.2f}, flow-size cv {v['size_cv']:.2f})", v["score"], "ratio"),
        ],
        "contradicting": [],
    }
