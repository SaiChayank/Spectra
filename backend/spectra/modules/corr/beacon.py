"""Module 7b: host-pair beaconing scorer v2 (docs/plan-beaconing-detector.md "v2", ci/prereg/e21.json).

Independent of the isolation forest: one score per (source host, SNI-or-destination-IP) pair from flow
*metadata only* (start time, forward byte count, duration).  Design after RITA's published method; every
number is preregistered and nothing is fitted to data.  Components, each in [0, 1], robust statistics only:

  G gaps        mean of (1 - |bowley|) and (1 - min(1, MAD/median)) of start-to-start gaps
  S sizes       the same two formulas on forward bytes (0 if the median is 0)
  D persistence active hour bins / total hour bins from first_seen to now (newest 24)
  H flatness    1 - min(1, MAD/median) of the hourly flow counts, empty hours included (0 if median 0)

G and S need >= 12 flows and a median gap >= 1 s; D and H need a span >= 3 h.  A score exists only when D
and at least one of G/H are available; it is the unweighted mean of the available components.  "Now" is the
largest flow start time seen (capture clock).  Quartiles use the inclusive method (statistics.quantiles).
Nothing can alert in the first 3 h of a pair.  Known periodic services belong in the allow-list.
"""

from __future__ import annotations

import ipaddress
import statistics
from collections import OrderedDict, deque

from .graph import PAIR_CAP, _strip_port

MIN_FLOWS = 12       # flows before G and S exist
KEEP = 512           # newest flows kept per pair
MIN_GAP_S = 1.0      # median start-to-start gap below this is not a beacon
MIN_SPAN_S = 3 * 3600.0   # D and H need this much first_seen -> now
BINS = 24            # newest hour bins used for D and H
MAX_IPS = 16         # destination IPs remembered per SNI pair
DEFAULT_THRESHOLD = 0.8   # preregistered, ci/prereg/e21.json


def _spread(x) -> float:
    """Mean of (1 - |bowley|) and (1 - min(1, MAD/median)); 0 when the median is not positive."""
    q1, q2, q3 = statistics.quantiles(x, n=4, method="inclusive")
    if q2 <= 0:
        return 0.0
    bowley = (q3 + q1 - 2 * q2) / (q3 - q1) if q3 != q1 else 0.0
    mad = statistics.median(abs(v - q2) for v in x)
    return (1.0 - min(1.0, abs(bowley)) + 1.0 - min(1.0, mad / q2)) / 2.0


def score_pair(flows, hours: dict, first_seen: float, now: float, min_flows: int = MIN_FLOWS) -> dict | None:
    """Score a pair from ``(start_ts, fwd_bytes, duration_s)`` tuples (sorted by start) and its
    ``{hour: flow_count}`` bins; None when there is no verdict (too little evidence)."""
    comps: dict[str, float] = {}
    med_gap = None
    if len(flows) >= max(min_flows, 4):
        gaps = [b[0] - a[0] for a, b in zip(flows, flows[1:], strict=False)]
        med_gap = statistics.median(gaps)
        if med_gap >= MIN_GAP_S:
            comps["G"] = _spread(gaps)
            comps["S"] = _spread([float(f[1]) for f in flows])
    if now - first_seen >= MIN_SPAN_S:
        hi = int(now // 3600)
        lo = max(int(first_seen // 3600), hi - BINS + 1)
        counts = [hours.get(h, 0) for h in range(lo, hi + 1)]
        comps["D"] = sum(1 for c in counts if c) / len(counts)
        med = statistics.median(counts)
        comps["H"] = 1.0 - min(1.0, statistics.median(abs(c - med) for c in counts) / med) if med > 0 else 0.0
    if "D" not in comps or not ("G" in comps or "H" in comps):
        return None
    return {
        "score": round(sum(comps.values()) / len(comps), 4), "components": {k: round(v, 4) for k, v in comps.items()},
        "n": len(flows), "span_h": round((now - first_seen) / 3600.0, 2),
        "median_gap_s": round(med_gap, 3) if med_gap is not None else None,
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

    def __init__(self, threshold: float = DEFAULT_THRESHOLD, min_flows: int = MIN_FLOWS, allowlist=()):
        self.threshold = float(threshold)
        self.min_flows = int(min_flows)
        self.allow = parse_allowlist(allowlist)
        self.pairs: OrderedDict[tuple[str, str], dict] = OrderedDict()
        self.now = float("-inf")

    def reset(self) -> None:
        self.pairs.clear()
        self.now = float("-inf")

    def observe(self, record: dict) -> dict | None:
        """Count this flow; return the pair verdict (``pair``, ``sni``, ``dst_ips``, stats) if it alerts."""
        host, ip = _strip_port(record.get("src")), _strip_port(record.get("dst"))
        t = record.get("start_ts")
        if t is None:
            t = record.get("last_ts")
        if not host or not ip or t is None:
            return None
        t = float(t)
        sni = (record.get("sni") or "").lower().rstrip(".") or None
        key = (host, sni or ip)
        dur = float(record.get("duration") or 0.0)
        self.now = max(self.now, t)
        st = self.pairs.pop(key, None) or {"flows": deque(maxlen=KEEP), "first": t, "hours": {}, "ips": set()}
        self.pairs[key] = st
        while len(self.pairs) > PAIR_CAP:
            self.pairs.popitem(last=False)
        st["flows"].append((t, int(record.get("bytes_fwd") or 0), dur))
        st["first"] = min(st["first"], t)
        if len(st["ips"]) < MAX_IPS:
            st["ips"].add(ip)
        end = int((t + dur) // 3600)
        for h in range(max(int(t // 3600), end - BINS + 1), end + 1):     # a long flow counts in every hour it spans
            st["hours"][h] = st["hours"].get(h, 0) + 1
        floor = int(self.now // 3600) - BINS + 1
        for h in [h for h in st["hours"] if h < floor]:
            del st["hours"][h]
        if is_allowed(self.allow, ip, sni):
            return None
        s = score_pair(sorted(st["flows"]), st["hours"], st["first"], self.now, self.min_flows)
        if s is None or s["score"] < self.threshold:
            return None
        return {**s, "pair": (host, key[1]), "sni": sni, "dst_ips": sorted(st["ips"])}


def as_threat(v: dict) -> dict:
    """Verdict -> the threat dict the alert layer expects (metadata-only evidence)."""
    def sig(name, detail, value, unit):
        return {"signal": name, "weight": 0.5, "detail": detail, "value": value, "unit": unit}
    comps = ", ".join(f"{k} {x:.2f}" for k, x in v["components"].items())
    dest = v["sni"] or ", ".join(v["dst_ips"])
    timing = (f"{v['n']} flows over {v['span_h']:.1f} h from {v['pair'][0]} to {dest}"
              + (f", one every ~{v['median_gap_s']:.1f}s" if v["median_gap_s"] else ""))
    return {
        "threat_type": "C2_BEACONING",
        "confidence": round(min(0.95, v["score"]), 3),
        "supporting": [
            sig("periodic_forward_timing", timing, v["median_gap_s"] or 0.0, "s"),
            sig("pair_beacon_score", f"pair score {v['score']:.2f} (components available: {comps})",
                v["score"], "ratio"),
        ],
        "contradicting": [],
    }
