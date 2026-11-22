"""E2.2 rare destination / first seen, retrospective scorer (ci/prereg/e22.json, frozen 2026-11-20).

One window = one capture day of flow *metadata* (source, destination, start time, duration, SNI).  For each
internal host h and external destination d (lower-cased SNI, else destination IP; the E21 key):

  N             distinct internal hosts with an external flow in the window
  prevalence(d) distinct internal hosts with a flow to d
  hours(h,d)    distinct whole capture-clock hours with a flow h->d (a long flow counts in every hour it spans)
  s(h,d)        (1 / prevalence(d)) * min(1, hours(h,d) / 3), only for pairs with >= 2 flows
  host score    max s(h,d); evidence = top 3 destinations

N < 10 gives no verdict (``None``).  Every constant is preregistered; nothing is fitted.  Not wired into the
product: the flag stays off until the E22 gate passes.
"""

from __future__ import annotations

import ipaddress

from .beacon import INTERNAL_NETS
from .graph import _strip_port

MIN_HOSTS = 10        # N below this: no verdict
MIN_PAIR_FLOWS = 2
FULL_HOURS = 3        # P reaches 1 at this many distinct hours
THRESHOLD = 0.5       # reported only, not part of the ranking gate
TOP = 3


def score_window(records, internal_nets=INTERNAL_NETS) -> dict | None:
    """Host scores for one window, or None when fewer than MIN_HOSTS internal hosts talk out."""
    nets = [ipaddress.ip_network(str(n).strip(), strict=False) for n in internal_nets]

    def inside(a) -> bool:
        return any(a in n for n in nets if n.version == a.version)

    pairs: dict = {}      # (host, dest) -> {"flows", "hours", "ips"}
    seen = set()
    for r in records:
        host, ip = _strip_port(r.get("src")), _strip_port(r.get("dst"))
        t = r.get("start_ts")
        if not host or not ip or t is None:
            continue
        try:
            if not inside(ipaddress.ip_address(host)) or inside(ipaddress.ip_address(ip)):
                continue
        except ValueError:
            continue
        t, dur = float(t), float(r.get("duration") or 0.0)
        sni = (r.get("sni") or "").lower().rstrip(".") or None
        uid = (r.get("src"), r.get("dst"), t)
        if uid in seen:      # the same flow in two overlapping capture parts
            continue
        seen.add(uid)
        st = pairs.setdefault((host, sni or ip), {"flows": 0, "hours": set(), "ips": set()})
        st["flows"] += 1
        st["hours"].update(range(int(t // 3600), int((t + dur) // 3600) + 1))
        st["ips"].add(ip)
    hosts = {h for h, _ in pairs}
    if len(hosts) < MIN_HOSTS:
        return None
    prevalence: dict = {}
    for _, d in pairs:
        prevalence[d] = prevalence.get(d, 0) + 1
    per_host: dict = {h: [] for h in hosts}
    for (h, d), st in pairs.items():
        if st["flows"] < MIN_PAIR_FLOWS:
            continue
        s = (1.0 / prevalence[d]) * min(1.0, len(st["hours"]) / FULL_HOURS)
        per_host[h].append({"dest": d, "score": s, "prevalence": prevalence[d], "hours": len(st["hours"]),
                            "flows": st["flows"], "dst_ips": sorted(st["ips"])[:16]})
    out = {}
    for h, ev in per_host.items():
        ev.sort(key=lambda e: (-e["score"], -e["flows"], e["dest"]))
        out[h] = {"score": ev[0]["score"] if ev else 0.0, "alert": bool(ev) and ev[0]["score"] >= THRESHOLD, "top": ev[:TOP]}
    return {"N": len(hosts), "hosts": out}
