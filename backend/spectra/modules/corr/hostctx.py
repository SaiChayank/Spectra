"""Host and destination context for corroborated beaconing (v3, ci/prereg/e22.json; docs/35 E2.2, E2.6, E6-lite, E4-lite).

Metadata only: every input is a flow *record* field (addresses, start time, duration, forward bytes, SNI, JA3/JA4) and nothing
else is read or kept, so no payload byte can reach this state.  All state is bounded (caps below) and every clock is the capture
clock (flow timestamps), never the wall clock.

Three parts, all relative to a learning window that ends at ``learn_until`` (a capture timestamp):

* :class:`PeriodicityLearner` (signal **P**): destinations that some internal host reached periodically inside the window
  (>= 12 unique seconds and gap regularity G >= 0.8, G as in :mod:`.beacon`) become "expected periodic" until they expire.
* :class:`HostContext` (signals **R**, **F**, **I** + reported host-window statistics): destination novelty and prevalence across
  hosts, fingerprint novelty and user count, the isolation-forest flag share per pair, and per host per window flow / destination /
  SNI counts with the new-destination rate.
* :class:`CorroboratedBeacon`: the fixed fusion rule ``alert = B and not P and (R or F or I)``.  A beacon verdict alone never alerts.
"""

from __future__ import annotations

import ipaddress
import math
from collections import OrderedDict, deque

from .beacon import DEFAULT_THRESHOLD, INTERNAL_NETS, BeaconTracker, _spread
from .graph import _strip_port

LEARN_MIN_UNIQUE = 12          # unique whole seconds in the window before a pair can be learned periodic
LEARN_G = 0.8                  # gap regularity needed to learn a destination as periodic
LEARN_CAP = 4096               # learned destinations kept (oldest dropped first)
LEARN_EXPIRY_S = 7 * 86400.0   # a learned destination stops suppressing this long after the window ends
RARE_SHARE = 0.10              # "rare" = used by <= max(1, ceil(10 % of hosts)) hosts
WINDOW_S = 3600.0              # host statistics window
KEEP_WINDOWS = 24              # finished windows kept per host
SECONDS_KEEP = 512             # unique seconds kept per pair while learning
CAP_HOSTS = 4096               # hosts tracked
CAP_KEYS = 65536               # destinations / fingerprints / pairs tracked
CAP_MEMBERS = 64               # hosts remembered per destination or fingerprint (counts stop growing beyond, they are only compared to a limit)
CAP_WINDOW_SET = 1024          # distinct destinations / SNIs remembered inside one host window
CAP_PAIR_FPS = 8               # fingerprints remembered per pair


def _bounded_put(d: OrderedDict, key, value, cap: int):
    d[key] = value
    d.move_to_end(key)
    while len(d) > cap:
        d.popitem(last=False)
    return value


class _Nets:
    def __init__(self, nets):
        self.nets = [ipaddress.ip_network(str(n).strip(), strict=False) for n in nets]   # bad entry: raises

    def inside(self, ip: str) -> bool | None:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        return any(a in n for n in self.nets if n.version == a.version)


def flow_key(record: dict, nets: _Nets) -> tuple[str, str, str, bool] | None:
    """(host, destination key, destination ip, outbound) for a flow whose source is internal, else None.
    The destination key is the SNI when the flow has one, else the destination IP (the v2a1 pair key)."""
    host, ip = _strip_port(record.get("src")), _strip_port(record.get("dst"))
    if not host or not ip or not nets.inside(host):
        return None
    sni = (record.get("sni") or "").lower().rstrip(".") or None
    return host, sni or ip, ip, nets.inside(ip) is False


def fingerprint(record: dict) -> str | None:
    """JA4 of the client hello if present, else JA3; None for a flow without one."""
    return record.get("ja4") or record.get("ja3") or None


def _rare_limit(n_hosts: int) -> int:
    return max(1, math.ceil(RARE_SHARE * n_hosts))


class PeriodicityLearner:
    """Signal P: destinations seen periodically inside the learning window.  Bounded; no hand-written list."""

    def __init__(self, learn_until: float, cap: int = LEARN_CAP, expiry_s: float = LEARN_EXPIRY_S):
        self.learn_until = float(learn_until)
        self.cap = int(cap)
        self.expiry_s = float(expiry_s)
        self._seconds: OrderedDict[tuple[str, str], deque] = OrderedDict()
        self.learned: OrderedDict[str, dict] = OrderedDict()
        self.finalized = False

    def observe(self, host: str, key: str, t: float) -> None:
        if self.finalized or t >= self.learn_until:
            return
        q = self._seconds.get((host, key))
        if q is None:
            q = _bounded_put(self._seconds, (host, key), deque(maxlen=SECONDS_KEEP), CAP_KEYS)
        s = int(t // 1)
        if not q or q[-1] != s:
            q.append(s)

    def finalize(self) -> None:
        """Close the window: learn every destination with a regular pair; drop the raw seconds."""
        if self.finalized:
            return
        for (host, key), q in self._seconds.items():
            secs = sorted(set(q))
            if len(secs) < LEARN_MIN_UNIQUE:
                continue
            gaps = [b - a for a, b in zip(secs, secs[1:], strict=False)]
            g = _spread(gaps)
            if g >= LEARN_G and key not in self.learned:
                _bounded_put(self.learned, key, {"host": host, "G": round(g, 4), "unique_seconds": len(secs),
                                                 "expires": self.learn_until + self.expiry_s}, self.cap)
        self._seconds.clear()
        self.finalized = True

    def expected(self, key: str, now: float) -> bool:
        e = self.learned.get(key)
        return e is not None and now < e["expires"]


class HostContext:
    """Signals R, F, I and per-host window statistics, relative to the learning window."""

    def __init__(self, learn_until: float, internal_nets=INTERNAL_NETS, window_s: float = WINDOW_S):
        self.learn_until = float(learn_until)
        self.nets = _Nets(internal_nets)
        self.window_s = float(window_s)
        self.dest_learned: OrderedDict[str, None] = OrderedDict()      # keys seen in the learning window
        self.fp_learned: OrderedDict[str, None] = OrderedDict()
        self.dest_first: OrderedDict[str, float] = OrderedDict()       # first time any internal host reached the key
        self.dest_users: OrderedDict[str, set] = OrderedDict()         # hosts reaching the key after the window
        self.fp_users: OrderedDict[str, set] = OrderedDict()
        self.hosts_after: OrderedDict[str, None] = OrderedDict()
        self.pair_fps: OrderedDict[tuple[str, str], set] = OrderedDict()
        self.pair_if: OrderedDict[tuple[str, str], list] = OrderedDict()   # [flagged, scored] after the window
        self.windows: OrderedDict[str, dict] = OrderedDict()           # current window per host
        self.history: OrderedDict[str, deque] = OrderedDict()          # finished windows per host
        self.now = float("-inf")

    # -- feeding ------------------------------------------------------------------------------------------------------------

    def observe(self, record: dict, if_flag: bool | None = None) -> tuple[str, str] | None:
        """Count one flow; returns the (host, destination key) pair for outbound flows from an internal host, else None."""
        k = flow_key(record, self.nets)
        t = record.get("start_ts")
        if k is None or t is None:
            return None
        host, key, _ip, outbound = k
        t = float(t)
        self.now = max(self.now, t + float(record.get("duration") or 0.0))
        fp = fingerprint(record)
        if key not in self.dest_first:
            _bounded_put(self.dest_first, key, t, CAP_KEYS)
        self._window(host, key, record, t)
        if t < self.learn_until:
            _bounded_put(self.dest_learned, key, None, CAP_KEYS)
            if fp:
                _bounded_put(self.fp_learned, fp, None, CAP_KEYS)
            return (host, key) if outbound else None
        _bounded_put(self.hosts_after, host, None, CAP_HOSTS)
        users = self.dest_users.get(key) or _bounded_put(self.dest_users, key, set(), CAP_KEYS)
        if len(users) < CAP_MEMBERS:
            users.add(host)
        if fp:
            fu = self.fp_users.get(fp) or _bounded_put(self.fp_users, fp, set(), CAP_KEYS)
            if len(fu) < CAP_MEMBERS:
                fu.add(host)
        if not outbound:
            return None
        pair = (host, key)
        if fp:
            pf = self.pair_fps.get(pair) or _bounded_put(self.pair_fps, pair, set(), CAP_KEYS)
            if len(pf) < CAP_PAIR_FPS:
                pf.add(fp)
        if if_flag is not None:
            c = self.pair_if.get(pair) or _bounded_put(self.pair_if, pair, [0, 0], CAP_KEYS)
            c[0] += int(bool(if_flag))
            c[1] += 1
        return pair

    def _window(self, host: str, key: str, record: dict, t: float) -> None:
        w = self.windows.get(host)
        start = t - (t % self.window_s)
        if w is None or start != w["start"]:
            if w is not None:
                h = self.history.get(host) or _bounded_put(self.history, host, deque(maxlen=KEEP_WINDOWS), CAP_HOSTS)
                h.append(self._summary(w))
            w = _bounded_put(self.windows, host, {"start": start, "flows": 0, "dests": set(), "snis": set(), "new": 0},
                             CAP_HOSTS)
        w["flows"] += 1
        if len(w["dests"]) < CAP_WINDOW_SET:
            w["dests"].add(key)
        sni = (record.get("sni") or "").lower().rstrip(".")
        if sni and len(w["snis"]) < CAP_WINDOW_SET:
            w["snis"].add(sni)
        if self.dest_first.get(key) == t:      # this flow is the network's first contact with the key
            w["new"] += 1

    @staticmethod
    def _summary(w: dict) -> dict:
        return {"start": w["start"], "flows": w["flows"], "distinct_destinations": len(w["dests"]),
                "distinct_snis": len(w["snis"]), "new_destinations": w["new"],
                "new_destination_rate": round(w["new"] / w["flows"], 4) if w["flows"] else 0.0}

    # -- signals ------------------------------------------------------------------------------------------------------------

    @property
    def n_hosts(self) -> int:
        return len(self.hosts_after)

    def rare_destination(self, key: str) -> dict:
        """R: not seen in the learning window and reached by few hosts after it."""
        novel = key not in self.dest_learned
        users = len(self.dest_users.get(key, ()))
        limit = _rare_limit(self.n_hosts)
        first = self.dest_first.get(key)
        return {"fires": novel and users <= limit, "novel": novel, "prevalence": users, "limit": limit,
                "prevalence_measurable": self.n_hosts > 1,
                "age_s": round(self.now - first, 3) if first is not None else None}

    def rare_fingerprint(self, pair: tuple[str, str]) -> dict:
        """F: the pair used a fingerprint not seen in the window and used by few hosts after it."""
        limit = _rare_limit(self.n_hosts)
        rare = sorted(fp for fp in self.pair_fps.get(pair, ())
                      if fp not in self.fp_learned and len(self.fp_users.get(fp, ())) <= limit)
        return {"fires": bool(rare), "rare_fingerprints": len(rare), "limit": limit,
                "has_fingerprint": bool(self.pair_fps.get(pair))}

    def if_share(self, pair: tuple[str, str]) -> float | None:
        c = self.pair_if.get(pair)
        return c[0] / c[1] if c and c[1] else None

    def host_windows(self, host: str) -> list[dict]:
        out = list(self.history.get(host, ()))
        if host in self.windows:
            out.append(self._summary(self.windows[host]))
        return out


class CorroboratedBeacon:
    """Fixed fusion (e22): pair alert = B and not P and (R or F or I).  Flows must arrive in start-time order."""

    def __init__(self, learn_until: float, tau_i: float | None, internal_nets=INTERNAL_NETS,
                 threshold: float = DEFAULT_THRESHOLD, min_flows: int = 12, allowlist=()):
        self.threshold = float(threshold)
        self.tau_i = tau_i
        self.beacon = BeaconTracker(threshold=-1.0, min_flows=min_flows, allowlist=allowlist, internal_nets=internal_nets)
        self.ctx = HostContext(learn_until, internal_nets)
        self.learner = PeriodicityLearner(learn_until)
        self.after: OrderedDict[tuple[str, str], int] = OrderedDict()    # flows per pair at/after the window
        self.last: OrderedDict[tuple[str, str], dict] = OrderedDict()    # newest beacon verdict per pair after the window

    @property
    def learn_until(self) -> float:
        return self.ctx.learn_until

    def observe(self, record: dict, if_flag: bool | None = None) -> dict | None:
        """Feed one flow; returns the fused evaluation when this flow makes its pair alert, else None."""
        t = record.get("start_ts")
        if t is None:
            return None
        t = float(t)
        pair = self.ctx.observe(record, if_flag)
        v = self.beacon.observe(record)
        if pair is None:
            return None
        if t < self.learn_until:
            self.learner.observe(pair[0], pair[1], t)
            return None
        self.learner.finalize()
        self.after[pair] = self.after.get(pair, 0) + 1
        self.after.move_to_end(pair)
        while len(self.after) > CAP_KEYS:
            self.after.popitem(last=False)
        if v is not None:
            _bounded_put(self.last, pair, v, CAP_KEYS)
        ev = self.evaluate(pair)
        return ev if ev["alert"] else None

    def evaluate(self, pair: tuple[str, str]) -> dict:
        v = self.last.get(pair)
        b_score = v["score"] if v else 0.0
        b = b_score >= self.threshold
        p = self.learner.expected(pair[1], self.ctx.now)
        r = self.ctx.rare_destination(pair[1])
        f = self.ctx.rare_fingerprint(pair)
        share = self.ctx.if_share(pair)
        i = share is not None and self.tau_i is not None and share >= self.tau_i
        corroborated = r["fires"] or f["fires"] or i
        alert = b and not p and corroborated
        return {"pair": pair, "flows_after_window": self.after.get(pair, 0), "B": b, "B_score": b_score,
                "components": v["components"] if v else None, "P": p, "R": r, "F": f,
                "I": {"fires": i, "share": round(share, 4) if share is not None else None, "tau": self.tau_i},
                "corroborated": corroborated, "alert": alert,
                "fused_score": b_score if (not p and corroborated) else 0.0, "verdict": v}

    def results(self, min_flows: int = 20) -> list[dict]:
        """Every pair with at least ``min_flows`` flows at/after the window, evaluated now."""
        self.learner.finalize()
        return [self.evaluate(p) for p, n in self.after.items() if n >= min_flows]


class LiveCorroboration:
    """Streaming use in the detection service: the learning window starts at the first flow seen."""

    def __init__(self, config):
        self.cfg = config
        self.engine: CorroboratedBeacon | None = None

    def observe(self, record: dict, anomaly: bool | None = None) -> dict | None:
        if self.engine is None:
            t = record.get("start_ts")
            if t is None:
                return None
            c = self.cfg
            self.engine = CorroboratedBeacon(
                float(t) + 3600.0 * float(c.corroboration_learn_hours),
                c.corroboration_tau_i if c.corroboration_tau_i >= 0 else None,
                internal_nets=c.beaconing_internal_nets, threshold=c.beaconing_threshold,
                min_flows=c.beaconing_min_flows, allowlist=c.beaconing_allowlist)
        return self.engine.observe(record, anomaly)


def as_threat(ev: dict) -> dict:
    """Fused evaluation -> threat dict for the alert layer (metadata-only evidence)."""
    from .beacon import as_threat as beacon_threat
    t = beacon_threat(ev["verdict"])
    why = [name for name, ok in (("rare destination", ev["R"]["fires"]), ("rare fingerprint", ev["F"]["fires"]),
                                 ("anomaly-model flags", ev["I"]["fires"])) if ok]
    t["supporting"].append({"signal": "corroboration", "weight": 0.5, "detail": "corroborated by " + ", ".join(why),
                            "value": len(why), "unit": "signals"})
    return t
