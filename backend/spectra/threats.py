"""Explainable threat classification over flagged flows.

The anomaly detector answers *"is this flow unusual?"*; this layer answers
*"what behaviour does it look like, and why?"* — strictly **on top of** the
detector, never instead of it.  Only flows the detector already flagged are
classified, and a flow only receives a specific category when independent
behavioural signals accumulate enough evidence.  Everything else stays
``UNKNOWN_ANOMALY``: the honest answer rather than a guess.

Evidence model
--------------
Each category is a small set of named signals with fixed weights (0.3 weak,
0.4 moderate, 0.5 strong); a signal also carries the machine-readable
``value``/``unit`` behind it when one exists (the alert layer turns those
into structured evidence — see :mod:`spectra.evidence`).  A category
qualifies when

* its weighted support reaches the category minimum (see ``_MINIMUMS``), **and**
* at least two distinct signals fired — one strong number alone never
  identifies a threat,

and the qualifying category with the highest support wins (ties break by
``THREAT_TYPES`` order).  Contradicting evidence — e.g. *irregular timing*
against beaconing — lowers the confidence:

``confidence = support / (support + oppose)``, clamped to [0.30, 0.95].

When no category qualifies the flow stays ``UNKNOWN_ANOMALY`` and carries the
closest sub-threshold ``candidate`` plus ``insufficient_evidence: true``.
Signals describe **behaviour only**: this module never claims malware
identity for a flow.

The classifier is a pure function of ``(record, features, window)`` so it is
directly unit-testable, and it never raises into the pipeline: the detection
service wraps the call in :meth:`FailureTracker.guard`, falling back to
:func:`unknown_threat`.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Callable

from .features.extractor import FEATURE_NAMES

#: The categories from the classification prompt, in preference order (a
#: support tie between two categories keeps the earlier one).
THREAT_TYPES: tuple[str, ...] = (
    "C2_BEACONING",
    "RECONNAISSANCE",
    "DATA_EXFILTRATION_SUSPECTED",
    "TLS_ANOMALY",
    "QUIC_ANOMALY",
    "VOLUMETRIC_ANOMALY",
    "UNUSUAL_ENDPOINT_BEHAVIOR",
    "UNKNOWN_ANOMALY",
)

#: Explicit "we cannot say" verdict (never a placeholder category name).
UNKNOWN = "UNKNOWN_ANOMALY"

#: Prior-flow context window used per classification (bounded work per call).
THREAT_WINDOW = 500

_CONF_CAP = 0.95          # never overstate certainty
_CONF_FLOOR = 0.30        # a qualified category is never presented as a coin flip
_UNKNOWN_CAP = 0.45       # an unknown verdict always stays below 0.5
_MIN_SIGNALS = 2          # one strong signal alone never classifies a threat

_LEGACY_TLS = frozenset({"SSL 3.0", "TLS 1.0", "TLS 1.1"})
_STANDARD_QUIC = frozenset({"QUIC v1", "QUIC v2"})


# -- small helpers ------------------------------------------------------------

def _sig(signal: str, weight: float, detail: str,
         value: float | str | bool | None = None,
         unit: str | None = None) -> dict:
    """One named piece of evidence for/against a category.

    ``value``/``unit`` make the signal machine-readable for the alert layer's
    structured evidence (see :mod:`spectra.evidence`); ``detail`` stays the
    human phrasing either way.
    """
    out: dict = {"signal": signal, "weight": float(weight), "detail": detail}
    if value is not None:
        if isinstance(value, bool) or isinstance(value, str):
            out["value"] = value
        else:
            out["value"] = round(float(value), 4)
    if value is not None and unit is not None:
        out["unit"] = unit
    return out


def _features(feats: Any) -> dict[str, float]:
    """Feature vector -> ``{name: value}``; missing/unusable input is empty."""
    if feats is None:
        return {}
    try:
        values = list(feats)
    except TypeError:
        return {}
    return {name: float(values[i]) for i, name in enumerate(FEATURE_NAMES)
            if i < len(values)}


def _f(f: dict[str, float], name: str) -> float:
    return f.get(name, 0.0)


def _rfloat(rec: dict, key: str) -> float:
    try:
        return float(rec.get(key) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _split(addr: Any) -> tuple[str, str]:
    """``"10.0.0.1:443"`` -> ``("10.0.0.1", "443")`` (rpartition is IPv6-safe)."""
    if not isinstance(addr, str) or not addr:
        return "", ""
    host, sep, port = addr.rpartition(":")
    return (host, port) if sep else (addr, "")


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _cv(values: list[float]) -> float:
    """Coefficient of variation (std/mean); 0.0 when undefined."""
    if not values:
        return 0.0
    m = _mean(values)
    if m <= 0:
        return 0.0
    var = sum((v - m) ** 2 for v in values) / len(values)
    return (var ** 0.5) / m


# -- context (bounded window of prior flows) ----------------------------------

def _build_context(record: dict, window: list[dict]) -> dict:
    """Aggregate evidence from the flows that precede *record* in the window.

    The current flow is never part of its own window — repetition means
    *"seen before"*, not *"counting myself"*.
    """
    src_host, _ = _split(record.get("src"))
    dst_host, dst_port = _split(record.get("dst"))
    ctx: dict[str, Any] = {
        "window_len": len(window),
        "src_host": src_host,
        "dst_host": dst_host,
        "dst_port": dst_port,
        "pair_count": 0,           # same src -> same dst host, before this flow
        "endpoint_count": 0,       # same src -> same dst host:port (retries)
        "src_hosts": set(),        # distinct dst hosts contacted by this src
        "src_ports": set(),        # distinct dst ports contacted by this src
        "src_flows": 0,
        "src_short": 0,            # short/empty exchanges (scan-like)
        "src_durations": [],       # durations of this src's prior flows
        "src_bytes": [],           # sizes of this src's prior flows (baseline)
        "src_rates": [],           # bytes/s of this src's prior flows
        "dst_records": [],         # prior flows to this dst host (any src)
        "dst_bytes": [],           # their sizes (endpoint behaviour baseline)
        "dst_ports_seen": set(),   # ports previously used on this host
        "dst_small": 0,            # prior same-pair flows of <= 10 KB
        "tls_flows": 0,
        "ja3": Counter(),
        "ja4": Counter(),
    }
    for r in window:
        if not isinstance(r, dict):
            continue
        rh, _ = _split(r.get("src"))
        rd, rp = _split(r.get("dst"))
        dur = _rfloat(r, "duration")
        size = _rfloat(r, "bytes")
        is_src = rh == src_host
        if is_src:
            ctx["src_flows"] += 1
            ctx["src_hosts"].add(rd)
            ctx["src_ports"].add(rp)
            if dur <= 0.5 and _rfloat(r, "packets") <= 4:
                ctx["src_short"] += 1
            ctx["src_durations"].append(dur)
            ctx["src_bytes"].append(size)
            if dur > 0:
                ctx["src_rates"].append(size / dur)
        if rd == dst_host:
            ctx["dst_records"].append(r)
            ctx["dst_bytes"].append(size)
            ctx["dst_ports_seen"].add(rp)
            if is_src:
                ctx["pair_count"] += 1
                if size <= 10_000:
                    ctx["dst_small"] += 1
                if rp == dst_port:
                    ctx["endpoint_count"] += 1
        if r.get("tls_version"):
            ctx["tls_flows"] += 1
            if r.get("ja3"):
                ctx["ja3"][r["ja3"]] += 1
            if r.get("ja4"):
                ctx["ja4"][r["ja4"]] += 1
    return ctx


# -- behavioural rules (one per category, in THREAT_TYPES order) ---------------

def _rule_c2(rec: dict, f: dict[str, float], ctx: dict) -> tuple[list, list]:
    """Beaconing: a steady, small, repeated cadence to one destination."""
    sup: list[dict] = []
    opp: list[dict] = []
    mean_iat = _f(f, "iat_fwd_mean_s")
    mad = _f(f, "iat_fwd_mad_s")
    ratio = (mad / mean_iat) if mean_iat > 0 else float("inf")
    if mean_iat >= 0.1 and ratio <= 0.2:
        sup.append(_sig("periodic_forward_timing", 0.5,
                        f"forward IAT mad/mean {ratio:.2f} over {mean_iat:.2f}s "
                        f"spacing (steady cadence)",
                        value=mean_iat, unit="s"))
    if mean_iat > 0 and mad <= 0.05:
        sup.append(_sig("low_timing_mad", 0.3,
                        f"forward IAT mad {mad:.3f}s (near-constant interval)",
                        value=mad, unit="s"))
    if ctx["pair_count"] >= 3:
        sup.append(_sig("repeated_destination", 0.4,
                        f"same src->dst pair seen {ctx['pair_count']} times before",
                        value=ctx["pair_count"], unit="count"))
    b_mean = _f(f, "bytes_mean")
    within_cv = (_f(f, "bytes_std") / b_mean) if b_mean > 0 else 1.0
    cross = (list(ctx["dst_bytes"]) + [_rfloat(rec, "bytes")]
             if ctx["pair_count"] >= 3 else [])
    if within_cv <= 0.35 or (cross and _cv(cross) <= 0.35):
        detail = f"within-flow size cv {within_cv:.2f}"
        if cross:
            detail += f", cross-session size cv {_cv(cross):.2f}"
        sup.append(_sig("similar_packet_sizes", 0.3, detail,
                        value=within_cv, unit="ratio"))
    if ctx["dst_small"] >= 3:
        sup.append(_sig("repeated_small_sessions", 0.4,
                        f"{ctx['dst_small']} prior <=10KB sessions to this host",
                        value=ctx["dst_small"], unit="count"))
    if mean_iat >= 0.1 and ratio > 0.5:
        opp.append(_sig("irregular_timing", 0.3,
                        f"forward IAT mad/mean {ratio:.2f} (no steady cadence)",
                        value=ratio if ratio != float("inf") else None,
                        unit="ratio"))
    if _rfloat(rec, "bytes") >= 1_000_000:
        opp.append(_sig("bulk_transfer", 0.3,
                        f"{_rfloat(rec, 'bytes') / 1e6:.1f} MB exchange (bulk, "
                        f"not a heartbeat)",
                        value=_rfloat(rec, "bytes") / 1e6, unit="MB"))
    return sup, opp


def _rule_recon(rec: dict, f: dict[str, float], ctx: dict) -> tuple[list, list]:
    """Reconnaissance: fan-out probing, many short flows, repeated attempts."""
    sup: list[dict] = []
    opp: list[dict] = []
    if len(ctx["src_hosts"]) >= 8:
        sup.append(_sig("destination_fanout", 0.5,
                        f"{len(ctx['src_hosts'])} distinct dst hosts from one source",
                        value=len(ctx["src_hosts"]), unit="count"))
    if len(ctx["src_ports"]) >= 8:
        sup.append(_sig("port_fanout", 0.4,
                        f"{len(ctx['src_ports'])} distinct dst ports from one source",
                        value=len(ctx["src_ports"]), unit="count"))
    if ctx["src_flows"] >= 5 and ctx["src_short"] / ctx["src_flows"] >= 0.6:
        sup.append(_sig("many_short_flows", 0.4,
                        f"{ctx['src_short']}/{ctx['src_flows']} prior flows were "
                        f"short (<=0.5s, <=4 packets)",
                        value=round(ctx["src_short"] / ctx["src_flows"], 3),
                        unit="ratio"))
    if ctx["endpoint_count"] >= 3:
        sup.append(_sig("repeated_attempts", 0.4,
                        f"{ctx['endpoint_count']} attempts to this host:port before",
                        value=ctx["endpoint_count"], unit="count"))
    if _f(f, "rst_count") >= 1 and _f(f, "payload_ratio") <= 0.1:
        sup.append(_sig("reset_without_payload", 0.3,
                        f"RST with negligible payload (ratio "
                        f"{_f(f, 'payload_ratio'):.2f})",
                        value=_f(f, "payload_ratio"), unit="ratio"))
    if ctx["src_flows"] >= 5 and len(ctx["src_hosts"]) <= 2:
        opp.append(_sig("low_fanout", 0.3,
                        f"only {len(ctx['src_hosts'])} dst hosts across "
                        f"{ctx['src_flows']} flows",
                        value=len(ctx["src_hosts"]), unit="count"))
    if ctx["src_flows"] >= 3 and _mean(ctx["src_durations"]) >= 5.0:
        opp.append(_sig("long_lived_flows", 0.3,
                        f"prior flows average {_mean(ctx['src_durations']):.1f}s "
                        f"(conversations, not probes)",
                        value=_mean(ctx["src_durations"]), unit="s"))
    return sup, opp


def _rule_exfil(rec: dict, f: dict[str, float], ctx: dict) -> tuple[list, list]:
    """Data exfiltration (suspected): outbound-heavy, sustained, off-baseline."""
    sup: list[dict] = []
    opp: list[dict] = []
    fwd = _f(f, "bytes_fwd")
    bwd = _f(f, "bytes_bwd")
    if fwd >= 3 * bwd and fwd >= 50_000:
        sup.append(_sig("outbound_dominance", 0.5,
                        f"{fwd / 1000:.0f}KB out vs {bwd / 1000:.0f}KB back",
                        value=fwd / max(bwd, 1), unit="ratio"))
    dur = _f(f, "duration_s")
    if dur >= 5 and fwd / dur >= 20_000:
        sup.append(_sig("sustained_transfer", 0.4,
                        f"{fwd / dur / 1000:.0f}KB/s outbound held for {dur:.1f}s",
                        value=round(fwd / dur / 1000, 1), unit="KB/s"))
    if ctx["pair_count"] == 0 and ctx["window_len"] >= 10:
        sup.append(_sig("unusual_destination", 0.4,
                        f"src->dst pair unseen in the last "
                        f"{ctx['window_len']} flows",
                        value=True, unit=None))
    total = _rfloat(rec, "bytes") or _f(f, "bytes_total")
    baseline = _mean(ctx["src_bytes"])
    if len(ctx["src_bytes"]) >= 5 and baseline > 0 and total >= 5 * baseline:
        sup.append(_sig("baseline_deviation", 0.4,
                        f"{total / 1000:.0f}KB vs {baseline / 1000:.0f}KB "
                        f"typical for this source",
                        value=round(total / baseline, 2), unit="ratio"))
    if bwd >= 3 * fwd and bwd >= 50_000:
        opp.append(_sig("inbound_dominant", 0.3,
                        f"{bwd / 1000:.0f}KB in vs {fwd / 1000:.0f}KB out "
                        f"(download, not upload)",
                        value=bwd / max(fwd, 1), unit="ratio"))
    if total < 10_000:
        opp.append(_sig("tiny_transfer", 0.3,
                        f"{total / 1000:.0f}KB total (negligible)",
                        value=round(total / 1000, 1), unit="KB"))
    return sup, opp


def _rule_tls(rec: dict, f: dict[str, float], ctx: dict) -> tuple[list, list]:
    """TLS metadata anomalies (only for TLS flows — QUIC is separate)."""
    if rec.get("quic_version"):
        return [], []
    if not (rec.get("tls_version") or _f(f, "tls_present") >= 0.5):
        return [], []
    sup: list[dict] = []
    opp: list[dict] = []
    has_sni = bool(rec.get("sni")) or _f(f, "sni_present") >= 0.5
    version = rec.get("tls_version") or ""
    alpn = list(rec.get("alpn") or [])
    ja3, ja4 = rec.get("ja3"), rec.get("ja4")
    if not has_sni:
        sup.append(_sig("missing_sni", 0.4, "TLS handshake carried no SNI",
                        value=True))
    if version in _LEGACY_TLS:
        sup.append(_sig("legacy_version", 0.4, f"{version} negotiated",
                        value=version))
    if ctx["tls_flows"] >= 10 and (
            (ja3 and ctx["ja3"].get(ja3, 0) <= 1)
            or (ja4 and ctx["ja4"].get(ja4, 0) <= 1)):
        sup.append(_sig("rare_fingerprint", 0.4,
                        f"fingerprint rare among {ctx['tls_flows']} TLS flows "
                        f"in the window",
                        value=ctx["tls_flows"], unit="count"))
    slow = max(_f(f, "handshake_ms"), _f(f, "server_hello_ms"))
    if slow > 1500:
        sup.append(_sig("slow_handshake", 0.4, f"handshake took {slow:.0f}ms",
                        value=round(slow, 1), unit="ms"))
    ciphers = _f(f, "tls_cipher_count")
    if 0 < ciphers <= 2:
        sup.append(_sig("narrow_cipher_offering", 0.3,
                        f"only {ciphers:.0f} cipher offered/selected",
                        value=int(ciphers), unit="count"))
    if not alpn and _f(f, "tls_present") >= 0.5:
        sup.append(_sig("no_alpn", 0.3, "handshake carried no ALPN",
                        value=True))
    if ja3 and ctx["ja3"].get(ja3, 0) >= 5:
        opp.append(_sig("common_fingerprint", 0.3,
                        f"this ja3 seen {ctx['ja3'][ja3]}x before (ordinary "
                        f"client)",
                        value=ctx["ja3"][ja3], unit="count"))
    if 0 < _f(f, "handshake_ms") < 500 and has_sni and alpn:
        opp.append(_sig("healthy_handshake", 0.3,
                        f"fast handshake ({_f(f, 'handshake_ms'):.0f}ms) with "
                        f"SNI + ALPN",
                        value=round(_f(f, "handshake_ms"), 1), unit="ms"))
    if version == "TLS 1.3":
        opp.append(_sig("modern_version", 0.3, "TLS 1.3 negotiated",
                        value=version))
    return sup, opp


def _rule_quic(rec: dict, f: dict[str, float], ctx: dict) -> tuple[list, list]:
    """QUIC metadata anomalies (only for QUIC flows)."""
    version = rec.get("quic_version")
    if not version:
        return [], []
    sup: list[dict] = []
    opp: list[dict] = []
    alpn = [str(a) for a in (rec.get("alpn") or [])]
    if version.startswith("QUIC 0x"):
        sup.append(_sig("unknown_version", 0.5,
                        f"unpublished QUIC version {version}",
                        value=version))
    if "draft" in version or version == "version negotiation":
        sup.append(_sig("draft_or_negotiation", 0.4, f"{version} in use",
                        value=version))
    if not rec.get("sni"):
        sup.append(_sig("missing_sni", 0.4, "QUIC handshake carried no SNI",
                        value=True))
    if alpn and not any(a.lower().startswith("h3") for a in alpn):
        sup.append(_sig("non_h3_alpn", 0.35,
                        f"ALPN {','.join(alpn)} (not HTTP/3)",
                        value=",".join(alpn)))
    if not alpn:
        sup.append(_sig("no_alpn", 0.3, "handshake carried no ALPN",
                        value=True))
    if version in _STANDARD_QUIC:
        opp.append(_sig("standard_version", 0.3, f"{version} (published)",
                        value=version))
    if any(a.lower().startswith("h3") for a in alpn):
        opp.append(_sig("h3_alpn", 0.3, "HTTP/3 negotiated normally",
                        value=",".join(alpn)))
    return sup, opp


def _rule_volumetric(rec: dict, f: dict[str, float], ctx: dict) -> tuple[list, list]:
    """Volumetric anomaly: extreme rate or size for this environment."""
    sup: list[dict] = []
    opp: list[dict] = []
    bps = _f(f, "bytes_per_s")
    pps = _f(f, "packets_per_s")
    total = _rfloat(rec, "bytes") or _f(f, "bytes_total")
    if bps >= 500_000:
        sup.append(_sig("extreme_throughput", 0.5, f"{bps / 1e6:.1f} MB/s",
                        value=round(bps / 1e6, 2), unit="MB/s"))
    if pps >= 2_000:
        sup.append(_sig("high_packet_rate", 0.4, f"{pps:.0f} packets/s",
                        value=round(pps, 1), unit="packets/s"))
    if total >= 5_000_000:
        sup.append(_sig("large_transfer", 0.4, f"{total / 1e6:.1f} MB in one flow",
                        value=round(total / 1e6, 2), unit="MB"))
    baseline = _mean(ctx["src_rates"])
    if len(ctx["src_rates"]) >= 5 and baseline > 0 and bps >= 5 * baseline:
        sup.append(_sig("volume_deviation", 0.3,
                        f"{bps / 1000:.0f}KB/s vs {baseline / 1000:.0f}KB/s "
                        f"typical for this source",
                        value=round(bps / baseline, 2), unit="ratio"))
    if bps < 10_000 and pps < 100:
        opp.append(_sig("low_rate", 0.3,
                        f"{bps / 1000:.1f}KB/s, {pps:.0f} packets/s",
                        value=round(bps / 1000, 1), unit="KB/s"))
    if total < 50_000:
        opp.append(_sig("small_transfer", 0.3, f"{total / 1000:.0f}KB total",
                        value=round(total / 1000, 1), unit="KB"))
    return sup, opp


def _rule_endpoint(rec: dict, f: dict[str, float], ctx: dict) -> tuple[list, list]:
    """Unusual endpoint behaviour: a known endpoint acting out of character."""
    sup: list[dict] = []
    opp: list[dict] = []
    total = _rfloat(rec, "bytes") or _f(f, "bytes_total")
    baseline = _mean(ctx["dst_bytes"])
    prior = len(ctx["dst_bytes"])
    if prior >= 3 and baseline > 0 and (total >= 5 * baseline
                                        or total <= 0.2 * baseline):
        sup.append(_sig("behavior_change", 0.5,
                        f"{total / 1000:.0f}KB vs {baseline / 1000:.0f}KB "
                        f"typical for this endpoint",
                        value=round(total / baseline, 3), unit="ratio"))
    if (prior >= 3 and ctx["dst_port"]
            and ctx["dst_port"] not in ctx["dst_ports_seen"]):
        sup.append(_sig("unexpected_service_port", 0.4,
                        f"port {ctx['dst_port']} never used on this host in "
                        f"{prior} prior flows",
                        value=ctx["dst_port"]))
    if ctx["pair_count"] == 0 and ctx["window_len"] >= 20:
        sup.append(_sig("rare_endpoint", 0.3,
                        f"no prior traffic to this host in the last "
                        f"{ctx['window_len']} flows",
                        value=ctx["pair_count"], unit="count"))
    if _rfloat(rec, "score") >= 95:
        sup.append(_sig("extreme_score", 0.3,
                        f"detector score {_rfloat(rec, 'score'):.0f} "
                        f"(top of range)",
                        value=_rfloat(rec, "score")))
    if (ctx["pair_count"] >= 5 and baseline > 0
            and 0.5 * baseline <= total <= 2 * baseline):
        opp.append(_sig("known_endpoint", 0.3,
                        f"ordinary size for a host seen {ctx['pair_count']}x",
                        value=ctx["pair_count"], unit="count"))
    if ctx["endpoint_count"] >= 3:
        opp.append(_sig("expected_port", 0.3,
                        f"this host:port used {ctx['endpoint_count']}x before",
                        value=ctx["endpoint_count"], unit="count"))
    return sup, opp


#: ``(category, rule)`` in ``THREAT_TYPES`` order — the tie-break order.
_RULES: tuple[tuple[str, Callable[[dict, dict, dict], tuple[list, list]]], ...] = (
    ("C2_BEACONING", _rule_c2),
    ("RECONNAISSANCE", _rule_recon),
    ("DATA_EXFILTRATION_SUSPECTED", _rule_exfil),
    ("TLS_ANOMALY", _rule_tls),
    ("QUIC_ANOMALY", _rule_quic),
    ("VOLUMETRIC_ANOMALY", _rule_volumetric),
    ("UNUSUAL_ENDPOINT_BEHAVIOR", _rule_endpoint),
)

#: Minimum weighted support per category (plus >= 2 signals) to classify.
_MINIMUMS: dict[str, float] = {
    "C2_BEACONING": 0.9,
    "RECONNAISSANCE": 0.8,
    "DATA_EXFILTRATION_SUSPECTED": 0.8,
    "TLS_ANOMALY": 0.65,
    "QUIC_ANOMALY": 0.65,
    "VOLUMETRIC_ANOMALY": 0.75,
    "UNUSUAL_ENDPOINT_BEHAVIOR": 0.6,
}


def unknown_threat() -> dict:
    """Fallback verdict: an anomaly we cannot explain specifically."""
    return {
        "threat_type": UNKNOWN,
        "confidence": 0.0,
        "supporting": [],
        "contradicting": [],
        "insufficient_evidence": True,
    }


def classify_threat(record: dict, feats: Any,
                    window: list[dict] | None = None) -> dict:
    """Classify one *flagged* flow into an explainable threat category.

    Parameters
    ----------
    record:
        The flow record (``Flow.record()`` plus detector enrichment).
    feats:
        The flow's feature vector (``extract_features`` output), or ``None``.
    window:
        The most recent **prior** flow records (context); the current flow
        must never be included.  Bounded to ``THREAT_WINDOW`` entries.

    Returns
    -------
    dict with ``threat_type``, ``confidence`` (0-1), ``supporting`` and
    ``contradicting`` signal lists; unknown verdicts additionally carry the
    sub-threshold ``candidate`` and ``insufficient_evidence: True``.
    """
    rec = record if isinstance(record, dict) else {}
    f = _features(feats)
    ctx = _build_context(rec, list(window or [])[-THREAT_WINDOW:])

    qualified: tuple[str, list, list, float, float] | None = None
    candidate: tuple[str, list, list, float, float] | None = None

    for name, rule in _RULES:
        sup, opp = rule(rec, f, ctx)
        support = sum(s["weight"] for s in sup)
        oppose = sum(s["weight"] for s in opp)
        if (len(sup) >= _MIN_SIGNALS
                and support >= _MINIMUMS[name] + 1e-9
                and (qualified is None or support > qualified[3])):
            # strictly-greater keeps the earlier THREAT_TYPES entry on ties
            qualified = (name, sup, opp, support, oppose)
        if candidate is None or support > candidate[3]:
            candidate = (name, sup, opp, support, oppose)

    if qualified is not None:
        name, sup, opp, support, oppose = qualified
        confidence = support / (support + oppose) if (support + oppose) else 0.5
        confidence = round(min(_CONF_CAP, max(_CONF_FLOOR, confidence)), 3)
        return {"threat_type": name, "confidence": confidence,
                "supporting": sup, "contradicting": opp}

    # No category met its threshold: stay unknown and say so explicitly.
    name, sup, opp, support, oppose = candidate or (UNKNOWN, [], [], 0.0, 0.0)
    if support <= 0:
        return unknown_threat()
    confidence = round(min(_UNKNOWN_CAP,
                           support / (support + oppose + _MINIMUMS[name])), 3)
    return {"threat_type": UNKNOWN, "confidence": confidence,
            "supporting": sup, "contradicting": opp,
            "candidate": name, "insufficient_evidence": True}


__all__ = [
    "THREAT_TYPES",
    "THREAT_WINDOW",
    "UNKNOWN",
    "classify_threat",
    "unknown_threat",
]
