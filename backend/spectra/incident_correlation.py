"""Conservative alert-to-incident correlation: pure logic, no I/O.

An incident groups *related security activity* - alerts that share anchors -
and must never blindly merge unrelated anomalies.  The rules are deliberate
and documented:

Gates (all must hold for two alerts to be related)
    1. **Temporal proximity** - the gap between the two sightings'
       ``[first_seen, last_seen]`` intervals is at most ``window`` seconds.
    2. **At least one anchor** - same source host, same destination host,
       same SNI/domain, or a direct edge between their endpoint nodes in the
       correlation graph.  Shared subnets alone are too coarse to identify
       "the same activity" and never anchor on their own.
    3. **Score >= ``MIN_SCORE``** - the anchors and signals below must add up.

Signals (weights, all listed in the returned signal list)
    ==============================  =====  =====
    signal                          score  anchor
    ==============================  =====  =====
    same source host                   3    yes
    same destination host              3    yes
    same SNI / domain                  3    yes
    graph-linked (direct edge)         3    yes
    same threat type                   2    no
    temporally proximate (<= w/2)      1    no
    shared source subnet (/24)         1    no
    shared destination subnet (/24)    1    no
    repeated beaconing (same dst)      1    no
    ==============================  =====  =====

Consequences (the over-grouping tests rely on these): two alerts that share
only a threat type score at most 3 and never merge; alerts that share only a
/24 subnet never anchor; an anchor without threat/time support still needs
one more point (proximity or a weak signal) to reach the threshold.

The same signals become the human-readable ``reason`` stored on an
incident-alert link, and :func:`rollup` derives the incident-level fields
(severity, primary threat, affected entities, evidence summary, ...) from
its member alerts deterministically.
"""

from __future__ import annotations

import ipaddress

from .severity import SEVERITIES

#: Anchor weight: an endpoint identity that ties two alerts together.
ANCHOR_SCORE = 3.0
#: Same threat class (unknown labels carry no signal).
THREAT_SCORE = 2.0
#: Interval gap within half the window - active at overlapping times.
PROXIMITY_SCORE = 1.0
#: Shared /24 (IPv4) on one side - shared infrastructure, not an anchor.
SUBNET_SCORE = 1.0
#: Beaconing repeatedly to the same destination.
BEACON_SCORE = 1.0
#: Minimum total score for a pair to be considered the same incident.
MIN_SCORE = 4.0

C2 = "C2_BEACONING"
UNKNOWN = "UNKNOWN_ANOMALY"

#: Bound on rolled-up lists so one hot incident cannot bloat its row.
MAX_ENTITIES = 50
MAX_GRAPH_NODES = 50


def _host(addr: object) -> str:
    """``"10.0.0.1:443"`` -> ``"10.0.0.1"`` (IPv6-safe rpartition)."""
    if not isinstance(addr, str) or not addr:
        return ""
    host, sep, _port = addr.rpartition(":")
    return host if sep else addr


def _norm_domain(sni: object) -> str:
    """Lowercase, dot-trailing-normalized domain (``None`` -> ``""``)."""
    if not isinstance(sni, str) or not sni:
        return ""
    return sni.strip().rstrip(".").lower()


def _subnet(host: str) -> str | None:
    """IPv4 /24 network of ``host`` (non-IPv4 hosts share no subnet signal)."""
    if not host:
        return None
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return None
    if addr.version != 4:
        return None
    return str(ipaddress.ip_network(f"{host}/24", strict=False))


def endpoint_nodes(alert: dict) -> list[str]:
    """Candidate correlation-graph node ids of one alert's endpoints.

    Mirrors how ``spectra.modules.corr.graph`` names nodes: ``host:<src>``,
    ``ip:<dst>`` and ``domain:<sni>`` (when the flow carried SNI).
    """
    nodes: list[str] = []
    src, dst = _host(alert.get("source")), _host(alert.get("destination"))
    if src:
        nodes.append(f"host:{src}")
    if dst:
        nodes.append(f"ip:{dst}")
    sni = (alert.get("metadata") or {}).get("sni")
    if sni:
        nodes.append(f"domain:{sni}")
    return nodes


def _adjacent(edges, x: str, y: str) -> bool:
    """Direct edge between ``x`` and ``y`` (either direction, no iteration).

    ``edges`` is a defaultdict-of-defaultdicts; only ``.get`` is used so the
    check never mutates the live graph or races a concurrent writer.
    """
    left = edges.get(x)
    if left is not None and y in left:
        return True
    right = edges.get(y)
    if right is not None and x in right:
        return True
    return False


def _derive(alert: dict) -> dict:
    """Pre-split one alert once so a cluster pass never re-parses it."""
    metadata = alert.get("metadata") or {}
    src, dst = _host(alert.get("source")), _host(alert.get("destination"))
    try:
        first = float(alert.get("first_seen") or 0.0)
        last = float(alert.get("last_seen") or first)
    except (TypeError, ValueError):
        first = last = 0.0
    try:
        occurrences = int(alert.get("occurrences") or 1)
    except (TypeError, ValueError):
        occurrences = 1
    return {
        "alert": alert,
        "src": src,
        "dst": dst,
        "sni": _norm_domain(metadata.get("sni")),
        "src_net": _subnet(src),
        "dst_net": _subnet(dst),
        "threat": str(alert.get("threat_type") or ""),
        "first": first,
        "last": max(last, first),
        "occurrences": occurrences,
        "nodes": endpoint_nodes(alert),
    }


def _pair(da: dict, db: dict, window: float,
          graph) -> tuple[bool, float, list[str]]:
    """Gates + weights of one alert pair (see the module docstring)."""
    # Gate 1: temporal proximity between the two sighting intervals.
    gap = max(da["first"], db["first"]) - min(da["last"], db["last"])
    if gap < 0.0:
        gap = 0.0
    if gap > window:
        return False, 0.0, []

    score = 0.0
    anchors = 0
    signals: list[str] = []

    def _add(weight: float, signal: str, anchor: bool = False) -> None:
        nonlocal score, anchors
        score += weight
        signals.append(signal)
        if anchor:
            anchors += 1

    # Anchors: endpoint identity of the pair (gate 2 needs at least one).
    if da["src"] and da["src"] == db["src"]:
        _add(ANCHOR_SCORE, f"same source host {da['src']}", anchor=True)
    if da["dst"] and da["dst"] == db["dst"]:
        _add(ANCHOR_SCORE, f"same destination host {da['dst']}", anchor=True)
    if da["sni"] and da["sni"] == db["sni"]:
        _add(ANCHOR_SCORE, f"same SNI {da['sni']}", anchor=True)
    if graph is not None:
        edges = getattr(graph, "edges", None)
        if edges:
            for x in da["nodes"]:
                for y in db["nodes"]:
                    if x != y and _adjacent(edges, x, y):
                        _add(ANCHOR_SCORE, f"graph-linked {x} <-> {y}",
                             anchor=True)
                        break
                else:
                    continue
                break

    # Signals: evidence that strengthens an anchored pair.
    if da["threat"] and da["threat"] == db["threat"] and da["threat"] != UNKNOWN:
        _add(THREAT_SCORE, f"same threat type {da['threat']}")
    if gap <= window / 2.0:
        _add(PROXIMITY_SCORE, f"temporally proximate ({gap:.0f}s apart)")
    if (da["src_net"] and da["src_net"] == db["src_net"]
            and da["src"] != db["src"]):
        _add(SUBNET_SCORE, f"shared source subnet {da['src_net']}")
    if (da["dst_net"] and da["dst_net"] == db["dst_net"]
            and da["dst"] != db["dst"]):
        _add(SUBNET_SCORE, f"shared destination subnet {da['dst_net']}")
    if (da["dst"] and da["dst"] == db["dst"]
            and ((da["threat"] == C2 and da["occurrences"] >= 2)
                 or (db["threat"] == C2 and db["occurrences"] >= 2))):
        _add(BEACON_SCORE, f"repeated beaconing to {da['dst']}")

    related = anchors >= 1 and score >= MIN_SCORE
    return related, score, signals


def related(a: dict, b: dict, *, window: float,
            graph=None) -> tuple[bool, float, list[str]]:
    """``(is_related, score, signals)`` of two alerts (order-insensitive).

    ``signals`` lists every matched signal (for audit/attach reasons), even
    when the pair is not related; callers only record it on a merge.
    """
    if window <= 0:
        return False, 0.0, []
    return _pair(_derive(a), _derive(b), float(window), graph)


def cluster(alerts: list[dict], *, window: float,
            graph=None) -> list[list[dict]]:
    """Group alerts into incident candidates (single-linkage union-find).

    Two alerts join the same cluster when :func:`related` holds for them,
    transitively.  Clusters come back ordered by each member's ``first_seen``
    and hold every alert exactly once; singleton clusters are the caller's
    signal that nothing justified an incident (conservative by default).
    """
    if window <= 0 or len(alerts) < 2:
        return [[a] for a in alerts]
    items = sorted(
        ((a, _derive(a)) for a in alerts),
        key=lambda pair: (pair[1]["first"], str(pair[0].get("alert_id") or "")),
    )
    parent = list(range(len(items)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    n = len(items)
    for i in range(n):
        _ai, di = items[i]
        for j in range(i + 1, n):
            _aj, dj = items[j]
            # Sorted by first_seen: once j's window opens too late for i,
            # every later j does too - skip the rest (hard temporal gate).
            if dj["first"] - di["last"] > window:
                break
            if find(i) == find(j):
                continue
            if _pair(di, dj, window, graph)[0]:
                parent[find(j)] = find(i)

    groups: dict[int, list[dict]] = {}
    for index, (alert, _derived) in enumerate(items):
        groups.setdefault(find(index), []).append(alert)
    return list(groups.values())


def _severity_rank(alert: dict) -> int:
    severity = alert.get("severity")
    return SEVERITIES.index(severity) if severity in SEVERITIES else 0


def _primary(alerts: list[dict]) -> dict:
    """Most severe member, ties broken by confidence, then occurrences."""
    return min(
        alerts,
        key=lambda a: (
            -_severity_rank(a),
            -float(a.get("confidence") or 0.0),
            -int(a.get("occurrences") or 1),
        ),
    )


def rollup(alerts: list[dict], *, graph=None) -> dict:
    """Derive incident-level fields from its member alerts (deterministic).

    Severity is the ordinal **max** of member severities (an incident is as
    serious as its worst alert); confidence and the primary threat class
    belong to the primary alert - the most severe member, ties by confidence
    then occurrences - so "confidence" never averages unrelated verdicts.
    Model versions and graph nodes are deduplicated unions; the evidence
    summary prefixes the member count to the primary alert's own summary.
    """
    if not alerts:
        return {
            "alert_count": 0,
            "first_seen": None,
            "last_seen": None,
            "affected_entities": [],
            "primary_threat_class": None,
            "severity": None,
            "confidence": None,
            "model_versions": [],
            "related_graph_nodes": [],
            "evidence_summary": None,
        }
    primary = _primary(alerts)
    entities: set[str] = set()
    nodes: set[str] = set()
    versions: set[str] = set()
    for alert in alerts:
        metadata = alert.get("metadata") or {}
        for addr in (alert.get("source"), alert.get("destination")):
            host = _host(addr)
            if host:
                entities.add(host)
        if metadata.get("sni"):
            entities.add(str(metadata["sni"]))
        if graph is not None:
            for nid in endpoint_nodes(alert):
                try:
                    if graph.node(nid) is not None:
                        nodes.add(nid)
                except Exception:  # noqa: BLE001 - rollups never fail on the graph
                    pass
        versions.add(
            f"{alert.get('model_id') or 'unknown'}"
            f"@{alert.get('model_version') or 'unknown'}")

    count = len(alerts)
    primary_threat = str(primary.get("threat_type") or UNKNOWN)
    evidence = primary.get("evidence") or {}
    summary = str(evidence.get("summary") or "").strip()
    label = f"{count} linked alert(s); {primary_threat}"
    if summary:
        label = f"{label}: {summary}"
    return {
        "alert_count": count,
        "first_seen": min(float(a.get("first_seen") or 0.0) for a in alerts),
        "last_seen": max(float(a.get("last_seen") or 0.0) for a in alerts),
        "affected_entities": sorted(entities)[:MAX_ENTITIES],
        "primary_threat_class": primary_threat,
        "severity": primary.get("severity"),
        "confidence": float(primary.get("confidence") or 0.0),
        "model_versions": sorted(versions),
        "related_graph_nodes": sorted(nodes)[:MAX_GRAPH_NODES],
        "evidence_summary": label,
    }


def auto_title(alerts: list[dict]) -> str:
    """Deterministic incident title for correlation-created incidents."""
    if not alerts:
        return "Incident"
    primary = _primary(alerts)
    threat = str(primary.get("threat_type") or UNKNOWN)
    entity = _norm_domain((primary.get("metadata") or {}).get("sni")) \
        or _host(primary.get("destination")) \
        or _host(primary.get("source"))
    if entity:
        return f"{threat} activity affecting {entity}"
    return f"{threat} activity ({len(alerts)} alerts)"


__all__ = [
    "ANCHOR_SCORE",
    "BEACON_SCORE",
    "MIN_SCORE",
    "PROXIMITY_SCORE",
    "SUBNET_SCORE",
    "THREAT_SCORE",
    "auto_title",
    "cluster",
    "endpoint_nodes",
    "related",
    "rollup",
]
