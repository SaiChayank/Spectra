"""Module 4: Digital Twin topology - an isolated replica built from evidence.

The twin is derived from the Module 7 correlation graph, so it always mirrors
what Spectra actually observed (no invented infrastructure):

    * assets      - hosts + servers that can be compromised (simulation nodes)
    * zones       - sector segments the replica is partitioned into
    * asset_edges - who talks to whom, normalised to [0, 1] (propagation odds)
    * by_domain   - domain -> served IPs (for "block this domain" playbooks)
    * criticality - regulatory sensitivity x detection pressure (0..1)

Deterministic: the same graph always yields byte-identical topology, which is
what makes simulation runs reproducible.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from ...sectors import SENSITIVITY, get_classifier
from ..corr.graph import EDGE_SERVED_BY, EDGE_TALKS_TO, NODE_DOMAIN, NODE_HOST, NODE_IP, NODE_SECTOR

ASSET_TYPES = (NODE_HOST, NODE_IP)

ROLE = {
    NODE_HOST: "endpoint",
    NODE_IP: "server",
    NODE_DOMAIN: "service",
    NODE_SECTOR: "zone",
}


def build_topology(graph, min_flows: int = 1) -> dict:
    """Build the twin replica from a :class:`CorrelationGraph`."""
    classifier = graph.classifier if hasattr(graph, "classifier") else get_classifier()
    raw = graph.nodes_list(limit=100_000, sort="flows")

    # 1. host zone = dominant sector of the domains it talks to
    host_domains: dict[str, set] = defaultdict(set)
    for nid, node in graph.nodes.items():
        if node["type"] == NODE_HOST:
            host_domains[nid] = set(node.get("domains") or ())
    domain_sector = {
        nid: (node.get("sector") or classifier.classify(node.get("label")))
        for nid, node in graph.nodes.items() if node["type"] == NODE_DOMAIN
    }

    def zone_of(node: dict) -> str:
        nid, ntype = node["id"], node["type"]
        if ntype == NODE_SECTOR:
            return node.get("label") or node.get("sector") or "general"
        if ntype == NODE_HOST:
            votes = Counter(domain_sector[d] for d in host_domains.get(nid, ())
                            if d in domain_sector)
            if votes:
                # deterministic tie-break: highest vote count, then name
                top = max(votes.values())
                return sorted(s for s, c in votes.items() if c == top)[0]
            return node.get("sector") or "general"
        if ntype == NODE_DOMAIN:
            return node.get("sector") or classifier.classify(node.get("label"))
        # ip: external service or internal
        sector = node.get("sector")
        return sector or ("external" if node["type"] == NODE_IP else "general")

    def criticality(node: dict, zone: str) -> float:
        base = SENSITIVITY.get(zone, SENSITIVITY["general"])
        flows = int(node.get("flows") or 0)
        det_ratio = (int(node.get("detections") or 0) / flows) if flows else 0.0
        return round(min(1.0, base + 0.3 * base * det_ratio), 3)

    nodes: list[dict] = []
    for node in raw:
        if int(node.get("flows") or 0) < min_flows:
            continue
        zone = zone_of(node)
        nodes.append({
            "id": node["id"],
            "type": node["type"],
            "role": ROLE.get(node["type"], node["type"]),
            "label": node.get("label") or node["id"],
            "zone": zone,
            "sector": node.get("sector"),
            "asset": node["type"] in ASSET_TYPES,
            "criticality": criticality(node, zone),
            "flows": int(node.get("flows") or 0),
            "bytes": int(node.get("bytes") or 0),
            "detections": int(node.get("detections") or 0),
            "first_ts": node.get("first_ts"),
            "last_ts": node.get("last_ts"),
        })
    nodes.sort(key=lambda n: n["id"])
    by_id = {n["id"]: n for n in nodes}

    # 2. asset edges (talks_to only - these are the propagation channels)
    asset_edges: list[dict] = []
    for row in graph.edges_list(limit=100_000):
        if row["type"] != EDGE_TALKS_TO:
            continue
        src, dst = by_id.get(row["source"]), by_id.get(row["target"])
        if src is None or dst is None or not (src["asset"] and dst["asset"]):
            continue
        weight = float(row["weight"]) or 1.0
        asset_edges.append({
            "source": src["id"],
            "target": dst["id"],
            "weight": weight,
            "cross_zone": src["zone"] != dst["zone"],
            "to_external": dst["zone"] == "external" or src["zone"] == "external",
        })
    asset_edges.sort(key=lambda e: (e["source"], e["target"]))
    max_w = max((e["weight"] for e in asset_edges), default=1.0) or 1.0
    for e in asset_edges:
        e["normalized"] = round(min(1.0, e["weight"] / max_w), 4)

    # 3. domain -> served IPs (containment hook for "block domain" actions)
    by_domain: dict[str, list[str]] = defaultdict(list)
    for row in graph.edges_list(limit=100_000):
        if row["type"] == EDGE_SERVED_BY:
            by_domain[row["source"]].append(row["target"])
    for dom in by_domain:
        by_domain[dom] = sorted(set(by_domain[dom]))

    # 4. zone membership (assets only) + summary
    zone_members: dict[str, list[str]] = defaultdict(list)
    for n in nodes:
        if n["asset"]:
            zone_members[n["zone"]].append(n["id"])
    zones = [
        {
            "id": z,
            "assets": sorted(members),
            "size": len(members),
            "criticality": SENSITIVITY.get(z, SENSITIVITY["general"]),
        }
        for z, members in sorted(zone_members.items())
    ]

    assets = sorted(n["id"] for n in nodes if n["asset"])
    det_total = sum(n["detections"] for n in nodes if n["asset"])
    return {
        "nodes": nodes,
        "assets": assets,
        "asset_edges": asset_edges,
        "zones": zones,
        "by_domain": dict(sorted(by_domain.items())),
        "summary": {
            "nodes": len(nodes),
            "assets": len(assets),
            "edges": len(asset_edges),
            "zones": len(zones),
            "by_type": dict(Counter(n["type"] for n in nodes)),
            "detections": det_total,
            "mean_criticality": round(
                sum(n["criticality"] for n in nodes if n["asset"]) / len(assets), 3
            ) if assets else 0.0,
        },
    }


__all__ = ["build_topology", "ASSET_TYPES"]
