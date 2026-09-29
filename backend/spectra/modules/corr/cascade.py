"""Kill-chain / cascade scoring for the correlation graph (Module 7).

Given a starting node (compromised host, C2 domain, ...), measure how far the
blast radius could reach: affected sectors, internal hosts and observed
detections along the path, then score 0-100 with sector-sensitivity weighting
and path-length decay.
"""

from __future__ import annotations

from ...sectors import SENSITIVITY
from .graph import NODE_DOMAIN, NODE_HOST, NODE_IP, NODE_SECTOR, CorrelationGraph

MAX_DEPTH = 4


def cascade(graph: CorrelationGraph, start: str, max_depth: int = MAX_DEPTH) -> dict:
    if start not in graph.nodes:
        return {"start": start, "found": False, "score": 0,
                "affected": {}, "kill_chain": [], "reasons": []}

    hops = graph.reachable(start, max_depth=max_depth)
    affected = {NODE_HOST: [], NODE_IP: [], NODE_DOMAIN: [], NODE_SECTOR: []}
    detections = 0
    total_bytes = 0
    sectors: set[str] = set()

    for nid, depth in sorted(hops.items(), key=lambda kv: kv[1]):
        node = graph.nodes.get(nid)
        if node is None:
            continue
        affected[node["type"]].append({
            "id": nid, "label": node["label"], "depth": depth,
            "detections": node["detections"], "flows": node["flows"],
        })
        if node["type"] in (NODE_HOST, NODE_DOMAIN, NODE_IP):
            detections += node["detections"]
            total_bytes += node["bytes"]
        if node["type"] == NODE_SECTOR and node["label"]:
            sectors.add(node["label"])
        elif node.get("sector"):
            sectors.add(node["sector"])

    # scoring: reach x detections x sector sensitivity, decayed by depth
    max_depth_used = max(hops.values()) if hops else 0
    reach = min(1.0, len(hops) / 12.0)
    det = min(1.0, detections / 5.0)
    sens = max((SENSITIVITY.get(s, 0.4) for s in sectors), default=0.4)
    spread = min(1.0, max_depth_used / max_depth)
    score = round(100 * (0.30 * reach + 0.35 * det + 0.25 * sens + 0.10 * spread))

    level = "high" if score >= 70 else "medium" if score >= 40 else "low"
    reasons = [
        f"{len(hops)} nodes reachable within {max_depth} hops",
        f"{detections} anomalous flow(s) in the neighbourhood",
        "sectors touched: " + (", ".join(sorted(sectors)) or "none"),
    ]
    if detections:
        reasons.append("anomalous endpoints sit on shared infrastructure "
                       "(potential pivot points)")
    if len(sectors) >= 2:
        reasons.append("cross-sector propagation path observed - cascade risk")

    return {
        "start": start,
        "found": True,
        "score": score,
        "level": level,
        "max_depth_used": max_depth_used,
        "affected": {k: v for k, v in affected.items()},
        "affected_counts": {k: len(v) for k, v in affected.items()},
        "sectors": sorted(sectors),
        "detections": detections,
        "bytes_involved": total_bytes,
        "kill_chain": _kill_chain(graph, start, hops),
        "reasons": reasons,
    }


def _kill_chain(graph: CorrelationGraph, start: str,
                hops: dict[str, int]) -> list[dict]:
    """Reconstruct a representative host -> ip -> domain -> sector path."""
    node = graph.nodes[start]
    chain = [{"step": 1, "node": start, "type": node["type"],
              "label": node["label"]}]
    current, step = start, 2
    visited = {start}
    while step <= MAX_DEPTH:
        # prefer domain and sector hops outward
        candidates = [
            (depth, nxt) for nxt, depth in hops.items()
            if nxt not in visited and nxt in graph.edges.get(current, {})
        ]
        if not candidates:
            # try one hop outward anywhere (graph direction may be reversed)
            candidates = [
                (depth, nxt) for nxt, depth in hops.items()
                if nxt not in visited and current in graph.edges.get(nxt, {})
            ]
            if not candidates:
                break
            _, nxt = min(candidates)
            edge = next(
                etype for etype in graph.edges[nxt][current]
            )
        else:
            _, nxt = min(candidates)
            edge = next(
                etype for etype in graph.edges[current][nxt]
            )
        n = graph.nodes[nxt]
        chain.append({"step": step, "node": nxt, "type": n["type"],
                      "label": n["label"], "via": edge})
        visited.add(nxt)
        current = nxt
        step += 1
    return chain
