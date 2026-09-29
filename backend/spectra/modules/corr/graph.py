"""Module 7: Cross-Domain Correlation - traffic graph and blast-radius queries.

Graph model (all edges derived from observed flows only):

    host ──talks_to──> ip ◀──served_by── domain ──in_sector──> sector

  * host    : internal source IP (or external peer when capture is mirrored)
  * ip      : destination IP
  * domain  : TLS SNI / hostname
  * sector  : fintech | healthcare | smart_city | general (from sectors.py)

Shared infrastructure shows up as IP nodes with several `served_by` edges;
the cascade engine uses that to score how far a compromise could spread
(the product doc's "kill-chain propagation across sectors").
"""

from __future__ import annotations

from collections import defaultdict, deque

from ...sectors import SectorClassifier, get_classifier

NODE_HOST = "host"
NODE_IP = "ip"
NODE_DOMAIN = "domain"
NODE_SECTOR = "sector"

EDGE_TALKS_TO = "talks_to"
EDGE_SERVED_BY = "served_by"
EDGE_IN_SECTOR = "in_sector"


def _strip_port(addr: str | None) -> str:
    if not addr:
        return ""
    return addr.rsplit(":", 1)[0] if ":" in addr else addr


class CorrelationGraph:
    def __init__(self, classifier: SectorClassifier | None = None):
        self.classifier = classifier or get_classifier()
        self.nodes: dict[str, dict] = {}
        # adjacency: src_id -> {dst_id -> {edge_type -> weight}}
        self.edges: dict[str, dict[str, dict[str, float]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(float))
        )

    # -- construction --------------------------------------------------------

    def _node(self, nid: str, ntype: str, label: str | None = None,
              sector: str | None = None) -> dict:
        node = self.nodes.get(nid)
        if node is None:
            node = {
                "id": nid,
                "type": ntype,
                "label": label or nid,
                "sector": sector,
                "flows": 0,
                "bytes": 0,
                "detections": 0,
                "domains": set(),
                "first_ts": None,
                "last_ts": None,
            }
            self.nodes[nid] = node
        if sector and not node.get("sector"):
            node["sector"] = sector
        return node

    def _edge(self, src: str, dst: str, etype: str, weight: float = 1.0) -> None:
        self.edges[src][dst][etype] += weight

    def observe(self, record: dict) -> None:
        """Add one completed flow to the graph."""
        host = _strip_port(record.get("src"))
        ip = _strip_port(record.get("dst"))
        sni = record.get("sni")
        ts = record.get("last_ts")
        size = int(record.get("bytes") or 0)
        anomaly = bool(record.get("anomaly"))

        if not host or not ip:
            return
        sector = self.classifier.classify(sni or ip)

        h = self._node(f"host:{host}", NODE_HOST, host,
                       self.classifier.classify(host) if not sni else None)
        d = self._node(f"ip:{ip}", NODE_IP, ip, sector if sni else None)

        for n in (h, d):
            n["flows"] += 1
            n["bytes"] += size
            if anomaly:
                n["detections"] += 1
            if ts:
                n["first_ts"] = ts if n["first_ts"] is None else min(n["first_ts"], ts)
                n["last_ts"] = ts if n["last_ts"] is None else max(n["last_ts"], ts)

        self._edge(h["id"], d["id"], EDGE_TALKS_TO, weight=size or 1)

        if sni:
            dom_id = f"domain:{sni}"
            dom = self._node(dom_id, NODE_DOMAIN, sni, sector)
            dom["flows"] += 1
            dom["bytes"] += size
            if anomaly:
                dom["detections"] += 1
            if ts:
                dom["first_ts"] = ts if dom["first_ts"] is None else min(dom["first_ts"], ts)
                dom["last_ts"] = ts if dom["last_ts"] is None else max(dom["last_ts"], ts)
            h["domains"].add(dom_id)
            d["domains"].add(dom_id)
            self._edge(dom_id, d["id"], EDGE_SERVED_BY, weight=1)
            sec_id = f"sector:{sector}"
            sec = self._node(sec_id, NODE_SECTOR, sector, sector)
            sec["flows"] += 1
            sec["bytes"] += size
            if anomaly:
                sec["detections"] += 1
            if ts:
                sec["first_ts"] = ts if sec["first_ts"] is None else min(sec["first_ts"], ts)
                sec["last_ts"] = ts if sec["last_ts"] is None else max(sec["last_ts"], ts)
            self._edge(dom_id, sec_id, EDGE_IN_SECTOR, weight=1)

    def observe_many(self, records) -> None:
        for rec in records:
            self.observe(rec)

    def hydrate(self, store, limit: int = 50_000) -> int:
        """Rebuild the graph from persisted history (API restarts)."""
        page = store.query_flows(limit=min(limit, 1000), offset=0)
        items = list(page["items"])
        total = page["count"]
        offset = len(items)
        while len(items) < min(total, limit):
            page = store.query_flows(limit=1000, offset=offset)
            if not page["items"]:
                break
            items.extend(page["items"])
            offset += len(page["items"])
        for rec in items:
            self.observe(rec)
        return len(items)

    # -- queries -------------------------------------------------------------

    def summary(self) -> dict:
        by_type: dict[str, int] = defaultdict(int)
        by_sector: dict[str, int] = defaultdict(int)
        detections = 0
        for node in self.nodes.values():
            by_type[node["type"]] += 1
            if node["type"] == NODE_SECTOR:
                by_sector[node["label"]] = node["flows"]
            detections += node["detections"] if node["type"] == NODE_HOST else 0
        # shared infrastructure: IP nodes served by >= 2 distinct domains
        served_by_count: dict[str, int] = defaultdict(int)
        for src, nbrs in self.edges.items():
            if self.nodes.get(src, {}).get("type") != NODE_DOMAIN:
                continue
            for dst, weights in nbrs.items():
                if EDGE_SERVED_BY in weights:
                    served_by_count[dst] += 1
        shared_ips = [nid for nid, n in served_by_count.items() if n >= 2]
        return {
            "nodes": len(self.nodes),
            "edges": sum(len(n) for n in self.edges.values()),
            "by_type": dict(by_type),
            "by_sector": dict(by_sector),
            "shared_infrastructure": len(shared_ips),
            "shared_ip_nodes": sorted(shared_ips)[:50],
        }

    def node(self, nid: str) -> dict | None:
        node = self.nodes.get(nid)
        if node is None:
            return None
        return self._public(node)

    def _public(self, node: dict) -> dict:
        return {
            **{k: v for k, v in node.items() if k != "domains"},
            "domains": sorted(node["domains"]),
        }

    def nodes_list(self, ntype: str | None = None, sector: str | None = None,
                   limit: int = 500, sort: str = "detections") -> list[dict]:
        rows = [self._public(n) for n in self.nodes.values()
                if (ntype is None or n["type"] == ntype)
                and (sector is None or n.get("sector") == sector)]
        key = {"detections": lambda r: (-r["detections"], -r["flows"]),
               "flows": lambda r: (-r["flows"],),
               "bytes": lambda r: (-r["bytes"],)}.get(sort, None)
        if key:
            rows.sort(key=key)
        return rows[:limit]

    def edges_list(self, limit: int = 2000) -> list[dict]:
        out = []
        for src, nbrs in self.edges.items():
            for dst, weights in nbrs.items():
                for etype, weight in weights.items():
                    out.append({"source": src, "target": dst,
                                "type": etype, "weight": round(weight, 2)})
                    if len(out) >= limit:
                        return out
        return out

    def neighbors(self, nid: str) -> dict:
        node = self.nodes.get(nid)
        if node is None:
            return {"node": None, "in": [], "out": []}
        out = [
            {"target": dst, "type": etype, "weight": round(w, 2)}
            for dst, weights in self.edges.get(nid, {}).items()
            for etype, w in weights.items()
        ]
        incoming = []
        for src, nbrs in self.edges.items():
            if nid in nbrs:
                for etype, w in nbrs[nid].items():
                    incoming.append({"source": src, "type": etype,
                                     "weight": round(w, 2)})
        return {"node": self._public(node), "in": incoming, "out": out}

    def shortest_path(self, src: str, dst: str, max_depth: int = 6) -> list[str] | None:
        """Undirected shortest path (kill-chain hops may traverse edges either way)."""
        if src not in self.nodes or dst not in self.nodes:
            return None
        if src == dst:
            return [src]
        seen = {src}
        queue: deque[tuple[str, list[str]]] = deque([(src, [src])])
        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue
            nxts = set(self.edges.get(current, {}))
            for pred, nbrs in self.edges.items():
                if current in nbrs:
                    nxts.add(pred)
            for nxt in nxts:
                if nxt in seen:
                    continue
                if nxt == dst:
                    return path + [nxt]
                seen.add(nxt)
                queue.append((nxt, path + [nxt]))
        return None

    def reachable(self, nid: str, max_depth: int = 4) -> dict[str, int]:
        """BFS distances from nid (undirected for blast-radius purposes)."""
        if nid not in self.nodes:
            return {}
        seen = {nid: 0}
        queue: deque[str] = deque([nid])
        while queue:
            current = queue.popleft()
            if seen[current] >= max_depth:
                continue
            nxts = set(self.edges.get(current, {}))
            for src, nbrs in self.edges.items():  # reverse direction
                if current in nbrs:
                    nxts.add(src)
            for nxt in nxts:
                if nxt not in seen:
                    seen[nxt] = seen[current] + 1
                    queue.append(nxt)
        return seen

    def reset(self) -> None:
        self.nodes.clear()
        self.edges.clear()
