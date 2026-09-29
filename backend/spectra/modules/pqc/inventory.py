"""Crypto-agility inventory: quantum posture per endpoint (Module 1)."""

from __future__ import annotations

from collections import Counter

from ...sectors import SectorClassifier, get_classifier


class PQCInventory:
    """Aggregates per-flow assessments into endpoint-level posture."""

    def __init__(self, classifier: SectorClassifier | None = None):
        self.classifier = classifier or get_classifier()
        self._endpoints: dict[str, dict] = {}

    def __len__(self) -> int:
        return len(self._endpoints)

    def observe(self, record: dict, assessment: dict) -> None:
        if not assessment.get("applicable"):
            return
        sni = record.get("sni")
        key = sni or (record.get("dst") or "").rsplit(":", 1)[0]
        if not key:
            return
        ep = self._endpoints.get(key)
        if ep is None:
            ep = {
                "endpoint": key,
                "kind": "sni" if sni else "ip",
                "sector": self.classifier.classify(key),
                "flows": 0,
                "bytes": 0,
                "first_ts": record.get("start_ts"),
                "last_ts": record.get("last_ts"),
                "risks": Counter(),
                "min_score": 100,
                "max_score": 0,
                "vulnerable_flows": 0,
                "pq_ready_flows": 0,
                "algorithms": set(),
                "versions": set(),
                "actions": set(),
            }
            self._endpoints[key] = ep

        score = assessment.get("score")
        ep["flows"] += 1
        ep["bytes"] += int(record.get("bytes") or 0)
        ep["risks"][assessment.get("risk", "unknown")] += 1
        if record.get("start_ts"):
            ep["first_ts"] = min(ep["first_ts"] or record["start_ts"], record["start_ts"])
        if record.get("last_ts"):
            ep["last_ts"] = max(ep["last_ts"] or 0, record["last_ts"])
        if score is not None:
            ep["min_score"] = min(ep["min_score"], score)
            ep["max_score"] = max(ep["max_score"], score)
            if assessment.get("quantum_vulnerable"):
                ep["vulnerable_flows"] += 1
            else:
                ep["pq_ready_flows"] += 1
        kx = assessment.get("kx", {})
        if kx.get("name") and not str(kx["name"]).startswith("unknown"):
            ep["algorithms"].add(f"{kx['name']} ({kx['kx_class']})")
        cipher = assessment.get("cipher", {})
        if cipher.get("name") and not str(cipher["name"]).startswith("unknown"):
            ep["algorithms"].add(cipher["name"])
        if assessment.get("version"):
            ep["versions"].add(assessment["version"])
        ep["actions"].update(assessment.get("actions", []))

    # -- reporting ----------------------------------------------------------

    def summary(self) -> dict:
        risk_counts: Counter = Counter()
        sector_counts: Counter = Counter()
        vulnerable = ready = 0
        flows = 0
        for ep in self._endpoints.values():
            risk_counts.update(ep["risks"])
            sector_counts[ep["sector"]] += 1
            flows += ep["flows"]
            # endpoint posture = its worst flow
            if ep["vulnerable_flows"] and ep["min_score"] < 55:
                vulnerable += 1
            elif ep["min_score"] >= 55:
                ready += 1
        return {
            "endpoints": len(self._endpoints),
            "flows": flows,
            "risk_distribution": dict(risk_counts),
            "by_sector": dict(sector_counts),
            "vulnerable_endpoints": vulnerable,
            "quantum_ready_endpoints": ready,
        }

    def endpoints(self, limit: int = 100, sector: str | None = None,
                  worst_first: bool = True) -> list[dict]:
        rows = []
        for ep in self._endpoints.values():
            if sector and ep["sector"] != sector:
                continue
            rows.append({
                "endpoint": ep["endpoint"],
                "kind": ep["kind"],
                "sector": ep["sector"],
                "flows": ep["flows"],
                "bytes": ep["bytes"],
                "min_score": ep["min_score"] if ep["flows"] else None,
                "max_score": ep["max_score"] if ep["flows"] else None,
                "vulnerable_flows": ep["vulnerable_flows"],
                "pq_ready_flows": ep["pq_ready_flows"],
                "risk_distribution": dict(ep["risks"]),
                "algorithms": sorted(ep["algorithms"]),
                "versions": sorted(ep["versions"]),
                "actions": sorted(ep["actions"]),
                "first_ts": ep["first_ts"],
                "last_ts": ep["last_ts"],
            })
        rows.sort(
            key=lambda r: (r["min_score"] if r["min_score"] is not None else -1),
            reverse=not worst_first,
        )
        return rows[:limit]

    def reset(self) -> None:
        self._endpoints.clear()
