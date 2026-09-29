"""Offline PQC scan of a PCAP file (used by the CLI and /api/pqc/scan)."""

from __future__ import annotations

from ...tools import collect_flows
from .hndl import screen_flows
from .inventory import PQCInventory
from .roadmap import generate_roadmap
from .scanner import assess_flow


def scan_pcap(path: str, idle_timeout: float = 30.0,
              sector: str | None = None) -> dict:
    """Read a PCAP and return the full PQC readiness report."""
    flows = collect_flows(path, idle_timeout=idle_timeout)
    inventory = PQCInventory()

    pairs: list[tuple[dict, dict]] = []
    assessments: list[dict] = []
    for flow in flows:
        record = flow.record()
        assessment = assess_flow(flow)
        record["pqc"] = assessment
        if assessment["applicable"]:
            inventory.observe(record, assessment)
            pairs.append((record, assessment))
            assessments.append({
                "src": record.get("src"),
                "dst": record.get("dst"),
                "sni": record.get("sni"),
                "risk": assessment["risk"],
                "score": assessment["score"],
                "version": assessment["version"],
                "kx": assessment["kx"].get("name"),
                "kx_class": assessment["kx"].get("kx_class"),
                "kx_source": assessment["kx"].get("source"),
                "cipher": assessment["cipher"].get("name"),
                "quantum_vulnerable": assessment["quantum_vulnerable"],
                "bytes": record.get("bytes"),
                "duration": record.get("duration"),
            })

    findings = screen_flows(pairs)
    summary = inventory.summary()
    endpoints = inventory.endpoints(limit=200, sector=sector)
    return {
        "pcap": path,
        "flows": len(flows),
        "assessed": len(assessments),
        "summary": summary,
        "endpoints": endpoints,
        "hndl": findings,
        "roadmap": generate_roadmap(summary, endpoints, findings, sector),
        "assessments": assessments,
    }
