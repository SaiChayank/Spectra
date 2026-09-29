"""Sector-aware PQC migration roadmap generator (Module 1).

Turns inventory findings and HNDL suspects into a prioritised, phase-based
transition plan (0-6 / 6-18 / 18-36 months - matching the product doc's
Phase 1/2/3 legend).
"""

from __future__ import annotations

from ...sectors import SectorClassifier, get_classifier


def _item(item_id, title, priority, effort, affected, rationale, actions=None,
          reference=None):
    return {
        "id": item_id,
        "title": title,
        "priority": priority,        # P0 = do now, P1 = this quarter, P2 = strategic
        "effort": effort,            # S / M / L
        "affected": affected,
        "rationale": rationale,
        "actions": actions or [],
        "reference": reference,
    }


def generate_roadmap(
    summary: dict,
    endpoints: list[dict] | None = None,
    hndl_findings: list[dict] | None = None,
    sector: str | None = None,
) -> dict:
    endpoints = endpoints or []
    hndl_findings = hndl_findings or []
    if sector:
        endpoints = [e for e in endpoints if e.get("sector") == sector]
        hndl_findings = [f for f in hndl_findings if f.get("sector") == sector]

    vulnerable = [e for e in endpoints if (e.get("min_score") or 100) < 55]
    rsa_endpoints = [e for e in endpoints if any("RSA key transport" in a or "disable RSA" in a
                                                 for a in e.get("actions", []))]
    legacy_tls = [e for e in endpoints if any("disable TLS" in a or "deprecated" in a
                                              for a in e.get("actions", []))]
    hybrid_offered = [
        e for e in endpoints
        if any("hybrid" in algo or "MLKEM" in algo or "Kyber" in algo
               for algo in e.get("algorithms", []))
    ]
    already_ready = [e for e in endpoints if (e.get("min_score") or 0) >= 80]
    high_hndl = [f for f in hndl_findings if f.get("level") == "high"]

    phase1, phase2, phase3 = [], [], []

    # ---- Phase 1: immediate (0-6 months) ----------------------------------
    if high_hndl:
        phase1.append(_item(
            "hndl-contain",
            "Contain harvest-now-decrypt-later exposure",
            "P0", "M", len(high_hndl),
            f"{len(high_hndl)} bulk flow(s) on quantum-vulnerable crypto are worth "
            "harvesting today; long-lived data (records, telemetry) stays valuable "
            "for 5-15 years.",
            actions=[
                f"re-key or re-route {f['endpoint']} ({f['bytes']:,} bytes, "
                f"{f['level']} risk)" for f in high_hndl[:10]
            ],
            reference="Product doc: HNDL Threat Intelligence",
        ))
    if rsa_endpoints:
        phase1.append(_item(
            "kill-rsa-transport",
            "Disable RSA key transport",
            "P0", "S", len(rsa_endpoints),
            "RSA key transport provides no forward secrecy: recorded handshakes "
            "can be decrypted once the RSA key is broken by a quantum computer.",
            actions=[f"remove RSA suites on {e['endpoint']}" for e in rsa_endpoints[:20]],
            reference="RFC 8996 (TLS 1.0/1.1), NIST SP 800-131A",
        ))
    if legacy_tls:
        phase1.append(_item(
            "retire-legacy-tls",
            "Retire TLS < 1.2 on observed endpoints",
            "P0", "S", len(legacy_tls),
            "Legacy versions lack AEAD/HKDF and are incompatible with hybrid "
            "key exchange.",
            actions=[f"enforce TLS 1.2+ on {e['endpoint']}" for e in legacy_tls[:20]],
            reference="RFC 8996",
        ))
    if not phase1:
        phase1.append(_item(
            "baseline-ok",
            "No immediate quantum exposure found",
            "P2", "S", 0,
            "Current captures show no RSA-transport or legacy-TLS endpoints; "
            "keep monitoring.",
        ))

    # ---- Phase 2: near-term (6-18 months) ---------------------------------
    hybrid_targets = [e for e in vulnerable if e not in hybrid_offered]
    phase2.append(_item(
        "roll-out-hybrid-kx",
        "Roll out X25519MLKEM768 hybrid key exchange",
        "P1", "M", len(hybrid_targets) or summary.get("vulnerable_endpoints", 0),
        "Browsers, OpenSSL 3.5, BoringSSL and major CDNs negotiate "
        "X25519MLKEM768 by default; enabling it server-side is the single "
        "highest-leverage step against HNDL.",
        actions=[
            "OpenSSL: SSL_CTX_set1_groups_list(ctx, \"X25519MLKEM768:X25519:P-256\")",
            *[f"enable hybrid group on {e['endpoint']}" for e in hybrid_targets[:15]],
        ],
        reference="RFC 10024 (X25519MLKEM768, IANA 0x11EC)",
    ))
    if hybrid_offered:
        phase2.append(_item(
            "confirm-hybrid-negotiation",
            "Confirm negotiated (not just offered) hybrid groups",
            "P1", "S", len(hybrid_offered),
            f"{len(hybrid_offered)} endpoint(s) advertise a hybrid group in the "
            "ClientHello; verify the ServerHello selects it.",
            actions=[f"verify key_share selection for {e['endpoint']}"
                     for e in hybrid_offered[:15]],
            reference="Spectra detects group_source == 'negotiated'",
        ))
    phase2.append(_item(
        "pq-auth-pilot",
        "Pilot ML-DSA certificate authentication",
        "P1", "M", max(1, len(endpoints) // 10),
        "Signature schemes (RSA/ECDSA/EdDSA) are the second quantum casualty; "
        "ML-DSA (FIPS 204) is standardised with TLS codepoints 0x0904-0x0906.",
        actions=["stand up an internal PKI issuing mldsa65 certificates",
                 "test with draft-ietf-tls-mldsa capable clients"],
        reference="FIPS 204 / draft-ietf-tls-mldsa-06",
    ))

    # ---- Phase 3: strategic (18-36 months) --------------------------------
    phase3.append(_item(
        "crypto-agility-governance",
        "Institutionalise crypto-agility monitoring",
        "P2", "L", summary.get("endpoints", 0),
        "Keep a continuously verified inventory: algorithm posture must be a "
        "monitored metric, not an annual audit artefact.",
        actions=[
            "export Spectra /api/pqc/inventory into the CMDB on a schedule",
            "alert when any endpoint's readiness drops below 55/100",
            "quarterly HNDL review for sectors: "
            + ", ".join(sorted(summary.get("by_sector", {}).keys())) or "all",
        ],
        reference="Product doc: Crypto-Agility Monitor + Migration Roadmap Generator",
    ))
    if already_ready:
        phase3.append(_item(
            "maintain-ready",
            "Maintain quantum-ready endpoints",
            "P2", "S", len(already_ready),
            f"{len(already_ready)} endpoint(s) already reach the quantum-ready "
            "band; lock their configuration with policy-as-code.",
            actions=[f"pin groups for {e['endpoint']}" for e in already_ready[:15]],
        ))
    phase3.append(_item(
        "verify-continuously",
        "Continuous verification against live traffic",
        "P2", "S", 0,
        "Run Spectra captures against production baselines each quarter and "
        "diff the roadmap.",
        actions=["spectra pqc scan --pcap quarterly-baseline.pcap"],
    ))

    return {
        "sector": sector or "all",
        "generated_from": {
            "endpoints": summary.get("endpoints", 0),
            "vulnerable_endpoints": summary.get("vulnerable_endpoints", 0),
            "quantum_ready_endpoints": summary.get("quantum_ready_endpoints", 0),
            "hndl_findings": len(hndl_findings),
        },
        "phases": [
            {"phase": 1, "window": "0-6 months", "items": phase1},
            {"phase": 2, "window": "6-18 months", "items": phase2},
            {"phase": 3, "window": "18-36 months", "items": phase3},
        ],
    }
