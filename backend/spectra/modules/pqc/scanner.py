"""Quantum risk assessment for a single TLS conversation (Module 1 core).

Produces a per-flow "quantum readiness" verdict:

    score   0..100  (100 = fully quantum-safe posture)
    risk    critical | high | moderate | low | quantum_ready | unknown
    reasons human-readable drivers behind the score
    actions concrete migration steps (fed by the roadmap generator)
"""

from __future__ import annotations

from ...parse.tls import TlsMetadata, tls_version_name
from .registry import (
    PQ_SIGNATURE_CODES,
    best_group,
    cipher_info,
    group_info,
    signature_info,
)

RISK_ORDER = ["unknown", "critical", "high", "moderate", "low", "quantum_ready"]

# score thresholds (inclusive lower bound)
_LEVELS = [
    (80, "quantum_ready"),
    (55, "low"),
    (30, "moderate"),
    (15, "high"),
    (0, "critical"),
]

# HNDL-relevant: flows below this score are harvestable by a future quantum adversary
VULNERABLE_BELOW = 55


def risk_from_score(score: int | None) -> str:
    if score is None:
        return "unknown"
    for low, name in _LEVELS:
        if score >= low:
            return name
    return "critical"


def _version_code(client: TlsMetadata | None, server: TlsMetadata | None) -> int:
    if server and server.negotiated_version:
        return server.negotiated_version
    if client and client.negotiated_version:
        return client.negotiated_version
    if server and server.legacy_version:
        return server.legacy_version
    if client and client.legacy_version:
        return client.legacy_version
    return 0


def assess_handshake(client: TlsMetadata | None, server: TlsMetadata | None) -> dict:
    """Classify one flow's key exchange, authentication and TLS version."""
    if client is None and server is None:
        return {
            "applicable": False,
            "risk": "unknown",
            "score": None,
            "reasons": ["no TLS/QUIC handshake observed (plaintext, unopened Initial or mid-stream join)"],
            "actions": [],
        }

    reasons: list[str] = []
    actions: list[str] = []

    version = _version_code(client, server)
    version_name = tls_version_name(version) if version else "unknown"

    # --- key exchange group -------------------------------------------------
    negotiated_from_server = bool(server and server.selected_group)
    if negotiated_from_server:
        group_code = server.selected_group
    elif client and client.key_share_groups:
        group_code = best_group(client.key_share_groups)
    elif client and client.curves:
        group_code = best_group(client.curves)
    else:
        group_code = 0
    group = group_info(group_code)
    group_source = "negotiated" if negotiated_from_server else "client_offered"

    # --- cipher suite -------------------------------------------------------
    if server and server.selected_cipher:
        suite = cipher_info(server.selected_cipher)
        suite_source = "negotiated"
    elif client and client.cipher_suites:
        suite = cipher_info(client.cipher_suites[0])
        suite_source = "client_first_choice"
    else:
        suite = cipher_info(0)
        suite_source = "unknown"

    # --- authentication -----------------------------------------------------
    pq_sig_algs = [
        signature_info(c) for c in (client.signature_algorithms if client else [])
        if c in PQ_SIGNATURE_CODES
    ]
    classical_sig_count = sum(
        1 for c in (client.signature_algorithms if client else [])
        if signature_info(c)["quantum"] == "vulnerable"
    )

    # --- scoring ------------------------------------------------------------
    score = 0
    # RSA key transport wins the verdict: whatever curves the client offers,
    # the negotiated suite proves the shared secret came from an RSA encrypt.
    if suite["scheme"] == "rsa_transport":
        score += 0
        kx_scheme = "rsa_transport"
        reasons.append("RSA key transport - no forward secrecy, harvestable at any time")
        actions.append("disable RSA key transport suites; require ECDHE/TLS 1.3")
    elif group["kx_class"] in ("pqc", "hybrid"):
        score += 65 if group["kx_class"] == "pqc" else 60
        kx_scheme = "quantum_resistant"
        reasons.append(
            f"key exchange uses {group['name']} ({group['kx_class']}, quantum-resistant)"
        )
    elif group["kx_class"] == "classical":
        score += 15
        kx_scheme = "classical_ephemeral"
        reasons.append(f"key exchange uses classical group {group['name']} (harvestable)")
        actions.append(f"enable a hybrid group (e.g. X25519MLKEM768) for {group['name']}")
    else:
        kx_scheme = "unknown"
        reasons.append("key exchange group could not be determined")

    if version == 0x0304:
        score += 20
    elif version == 0x0303:
        score += 12
        reasons.append("TLS 1.2 - plan for a TLS 1.3 cutover")
        actions.append("upgrade endpoint to TLS 1.3")
    elif version in (0x0301, 0x0302, 0x0300):
        reasons.append(f"{version_name} is deprecated and offers no modern security")
        actions.append(f"disable {version_name}; enforce TLS 1.2+ (prefer 1.3)")
    else:
        reasons.append("TLS version unknown")

    if pq_sig_algs:
        score += 15
        reasons.append(
            "client offers post-quantum signatures: "
            + ", ".join(s["name"] for s in pq_sig_algs)
        )
    elif classical_sig_count:
        score += 5
        reasons.append("authentication is classically signed only (RSA/ECDSA/EdDSA)")
        actions.append("plan certificate migration to ML-DSA (FIPS 204)")

    if suite.get("aead"):
        score += 5
    if suite.get("deprecated"):
        reasons.append(f"cipher suite {suite['name']} is deprecated")
        actions.append(f"remove {suite['name']} from the endpoint's suite list")

    score = max(0, min(100, score))
    risk = risk_from_score(score)

    if group_source == "client_offered" and group["kx_class"] in ("pqc", "hybrid"):
        reasons.append(
            "client *offers* a quantum-resistant group but no ServerHello was seen "
            "(negotiation unconfirmed)"
        )

    return {
        "applicable": True,
        "version": version_name,
        "version_code": version,
        "risk": risk,
        "score": score,
        "quantum_vulnerable": score < VULNERABLE_BELOW,
        "kx_scheme": kx_scheme,
        "kx": {
            **group,
            "source": group_source,
            "offered": [group_info(c)["name"] for c in (client.key_share_groups if client else [])],
        },
        "cipher": {**suite, "source": suite_source},
        "auth": {
            "pq_signatures_offered": [s["name"] for s in pq_sig_algs],
            "classical_signatures_offered": classical_sig_count,
        },
        "reasons": reasons,
        "actions": sorted(set(actions)),
    }


def assess_flow(flow) -> dict:  # Flow
    """Convenience wrapper over a tracked Flow object."""
    return assess_handshake(flow.client_tls, flow.server_tls)
