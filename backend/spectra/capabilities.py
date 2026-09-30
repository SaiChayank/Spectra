"""Capability maturity vocabulary for Spectra's advanced modules.

Every advanced module reports where it sits on the maturity ladder so API
consumers (and the dashboard) can tell real integration from local
simulation. ``HARDWARE_BACKED`` is reserved for functionality backed by
actual hardware (e.g. SGX/SEV attestation, a vendor MEC/5G control plane);
nothing in this build claims it, and simulated surfaces must never be
described as production hardware integrations.
"""

from __future__ import annotations

REAL = "REAL"
LOCAL = "LOCAL"
SIMULATED = "SIMULATED"
EXPERIMENTAL = "EXPERIMENTAL"
HARDWARE_BACKED = "HARDWARE_BACKED"
UNAVAILABLE = "UNAVAILABLE"

CAPABILITIES: tuple[str, ...] = (
    REAL,
    LOCAL,
    SIMULATED,
    EXPERIMENTAL,
    HARDWARE_BACKED,
    UNAVAILABLE,
)

DEFINITIONS: dict[str, str] = {
    REAL: "Real functionality operating on real inputs - no simulated "
          "components.",
    LOCAL: "Real computation with local-only, single-process scope (not a "
           "distributed production integration).",
    SIMULATED: "Modeled or emulated behavior - the underlying integration "
               "does not exist in this build.",
    EXPERIMENTAL: "Research prototype: real mathematics, not hardened for "
                  "production use.",
    HARDWARE_BACKED: "Backed by dedicated hardware (e.g. an SGX/SEV enclave "
                     "or a vendor MEC/5G control plane).",
    UNAVAILABLE: "Not functional in this build.",
}

# module/component -> (status, hardware_backed, note)
_MODULE_CAPABILITIES: dict[str, dict] = {
    "pqc": {
        "status": REAL,
        "hardware_backed": False,
        "note": "Heuristic quantum-risk scoring over real parsed TLS/QUIC "
                "handshakes.",
    },
    "adversarial": {
        "status": REAL,
        "hardware_backed": False,
        "note": "White-box evasion, drift and robustness analysis against "
                "the fitted model.",
    },
    "correlation": {
        "status": REAL,
        "hardware_backed": False,
        "note": "Attack-graph correlation over observed flow records.",
    },
    "audit": {
        "status": EXPERIMENTAL,
        "hardware_backed": False,
        "note": "Research-grade pure-Python cryptography (hash chain, Merkle, "
                "Schnorr, ZK statements); not production-hardened.",
    },
    "bio": {
        "status": EXPERIMENTAL,
        "hardware_backed": False,
        "note": "Bio-inspired danger/SNN/swarm heuristics - research "
                "prototype.",
    },
    "tee": {
        "status": SIMULATED,
        "hardware_backed": False,
        "note": "Simulated enclave in-process; a real deployment requires "
                "SGX/SEV hardware. Never hardware-backed in this build.",
    },
    "federated": {
        "status": SIMULATED,
        "hardware_backed": False,
        "note": "Real additive secret-sharing math over locally simulated "
                "parties.",
    },
    "twin": {
        "status": SIMULATED,
        "hardware_backed": False,
        "note": "Deterministic local simulator; no live-network coupling.",
    },
    "edge": {
        "status": LOCAL,
        "hardware_backed": False,
        "note": "Real micro-detector scoring with local, single-process "
                "scope.",
    },
    "edge_deployment": {
        "status": SIMULATED,
        "hardware_backed": False,
        "note": "In-process deployment/NTN registry; no real MEC or 5G "
                "control plane.",
    },
}


def module_capabilities() -> dict:
    """Capability status for every advanced module (API-safe summary)."""
    modules = {
        name: {
            "status": entry["status"],
            "hardware_backed": entry["hardware_backed"],
            "note": entry["note"],
        }
        for name, entry in _MODULE_CAPABILITIES.items()
    }
    return {
        "statuses": list(CAPABILITIES),
        "definitions": dict(DEFINITIONS),
        "modules": modules,
        "hardware_backed_count": sum(
            1 for m in modules.values() if m["status"] == HARDWARE_BACKED
        ),
    }
