"""Capability maturity + integration contracts for Spectra's advanced modules.

Every advanced module reports where it sits on the maturity ladder so API
consumers (and the dashboard) can tell real integration from local
simulation. ``HARDWARE_BACKED`` is reserved for functionality backed by
actual hardware (e.g. SGX/SEV attestation, a vendor MEC/5G control plane);
nothing in this build claims it, and simulated surfaces must never be
described as production hardware integrations.

Each entry also declares its *integration contract* - what it consumes,
what it produces, whether it can move alert scoring (confidence/severity),
whether it only contributes evidence, and how it degrades when it fails -
so module behaviour is explicit in one place instead of implied by code
paths. ``SCORING_POLICY`` is the invariant that ties the table together:
no module in this build changes the anomaly score, the alert confidence
or the severity.
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

#: The scoring invariant: every module below is evidence/context only.
SCORING_POLICY: str = (
    "No advanced module changes the anomaly score, the alert confidence, "
    "or the severity: every module contributes supporting evidence or "
    "context only, and no module may invent an independent threat verdict."
)

# module/component -> contract (maturity + integration guarantees)
#   title                - human label for dashboards
#   status               - maturity ladder entry (see DEFINITIONS)
#   hardware_backed      - always False in this build (nothing is HW-backed)
#   note                 - one honest sentence about what it really is
#   consumes             - the input it reads
#   produces             - the output it contributes
#   affects_alert_scoring- True only if it may move score/confidence/
#                          severity (all False here - see SCORING_POLICY)
#   evidence_only        - True when it contributes evidence/context only
#   failure              - degradation behaviour on failure
_MODULE_CAPABILITIES: dict[str, dict] = {
    "pqc": {
        "title": "PQC crypto-readiness",
        "status": REAL,
        "hardware_backed": False,
        "note": "Heuristic quantum-risk scoring over real parsed TLS/QUIC "
                "handshakes.",
        "consumes": "Parsed TLS/QUIC handshake metadata (versions, groups, "
                    "ciphers, JA3/JA4) from every scored flow.",
        "produces": "Per-flow quantum-risk assessment persisted on the flow "
                    "record and copied onto alerts as module evidence; an "
                    "endpoint inventory with a migration roadmap.",
        "affects_alert_scoring": False,
        "evidence_only": True,
        "failure": "Guarded on the detection path (component 'pqc'): a "
                   "failure drops the annotation, never the flow.",
    },
    "adversarial": {
        "title": "Adversarial resilience",
        "status": REAL,
        "hardware_backed": False,
        "note": "White-box evasion, drift and robustness analysis against "
                "the fitted model.",
        "consumes": "The live score stream (evasion watch window) and the "
                    "fitted model with recent feature vectors (drift and "
                    "robustness runs).",
        "produces": "Evasion/drift context as system events and audit "
                    "entries, plus on-demand robustness reports; surfaced "
                    "as robustness observations in investigations.",
        "affects_alert_scoring": False,
        "evidence_only": True,
        "failure": "Guarded (component 'adversarial_watch'); drift refresh "
                   "is best effort and report endpoints return "
                   "available:false instead of raising.",
    },
    "correlation": {
        "title": "Correlation graph",
        "status": REAL,
        "hardware_backed": False,
        "note": "Attack-graph correlation over observed flow records.",
        "consumes": "Published flow records (endpoints, SNI, sector) and "
                    "hydrated flow history.",
        "produces": "Attack-graph nodes/edges plus incident relatedness "
                    "context: anchors, affected entities and one-hop "
                    "graph slices for investigations.",
        "affects_alert_scoring": False,
        "evidence_only": True,
        "failure": "Guarded (component 'correlation'): a graph failure "
                   "never kills publication, and bundles degrade to "
                   "available:false graph/twin sections.",
    },
    "audit": {
        "title": "Audit chain / ZKP",
        "status": EXPERIMENTAL,
        "hardware_backed": False,
        "note": "Research-grade pure-Python cryptography (hash chain, "
                "Merkle, Schnorr, ZK statements); not production-hardened. "
                "Proofs demonstrate tamper-evidence of this log, not "
                "regulatory compliance.",
        "consumes": "Audit events emitted across the pipeline and flow "
                    "records committed as Merkle leaves at capture stop.",
        "produces": "Tamper-evident integrity references - chained entries, "
                    "Merkle inclusion proofs, signed checkpoints - which "
                    "investigation bundles cite for incident/alert actions.",
        "affects_alert_scoring": False,
        "evidence_only": True,
        "failure": "Guarded (component 'audit'): appends are best effort - "
                   "a failure is counted and logged while capture and "
                   "detection continue.",
    },
    "bio": {
        "title": "Bio-inspired detection",
        "status": EXPERIMENTAL,
        "hardware_backed": False,
        "note": "Bio-inspired danger/SNN/swarm heuristics - research "
                "prototype.",
        "consumes": "Scored feature vectors plus drift/evasion context and "
                    "the edge timing scale.",
        "produces": "Behavioural annotations (immune danger level, SNN "
                    "score, swarm vote) on flow records and alerts - "
                    "supporting evidence that never invents an independent "
                    "threat verdict.",
        "affects_alert_scoring": False,
        "evidence_only": True,
        "failure": "Guarded (component 'bio'): an untrained or failing bio "
                   "system is skipped; detection continues without the "
                   "annotation.",
    },
    "tee": {
        "title": "TEE attestation",
        "status": SIMULATED,
        "hardware_backed": False,
        "note": "Simulated enclave in-process; a real deployment requires "
                "SGX/SEV hardware. Never hardware-backed in this build.",
        "consumes": "The model artifact path (for its measurement), "
                    "caller-supplied nonces, feature vectors and quotes.",
        "produces": "Local simulated attestation quotes, verification "
                    "checks and sealed-inference receipts - reported as "
                    "simulated unless real hardware is present, which it "
                    "never is in this build.",
        "affects_alert_scoring": False,
        "evidence_only": True,
        "failure": "Off the detection path: a missing enclave raises "
                   "TeeError -> HTTP 400 on its own routes and never "
                   "affects scoring or capture.",
    },
    "federated": {
        "title": "Federated aggregation",
        "status": SIMULATED,
        "hardware_backed": False,
        "note": "Real additive secret-sharing math over locally simulated "
                "parties.",
        "consumes": "Model delta vectors (explicit, or derived from the "
                    "live score window).",
        "produces": "Secret-shared secure aggregation over locally "
                    "simulated parties with a verifiable aggregate digest.",
        "affects_alert_scoring": False,
        "evidence_only": True,
        "failure": "Off the detection path: errors surface as explicit "
                   "API errors only.",
    },
    "twin": {
        "title": "Digital twin",
        "status": SIMULATED,
        "hardware_backed": False,
        "note": "Deterministic local simulator; no live-network coupling.",
        "consumes": "The correlation graph topology built from observed "
                    "flows only (no invented infrastructure).",
        "produces": "Deterministic blast-radius simulation, playbook "
                    "rehearsal and zone/criticality context alongside an "
                    "investigation.",
        "affects_alert_scoring": False,
        "evidence_only": True,
        "failure": "Read-side only: bundle twin context degrades to "
                   "available:false and never raises into the pipeline.",
    },
    "edge": {
        "title": "Edge / 5G slicing",
        "status": LOCAL,
        "hardware_backed": False,
        "note": "Real micro-detector scoring with local, single-process "
                "scope.",
        "consumes": "Flow records for slice classification, fitted "
                    "micro-detector features for local scoring, and link "
                    "profile RTT for the timing scale.",
        "produces": "Network-slice tags on flows and alerts, slice policy "
                    "adjustments for the immune ladder, and local "
                    "micro-detector latency reports.",
        "affects_alert_scoring": False,
        "evidence_only": True,
        "failure": "Guarded (component 'edge_slice'): classification falls "
                   "back to the 'default' slice and capture continues.",
    },
    "edge_deployment": {
        "title": "Edge deployment registry",
        "status": SIMULATED,
        "hardware_backed": False,
        "note": "In-process deployment/NTN registry; no real MEC or 5G "
                "control plane.",
        "consumes": "Deploy requests naming a node and a network slice.",
        "produces": "In-process deployment records explicitly marked "
                    "capability: SIMULATED - not a remote edge agent.",
        "affects_alert_scoring": False,
        "evidence_only": True,
        "failure": "Off the detection path: validation errors return "
                   "HTTP 400 on its own routes only.",
    },
}


def capability_contracts() -> dict[str, dict]:
    """Maturity + integration contract for every advanced module."""
    return {
        name: {
            "title": entry["title"],
            "status": entry["status"],
            "hardware_backed": entry["hardware_backed"],
            "note": entry["note"],
            "consumes": entry["consumes"],
            "produces": entry["produces"],
            "affects_alert_scoring": entry["affects_alert_scoring"],
            "evidence_only": entry["evidence_only"],
            "failure": entry["failure"],
        }
        for name, entry in _MODULE_CAPABILITIES.items()
    }


def module_capabilities(live: dict | None = None) -> dict:
    """Capability status for every advanced module (API-safe summary).

    ``live`` optionally carries per-module availability probed from the
    running engine (``SpectraEngine.capability_status``).  Entries missing
    from it keep ``available: None`` so consumers can tell "not probed"
    from "probed and down".
    """
    live = live or {}
    modules: dict[str, dict] = {}
    for name, contract in capability_contracts().items():
        probe = live.get(name) or {}
        modules[name] = {
            **contract,
            "available": probe.get("available"),
            "detail": probe.get("detail"),
            "failures": probe.get("failures"),
        }
    return {
        "statuses": list(CAPABILITIES),
        "definitions": dict(DEFINITIONS),
        "scoring_policy": SCORING_POLICY,
        "modules": modules,
        "hardware_backed_count": sum(
            1 for m in modules.values() if m["status"] == HARDWARE_BACKED
        ),
    }
