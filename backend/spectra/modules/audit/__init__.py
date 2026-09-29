"""Module 5: Zero-Knowledge Proof audit trail.

Public surface:
    AuditLog            - hash-chained append-only log + Merkle checkpoints
    build_certificate   - signed compliance certificate (HIPAA/PCI-DSS/GDPR)
    verify_certificate  - independent verification of a certificate bundle
    PROFILES            - claim sets per compliance profile
    merkle helpers      - leaf_hash / merkle_root / verify_merkle_proof
    ZKP primitives      - Pedersen commitments, zero + threshold proofs
"""

from .certify import (
    CertificateError,
    DISCLOSABLE_KEYS,
    PROFILES,
    build_certificate,
    sanitize,
    verify_certificate,
)
from .curve import (
    compress,
    decompress,
    pt_add,
    pt_mul,
    schnorr_keypair,
    schnorr_sign,
    schnorr_verify,
)
from .log import AuditError, AuditLog
from .merkle import (
    canonical_json,
    leaf_hash,
    merkle_proof,
    merkle_root,
    verify_merkle_proof,
)
from .zkp import (
    ZKPError,
    commit,
    prove_threshold,
    prove_zero,
    verify_opening,
    verify_threshold,
    verify_zero,
)

__all__ = [
    "AuditError",
    "AuditLog",
    "CertificateError",
    "DISCLOSABLE_KEYS",
    "PROFILES",
    "ZKPError",
    "build_certificate",
    "canonical_json",
    "commit",
    "compress",
    "decompress",
    "leaf_hash",
    "merkle_proof",
    "merkle_root",
    "prove_threshold",
    "prove_zero",
    "pt_add",
    "pt_mul",
    "sanitize",
    "schnorr_keypair",
    "schnorr_sign",
    "schnorr_verify",
    "verify_certificate",
    "verify_merkle_proof",
    "verify_opening",
    "verify_threshold",
    "verify_zero",
]
