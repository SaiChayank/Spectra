"""ZKP audit-trail routes (Module 5) over the audit service."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..runtime import engine
from ..schemas import Num, Out
from ..security import require

router = APIRouter(dependencies=[Depends(require("investigate"))])


class AuditEntry(Out):
    seq: int
    ts: Num
    kind: str
    actor: Optional[str] = None
    payload: Optional[dict[str, Any]] = None
    prev_hash: Optional[str] = None
    entry_hash: str
    leaves: Optional[list[Any]] = None
    merkle_root: Optional[str] = None


class AuditEntries(Out):
    count: int
    signing_key: str
    items: list[AuditEntry]


class AuditHead(Out):
    """``seq`` 0 with null ``ts``/``kind`` while the log is empty."""
    seq: int
    entry_hash: str
    ts: Optional[Num] = None
    kind: Optional[str] = None


class AuditVerify(Out):
    ok: bool
    entries: Optional[int] = None
    epoch: Optional[int] = None
    epochs: Optional[list[dict[str, Any]]] = None
    errors: Optional[list[Any]] = None
    head: Optional[AuditHead] = None
    signing_key: Optional[str] = None


class AuditCheckpoint(Out):
    seq: int
    epoch: int
    entries: int
    covered_from: int
    covered_to: int
    root: str
    entry_hash: str
    pubkey: str
    signature: str


class AuditKeyRotation(Out):
    epoch: int
    pubkey: str
    previous_pubkey: str
    start_seq: int
    entry_seq: int


class AuditChecks(Out):
    """Verification result: overall ``ok`` plus every named check."""
    ok: bool
    checks: list[dict[str, Any]]
    root: Optional[str] = None
    seq: Optional[int] = None
    claims_ok: Optional[bool] = None


class AuditProof(Out):
    seq: int
    entry_hash: str
    merkle_root: str
    index: int
    leaf: str
    siblings: list[Any]
    count: int


class AuditCertificate(Out):
    """Signed certificate bundle; the claims depend on the profile."""
    type: str
    version: int
    profile: str
    issued_at: Num
    issuer: dict[str, Any]
    window: dict[str, Any]
    chain_head: dict[str, Any]
    claims: list[dict[str, Any]]
    disclosure_policy: dict[str, Any]
    pubkey: str
    signature: str


class CertificateRequest(BaseModel):
    profile: str = Field("hipaa", pattern="^(hipaa|pci_dss|gdpr)$")
    since: float | None = None
    until: float | None = None
    min_flows: int = Field(1, ge=0)
    disclose: int = Field(3, ge=0, le=50)
    bits: int = Field(32, ge=1, le=64)


class CertificateVerifyRequest(BaseModel):
    certificate: dict


@router.get("/api/audit/entries", response_model=AuditEntries)
def audit_entries(limit: int = Query(50, ge=1, le=500),
                  offset: int = Query(0, ge=0),
                  kind: str | None = None,
                  since: float | None = None,
                  until: float | None = None,
                  actor: str | None = None) -> dict:
    """Hash-chained audit entries (newest first), time/actor/kind filtered."""
    return engine.audit_service.entries(limit=limit, offset=offset, kind=kind,
                                        since=since, until=until, actor=actor)


@router.get("/api/audit/head", response_model=AuditHead)
def audit_head() -> dict:
    return engine.audit_service.head()


@router.get("/api/audit/verify", response_model=AuditVerify)
def audit_verify() -> dict:
    """Full chain verification: sequence, prev links, entry hashes."""
    return engine.audit_service.verify()


@router.post("/api/audit/checkpoint", response_model=AuditCheckpoint)
def audit_checkpoint() -> dict:
    """Merkle-root + Schnorr-sign everything since the previous checkpoint."""
    from ...modules.audit import AuditError

    try:
        return engine.audit_service.checkpoint()
    except AuditError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/api/audit/rotate-key", response_model=AuditKeyRotation,
             dependencies=[Depends(require("config:manage"))])
def audit_rotate_key(principal: dict = Depends(require("config:manage"))) -> dict:
    """Rotate the audit signing key (ADMIN). Chain-recorded as ``audit.key_rotated``;
    earlier checkpoints keep verifying against their own epoch. Returns public
    material only."""
    return engine.audit_service.rotate_key(actor=principal["username"])


@router.get("/api/audit/checkpoint/verify", response_model=AuditChecks)
def audit_checkpoint_verify(seq: int | None = Query(None, ge=1)) -> dict:
    from ...modules.audit import AuditError

    try:
        return engine.audit_service.verify_checkpoint(seq)
    except AuditError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/api/audit/proof", response_model=AuditProof)
def audit_proof(seq: int = Query(..., ge=1),
                leaf: int = Query(..., ge=0)) -> dict:
    """Merkle inclusion proof for one committed flow record."""
    try:
        return engine.audit_service.proof(seq, leaf)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/audit/certificate", response_model=AuditCertificate)
def audit_certificate(req: CertificateRequest) -> dict:
    """Issue a signed compliance certificate (ZK claims + selective disclosure)."""
    from ...modules.audit import CertificateError

    try:
        return engine.audit_service.certify(
            profile=req.profile, since=req.since, until=req.until,
            min_flows=req.min_flows, disclose=req.disclose, bits=req.bits)
    except CertificateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/audit/certificate/verify", response_model=AuditChecks)
def audit_certificate_verify(req: CertificateVerifyRequest) -> dict:
    """Independently verify a certificate bundle (no database needed)."""
    return engine.audit_service.verify_certificate(req.certificate)
