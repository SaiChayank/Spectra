"""ZKP audit-trail routes (Module 5) over the audit service."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..runtime import engine
from ..security import require

router = APIRouter(dependencies=[Depends(require("investigate"))])


class CertificateRequest(BaseModel):
    profile: str = Field("hipaa", pattern="^(hipaa|pci_dss|gdpr)$")
    since: float | None = None
    until: float | None = None
    min_flows: int = Field(1, ge=0)
    disclose: int = Field(3, ge=0, le=50)
    bits: int = Field(32, ge=1, le=64)


class CertificateVerifyRequest(BaseModel):
    certificate: dict


@router.get("/api/audit/entries")
def audit_entries(limit: int = Query(50, ge=1, le=500),
                  offset: int = Query(0, ge=0),
                  kind: str | None = None,
                  since: float | None = None,
                  until: float | None = None,
                  actor: str | None = None) -> dict:
    """Hash-chained audit entries (newest first), time/actor/kind filtered."""
    return engine.audit_service.entries(limit=limit, offset=offset, kind=kind,
                                        since=since, until=until, actor=actor)


@router.get("/api/audit/head")
def audit_head() -> dict:
    return engine.audit_service.head()


@router.get("/api/audit/verify")
def audit_verify() -> dict:
    """Full chain verification: sequence, prev links, entry hashes."""
    return engine.audit_service.verify()


@router.post("/api/audit/checkpoint")
def audit_checkpoint() -> dict:
    """Merkle-root + Schnorr-sign everything since the previous checkpoint."""
    from ...modules.audit import AuditError

    try:
        return engine.audit_service.checkpoint()
    except AuditError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/api/audit/checkpoint/verify")
def audit_checkpoint_verify(seq: int | None = Query(None, ge=1)) -> dict:
    from ...modules.audit import AuditError

    try:
        return engine.audit_service.verify_checkpoint(seq)
    except AuditError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/api/audit/proof")
def audit_proof(seq: int = Query(..., ge=1),
                leaf: int = Query(..., ge=0)) -> dict:
    """Merkle inclusion proof for one committed flow record."""
    try:
        return engine.audit_service.proof(seq, leaf)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/audit/certificate")
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


@router.post("/api/audit/certificate/verify")
def audit_certificate_verify(req: CertificateVerifyRequest) -> dict:
    """Independently verify a certificate bundle (no database needed)."""
    return engine.audit_service.verify_certificate(req.certificate)
