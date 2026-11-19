"""Host triage routes (v0): ranked internal hosts, evidence timeline, verdict.

An aggregation of existing alert evidence per internal source host, NOT
fusion (docs/35 E4) and NOT calibrated: see :mod:`spectra.services.hosts`.
Reads need ``read``; a verdict needs ``incidents:manage`` (the same
permission as acknowledging/resolving alerts) and is audited.  Verdicts are
stored only; nothing is suppressed from them yet (E6).
"""

from __future__ import annotations

import ipaddress
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ...services.hosts import HostNotFound
from ..runtime import engine
from ..security import require

router = APIRouter(dependencies=[Depends(require("read"))])


class HostVerdict(BaseModel):
    verdict: Literal["true", "expected", "false"]
    note: Optional[str] = None
    actor: str
    created_at: float


class TopEvidence(BaseModel):
    detector: str
    technique: Optional[str] = None
    destination: str
    strength: float


class HostSummary(BaseModel):
    host: str
    rank: int
    confidence: float  # NOT a calibrated probability (see services.hosts)
    evidence_count: int
    top_evidence: TopEvidence
    first_seen: float
    last_seen: float
    verdict: Optional[HostVerdict] = None


class HostList(BaseModel):
    count: int
    offset: int
    items: list[HostSummary]


class EvidenceItem(BaseModel):
    detector: str
    threat_type: str
    technique: Optional[str] = None
    first_seen: float
    time: float
    destination: str
    strength: float
    occurrences: int
    alert_id: str
    flow_ids: list[int]


class HostEvidence(BaseModel):
    host: str
    count: int
    items: list[EvidenceItem]
    verdict: Optional[HostVerdict] = None


class VerdictRequest(BaseModel):
    verdict: Literal["true", "expected", "false"]
    note: Optional[str] = Field(None, max_length=500)


class StoredVerdict(HostVerdict):
    host: str


def _host(host: str) -> str:
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        raise HTTPException(status_code=422, detail="host must be an IP address")


@router.get("/api/hosts", response_model=HostList)
def hosts_list(
    sort: Literal["risk", "last_seen"] = "risk",
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    since: float | None = Query(None, description="evidence seen at/after"),
) -> dict:
    """Internal hosts with evidence, ranked by confidence (not calibrated)."""
    return engine.hosts.list(sort=sort, limit=limit, offset=offset,
                             since=since)


@router.get("/api/hosts/{host}/evidence", response_model=HostEvidence)
def hosts_evidence(host: str) -> dict:
    """The host's evidence timeline, newest first (404 when none)."""
    try:
        return engine.hosts.evidence(_host(host))
    except HostNotFound:
        raise HTTPException(status_code=404, detail="no evidence for host")


@router.post("/api/hosts/{host}/verdict", response_model=StoredVerdict)
def hosts_verdict(
    host: str, body: VerdictRequest,
    principal: dict = Depends(require("incidents:manage")),
) -> dict:
    """Record true / expected / false for a host (append-only, latest wins)."""
    host = _host(host)
    try:
        stored = engine.hosts.set_verdict(host, body.verdict, body.note,
                                          principal["username"])
    except HostNotFound:
        raise HTTPException(status_code=404, detail="no evidence for host")
    engine.audit_service.append(
        "host.verdict", {"host": host, "verdict": body.verdict},
        actor=principal["username"])
    return stored
