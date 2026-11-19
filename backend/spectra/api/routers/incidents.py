"""Incident routes: correlation, triage state machine, notes, timeline.

Reads require ``investigate``; every state change (including correlation and
alert membership) requires ``incidents:manage``.  The *service* attributes
each action to the caller and writes it to the hash-chained audit log plus
the incident timeline - the router only translates domain errors to HTTP.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from ...services.incidents import IncidentError
from ..runtime import engine
from ..schemas import Out
from .alerts import Alert
from ..security import auth_error, require

router = APIRouter(dependencies=[Depends(require("investigate"))])

_STATUS_PATTERN = "^(OPEN|INVESTIGATING|ACKNOWLEDGED|RESOLVED|FALSE_POSITIVE)$"


class Incident(Out):
    id: int
    title: str
    status: str
    created_at: Optional[float] = None
    created_by: Optional[str] = None
    updated_at: Optional[float] = None
    updated_by: Optional[str] = None
    acknowledged_at: Optional[float] = None
    acknowledged_by: Optional[str] = None
    resolved_at: Optional[float] = None
    resolved_by: Optional[str] = None
    detection_id: Optional[int] = None
    severity: Optional[str] = None
    confidence: Optional[float] = None
    summary: Optional[str] = None
    evidence_summary: Optional[str] = None
    primary_threat_class: Optional[str] = None
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    alert_count: Optional[int] = None
    note_count: Optional[int] = None  # absent on state-change responses
    affected_entities: list[str] = []
    model_versions: list[str] = []
    related_graph_nodes: list[str] = []


class IncidentList(Out):
    count: int
    offset: int
    items: list[Incident]


class IncidentNote(Out):
    id: int
    incident_id: int
    author: str
    body: str
    created_at: float


class IncidentDetail(Incident):
    notes: list[IncidentNote] = []
    alerts: list[Alert] = []
    timeline: list[dict[str, Any]] = []


class IncidentCorrelation(Out):
    clusters: int
    considered: int
    created: list[dict[str, Any]]
    ungrouped: list[str]


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    detection_id: int | None = Field(None, ge=1)
    alert_ids: list[str] | None = Field(None, max_length=200)
    summary: str | None = Field(None, max_length=2000)


class IncidentCorrelate(BaseModel):
    """Cluster unassigned alerts; omit ``alert_ids`` to consider all."""

    alert_ids: list[str] | None = Field(None, max_length=200)


class IncidentAttach(BaseModel):
    alert_ids: list[str] = Field(min_length=1, max_length=200)


class IncidentNoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=2000)


@router.get("/api/incidents", response_model=IncidentList)
def incidents_list(
    status: str | None = Query(None, pattern=_STATUS_PATTERN),
    severity: str | None = Query(None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"),
    threat_type: str | None = Query(None, max_length=64),
    since: float | None = Query(None, description="active at/after (overlap)"),
    until: float | None = Query(None, description="active at/before (overlap)"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict:
    """Incident page (newest first) with per-incident note counts.

    Filters combine (AND); the time range is overlap semantics over the
    incident's sighting interval (falling back to creation time).
    """
    try:
        return engine.incidents.list(status=status, severity=severity,
                                     threat_type=threat_type, since=since,
                                     until=until, limit=limit, offset=offset)
    except IncidentError as exc:
        raise auth_error(exc) from exc


@router.get("/api/incidents/{incident_id}", response_model=IncidentDetail)
def incidents_get(incident_id: int) -> dict:
    """One incident with its notes, member alerts, and timeline."""
    try:
        return engine.incidents.detail(incident_id)
    except IncidentError as exc:
        raise auth_error(exc) from exc


@router.post("/api/incidents", response_model=Incident)
def incidents_create(
    req: IncidentCreate,
    principal: dict = Depends(require("incidents:manage")),
) -> dict:
    """Open an incident from a detection and/or hand-picked alerts."""
    try:
        incident = engine.incidents.create(
            req.title, req.detection_id, principal["username"],
            alert_ids=req.alert_ids, summary=req.summary)
    except IncidentError as exc:
        raise auth_error(exc) from exc
    incident["note_count"] = 0
    return incident


@router.post("/api/incidents/correlate", response_model=IncidentCorrelation)
def incidents_correlate(
    req: IncidentCorrelate | None = None,
    principal: dict = Depends(require("incidents:manage")),
) -> dict:
    """Conservatively cluster unassigned alerts into incidents.

    Each cluster of two or more related alerts becomes one incident; single
    alerts stay unassigned (``ungrouped``) - unrelated activity is never
    merged.  Without ``alert_ids`` all unassigned alerts are considered.
    """
    try:
        return engine.incidents.correlate(
            principal["username"],
            alert_ids=(req.alert_ids if req else None))
    except IncidentError as exc:
        raise auth_error(exc) from exc


@router.post("/api/incidents/{incident_id}/investigate", response_model=Incident)
def incidents_investigate(
    incident_id: int,
    principal: dict = Depends(require("incidents:manage")),
) -> dict:
    """OPEN/ACKNOWLEDGED -> INVESTIGATING."""
    try:
        return engine.incidents.investigate(incident_id,
                                            principal["username"])
    except IncidentError as exc:
        raise auth_error(exc) from exc


@router.post("/api/incidents/{incident_id}/reopen", response_model=Incident)
def incidents_reopen(
    incident_id: int,
    principal: dict = Depends(require("incidents:manage")),
) -> dict:
    """RESOLVED/FALSE_POSITIVE -> INVESTIGATING (the incident grows again)."""
    try:
        return engine.incidents.reopen(incident_id, principal["username"])
    except IncidentError as exc:
        raise auth_error(exc) from exc


@router.post("/api/incidents/{incident_id}/false-positive", response_model=Incident)
def incidents_false_positive(
    incident_id: int,
    principal: dict = Depends(require("incidents:manage")),
) -> dict:
    """Record the assessed-benign decision (stays auditable)."""
    try:
        return engine.incidents.mark_false_positive(
            incident_id, principal["username"])
    except IncidentError as exc:
        raise auth_error(exc) from exc


@router.post("/api/incidents/{incident_id}/alerts", response_model=IncidentDetail)
def incidents_attach(
    incident_id: int,
    req: IncidentAttach,
    principal: dict = Depends(require("incidents:manage")),
) -> dict:
    """Attach hand-picked alerts to an active incident; returns the detail."""
    try:
        return engine.incidents.attach(
            incident_id, req.alert_ids, principal["username"])
    except IncidentError as exc:
        raise auth_error(exc) from exc


@router.post("/api/incidents/{incident_id}/acknowledge", response_model=Incident)
def incidents_acknowledge(
    incident_id: int,
    principal: dict = Depends(require("incidents:manage")),
) -> dict:
    """OPEN -> ACKNOWLEDGED."""
    try:
        incident = engine.incidents.acknowledge(incident_id,
                                                principal["username"])
    except IncidentError as exc:
        raise auth_error(exc) from exc
    return incident


@router.post("/api/incidents/{incident_id}/resolve", response_model=Incident)
def incidents_resolve(
    incident_id: int,
    principal: dict = Depends(require("incidents:manage")),
) -> dict:
    """OPEN/ACKNOWLEDGED/INVESTIGATING -> RESOLVED (terminal)."""
    try:
        incident = engine.incidents.resolve(incident_id,
                                            principal["username"])
    except IncidentError as exc:
        raise auth_error(exc) from exc
    return incident


@router.post("/api/incidents/{incident_id}/notes", response_model=IncidentNote)
def incidents_add_note(
    incident_id: int,
    req: IncidentNoteCreate,
    principal: dict = Depends(require("incidents:manage")),
) -> dict:
    """Attach an analyst note (author-attributed) to an incident."""
    try:
        note = engine.incidents.add_note(incident_id, req.body,
                                         principal["username"])
    except IncidentError as exc:
        raise auth_error(exc) from exc
    return note
