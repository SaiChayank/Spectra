"""Incident routes: triage + analyst notes (ANALYST workflow).

Reads require ``investigate``; state changes and notes require
``incidents:manage``. Every transition is attributed to the caller and
written to the hash-chained audit log.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from ...services.incidents import IncidentError
from ..runtime import engine
from ..security import auth_error, require

router = APIRouter(dependencies=[Depends(require("investigate"))])


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    detection_id: int | None = Field(None, ge=1)


class IncidentNoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=2000)


@router.get("/api/incidents")
def incidents_list(
    status: str | None = Query(None, pattern="^(OPEN|ACKNOWLEDGED|RESOLVED)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict:
    """Incident page (newest first) with per-incident note counts."""
    try:
        return engine.incidents.list(status=status, limit=limit, offset=offset)
    except IncidentError as exc:
        raise auth_error(exc) from exc


@router.get("/api/incidents/{incident_id}")
def incidents_get(incident_id: int) -> dict:
    """One incident with its analyst notes."""
    try:
        return engine.incidents.detail(incident_id)
    except IncidentError as exc:
        raise auth_error(exc) from exc


@router.post("/api/incidents")
def incidents_create(
    req: IncidentCreate,
    principal: dict = Depends(require("incidents:manage")),
) -> dict:
    """Open an incident, optionally anchored to a flagged detection."""
    try:
        incident = engine.incidents.create(req.title, req.detection_id,
                                           principal["username"])
    except IncidentError as exc:
        raise auth_error(exc) from exc
    incident["note_count"] = 0
    engine.audit_service.append(
        "incident.create",
        {"id": incident["id"], "title": incident["title"],
         "detection_id": incident["detection_id"]},
        actor=principal["username"])
    return incident


@router.post("/api/incidents/{incident_id}/acknowledge")
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
    engine.audit_service.append(
        "incident.acknowledge", {"id": incident_id},
        actor=principal["username"])
    return incident


@router.post("/api/incidents/{incident_id}/resolve")
def incidents_resolve(
    incident_id: int,
    principal: dict = Depends(require("incidents:manage")),
) -> dict:
    """OPEN/ACKNOWLEDGED -> RESOLVED (terminal)."""
    try:
        incident = engine.incidents.resolve(incident_id,
                                            principal["username"])
    except IncidentError as exc:
        raise auth_error(exc) from exc
    engine.audit_service.append(
        "incident.resolve", {"id": incident_id},
        actor=principal["username"])
    return incident


@router.post("/api/incidents/{incident_id}/notes")
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
    engine.audit_service.append(
        "incident.note",
        {"incident_id": incident_id, "note_id": note["id"]},
        actor=principal["username"])
    return note
