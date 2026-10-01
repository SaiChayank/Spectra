"""Alert routes: the analyst alert feed and its lifecycle.

Reads require ``read`` (alert content already reaches every signed-in
dashboard over the event WebSocket, so hiding the REST list would only
disagree with the stream).  Acknowledge/resolve require ``incidents:manage``
— the same triage vocabulary as incidents — and are attributed to the caller
in the hash-chained audit log.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ...services.threat_alerts import ThreatAlertError
from ..runtime import engine
from ..security import auth_error, require

router = APIRouter(dependencies=[Depends(require("read"))])


@router.get("/api/alerts")
def alerts_list(
    status: str | None = Query(None, pattern="^(OPEN|ACKNOWLEDGED|RESOLVED)$"),
    threat_type: str | None = Query(None, max_length=64),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict:
    """Alert page (most recent sighting first), with evidence + severity."""
    try:
        return engine.threat_alerts.list(status=status,
                                         threat_type=threat_type,
                                         limit=limit, offset=offset)
    except ThreatAlertError as exc:
        raise auth_error(exc) from exc


@router.get("/api/alerts/{alert_id}")
def alerts_get(alert_id: str) -> dict:
    """One alert: the four concepts side by side plus evidence + derivation."""
    try:
        return engine.threat_alerts.get(alert_id)
    except ThreatAlertError as exc:
        raise auth_error(exc) from exc


@router.post("/api/alerts/{alert_id}/acknowledge")
def alerts_acknowledge(
    alert_id: str,
    principal: dict = Depends(require("incidents:manage")),
) -> dict:
    """OPEN -> ACKNOWLEDGED."""
    try:
        alert = engine.threat_alerts.acknowledge(alert_id)
    except ThreatAlertError as exc:
        raise auth_error(exc) from exc
    engine.audit_service.append(
        "alert.acknowledge", {"alert_id": alert_id,
                              "severity": alert.get("severity")},
        actor=principal["username"])
    return alert


@router.post("/api/alerts/{alert_id}/resolve")
def alerts_resolve(
    alert_id: str,
    principal: dict = Depends(require("incidents:manage")),
) -> dict:
    """OPEN/ACKNOWLEDGED -> RESOLVED (terminal)."""
    try:
        alert = engine.threat_alerts.resolve(alert_id)
    except ThreatAlertError as exc:
        raise auth_error(exc) from exc
    engine.audit_service.append(
        "alert.resolve", {"alert_id": alert_id,
                          "severity": alert.get("severity")},
        actor=principal["username"])
    return alert
