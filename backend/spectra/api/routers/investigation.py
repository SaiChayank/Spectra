"""Investigation routes: one bundle per incident + global entity search.

Both reads require ``investigate`` (the same gate as incidents and the
correlation graph): the bundle assembles incident, alerts, related flows,
graph/twin context and audit references into a single bounded response, and
``/api/search`` resolves any identifier an analyst pastes in - IP, domain,
SNI, incident id, alert id, capture id, model id, JA3/JA4 fingerprint - via
the pure classifier in :mod:`spectra.entity_search`.  The router only
validates input and translates domain errors to HTTP.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ...services.investigation import InvestigationError
from ..runtime import engine
from ..security import auth_error, require

router = APIRouter(dependencies=[Depends(require("investigate"))])


@router.get("/api/investigations/{incident_id}")
def investigation_bundle(
    incident_id: int,
    flow_limit: int | None = Query(None, ge=1, le=500),
    flow_offset: int = Query(0, ge=0),
) -> dict:
    """Everything known about one incident (all sections bounded).

    ``flow_limit``/``flow_offset`` page the related-flow list; aggregates
    (hosts, domains, TLS, annotations) are computed over the configured
    evidence window, reported with ``window.evidence_rows``/``evidence_total``.
    """
    try:
        return engine.investigation.bundle(
            incident_id, flow_limit=flow_limit, flow_offset=flow_offset)
    except InvestigationError as exc:
        raise auth_error(exc) from exc


@router.get("/api/search")
def investigation_search(
    q: str = Query(..., min_length=1, max_length=255),
    limit: int | None = Query(None, ge=1, le=50),
) -> dict:
    """Global search: classify the query, then bounded hits per entity."""
    try:
        return engine.investigation.search(q, limit=limit)
    except InvestigationError as exc:
        raise auth_error(exc) from exc
