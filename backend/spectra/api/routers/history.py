"""History routes (SQLite-backed): flows, detections, captures, stats, runs, events."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from ...store import StoreError
from ..runtime import engine
from ..security import require

router = APIRouter(dependencies=[Depends(require("read"))])


def _store_or_400():
    if engine.store is None:
        raise HTTPException(status_code=409, detail="persistence is disabled")
    return engine.store


@router.get("/api/history/flows")
def history_flows(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    since: float | None = None,
    sni: str | None = None,
) -> dict:
    try:
        return _store_or_400().query_flows(
            limit=limit, offset=offset, anomaly_only=False, since=since, sni=sni
        )
    except StoreError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/api/history/detections")
def history_detections(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    since: float | None = None,
) -> dict:
    try:
        return _store_or_400().query_flows(
            limit=limit, offset=offset, anomaly_only=True, since=since
        )
    except StoreError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/api/history/captures")
def history_captures(limit: int = Query(20, ge=1, le=500)) -> dict:
    return {"items": _store_or_400().recent_captures(limit)}


@router.get("/api/history/stats")
def history_stats() -> dict:
    return _store_or_400().stats()


@router.get("/api/history/model-runs")
def history_model_runs(limit: int = Query(20, ge=1, le=200)) -> dict:
    return {"items": _store_or_400().model_runs(limit)}


@router.get("/api/history/events")
def history_events(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    event_type: str | None = Query(None, alias="type"),
) -> dict:
    """System-event feed (status/alert/drift/model); flow and detection
    events are served by /api/history/flows and /api/history/detections."""
    try:
        return _store_or_400().query_events(
            limit=limit, offset=offset, type=event_type
        )
    except StoreError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
