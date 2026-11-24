"""History routes (SQLite-backed): flows, detections, captures, stats, runs, events.

Every list is paginated (``limit``/``offset`` + total ``count``) and the
large tables accept the SOC filter set - time range, protocol, source,
destination, score range (flows), status (captures) - so no request can
pull an unbounded dataset.  Endpoints keep serving the ``items`` key the
dashboard already reads.
"""

from __future__ import annotations

import logging

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from ...store import StoreError, StoreUnavailable
from ..runtime import engine
from ..schemas import Num, Out
from .core import Flow
from ..security import require

log = logging.getLogger("spectra.api")

router = APIRouter(dependencies=[Depends(require("read"))])


class HistoryFlow(Flow):
    id: int
    ts: Num


class HistoryFlowList(Out):
    count: int
    offset: int
    items: list[HistoryFlow]


class HistoryCapture(Out):
    id: int
    mode: str
    status: str
    source: Optional[str] = None
    source_type: Optional[str] = None
    original_name: Optional[str] = None
    stored_name: Optional[str] = None
    content_hash: Optional[str] = None
    size_bytes: Optional[int] = None
    imported_at: Optional[Num] = None
    started_at: Optional[Num] = None
    stopped_at: Optional[Num] = None
    packets: Optional[int] = None
    flows: Optional[int] = None
    detections: Optional[int] = None
    error: Optional[str] = None


class HistoryCaptureList(Out):
    count: int
    offset: int
    items: list[HistoryCapture]


class HistoryStats(Out):
    flows: int
    detections: int
    anomaly_rate: Num
    avg_score: Optional[Num] = None
    first_ts: Optional[Num] = None
    last_ts: Optional[Num] = None
    by_proto: dict[str, int]
    top_sni: list[dict[str, Any]]


class ModelRun(Out):
    id: int
    trained_at: Num
    n_train: int
    contamination: Num
    metrics: Optional[str] = None
    pcap: Optional[str] = None


class ModelRunList(Out):
    count: int
    offset: int
    items: list[ModelRun]


class HistoryEvent(Out):
    id: int
    ts: Num
    type: str
    capture_id: Optional[int] = None
    data: dict[str, Any]


class HistoryEventList(Out):
    count: int
    offset: int
    items: list[HistoryEvent]


def _store_or_400():
    if engine.store is None:
        raise HTTPException(status_code=409, detail="persistence is disabled")
    return engine.store


@router.get("/api/history/flows", response_model=HistoryFlowList)
def history_flows(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    since: float | None = None,
    until: float | None = None,
    sni: str | None = None,
    proto: str | None = None,
    src: str | None = Query(None, description="host (any port) or ip:port"),
    dst: str | None = Query(None, description="host (any port) or ip:port"),
    min_score: float | None = Query(None, ge=0),
    max_score: float | None = Query(None, ge=0),
    capture_id: int | None = Query(None, ge=1),
) -> dict:
    """Persisted flow page (newest first) with endpoint/time/score filters."""
    try:
        return _store_or_400().query_flows(
            limit=limit, offset=offset, anomaly_only=False, since=since,
            until=until, sni=sni, proto=proto, src=src, dst=dst,
            min_score=min_score, max_score=max_score, capture_id=capture_id,
        )
    except StoreUnavailable:
        raise  # central handler: 503 + Retry-After
    except StoreError:
        # The underlying error can quote SQL/paths: log it, answer generic.
        log.exception("flow history query failed")
        raise HTTPException(status_code=500,
                            detail="storage error") from None


@router.get("/api/history/detections", response_model=HistoryFlowList)
def history_detections(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    since: float | None = None,
    until: float | None = None,
    proto: str | None = None,
    src: str | None = None,
    dst: str | None = None,
    min_score: float | None = Query(None, ge=0),
    max_score: float | None = Query(None, ge=0),
) -> dict:
    """Flagged flow page (the detections), same filter set as flows."""
    try:
        return _store_or_400().query_flows(
            limit=limit, offset=offset, anomaly_only=True, since=since,
            until=until, proto=proto, src=src, dst=dst,
            min_score=min_score, max_score=max_score,
        )
    except StoreUnavailable:
        raise  # central handler: 503 + Retry-After
    except StoreError:
        # The underlying error can quote SQL/paths: log it, answer generic.
        log.exception("detections history query failed")
        raise HTTPException(status_code=500,
                            detail="storage error") from None


@router.get("/api/history/captures", response_model=HistoryCaptureList)
def history_captures(
    limit: int = Query(20, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status: str | None = Query(
        None, pattern="^(UPLOADED|PROCESSING|COMPLETED|FAILED|STOPPED)$"),
) -> dict:
    """Capture sessions (newest first), paginated + lifecycle filter."""
    return _store_or_400().list_captures(limit=limit, offset=offset,
                                         status=status)


@router.get("/api/history/stats", response_model=HistoryStats)
def history_stats() -> dict:
    return _store_or_400().stats()


@router.get("/api/history/model-runs", response_model=ModelRunList)
def history_model_runs(
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict:
    """Training lineage page (newest first) with a total count."""
    store = _store_or_400()
    return {"count": store.model_run_count(), "offset": offset,
            "items": store.model_runs(limit, offset=offset)}


@router.get("/api/history/events", response_model=HistoryEventList)
def history_events(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    event_type: str | None = Query(None, alias="type"),
    since: float | None = None,
    until: float | None = None,
) -> dict:
    """System-event feed (status/alert/drift/model); flow and detection
    events are served by /api/history/flows and /api/history/detections."""
    try:
        return _store_or_400().query_events(
            limit=limit, offset=offset, type=event_type,
            since=since, until=until,
        )
    except StoreUnavailable:
        raise  # central handler: 503 + Retry-After
    except StoreError:
        # The underlying error can quote SQL/paths: log it, answer generic.
        log.exception("events history query failed")
        raise HTTPException(status_code=500,
                            detail="storage error") from None
