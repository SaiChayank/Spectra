"""Core routes: health, status, snapshots, live buffers, capture, system info."""

from __future__ import annotations

from typing import Any, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from ...capabilities import module_capabilities
from ...capture import CaptureError
from ..runtime import engine
from ..schemas import Num, Out
from ..security import require

#: No router-level dependency: ``/api/health`` is public. Every other route
#: declares its permission explicitly (read = any signed-in role; live
#: capture control is ADMIN-only).
router = APIRouter()


class CaptureRequest(BaseModel):
    """Live capture only - file processing is ``POST /api/captures/{id}/process``.

    The mode pattern rejects ``pcap`` outright (422): a path-bearing or
    pathless pcap start no longer exists, so no client can make the server
    open an arbitrary filesystem path through this route.
    """
    mode: str = Field(pattern="^live$")
    iface: str | None = None
    bpf_filter: str = Field("", max_length=1024)


class Health(Out):
    """Public liveness probe (documented only: the route answers 200 or 503)."""
    ok: bool
    writable: dict[str, str]
    service: str
    version: str
    database: str
    schema_version: Optional[int] = None
    uptime_s: Num


class HealthSystem(Out):
    ts: Num
    uptime_s: Num
    state: str
    reason: str
    counts: dict[str, int]
    subsystems: list[dict[str, Any]]
    metrics: dict[str, Any]


class Status(Out):
    """Live engine status (also embedded in /api/stats and status events)."""
    running: bool
    mode: Optional[str] = None
    source: Optional[str] = None
    packets: int
    flows: int
    detections: int
    started_at: Optional[Num] = None
    error: Optional[str] = None
    model_trained: bool
    filter: Optional[str] = None
    persist: bool
    queue: dict[str, Any]
    failures: dict[str, Any]
    pipeline: dict[str, Any]
    websocket: dict[str, Any]


class Stats(Out):
    status: Status
    model: dict[str, Any]
    totals: dict[str, Any]
    protocols: dict[str, int]
    tls_versions: dict[str, int]
    timeline: list[dict[str, Any]]


class Flow(Out):
    """One scored flow (metadata only). Detections add alert/threat fields."""
    src: str
    dst: str
    proto: str
    score: Optional[Num] = None  # null while no model is trained
    anomaly: bool
    start_ts: Num
    last_ts: Num
    duration: Num
    packets: int
    bytes: int
    bytes_fwd: Optional[int] = None
    cipher_count: Optional[int] = None
    extension_count: Optional[int] = None
    slice: Optional[str] = None
    snn_score: Optional[Num] = None
    swarm_flag: Optional[bool] = None
    sni: Optional[str] = None
    ja3: Optional[str] = None
    ja4: Optional[str] = None
    tls_version: Optional[str] = None
    quic_version: Optional[str] = None
    alpn: Optional[Union[list[str], str]] = None
    alert_id: Optional[str] = None
    threat: Optional[dict[str, Any]] = None
    reasons: Optional[list[Any]] = None
    detected_at: Optional[Num] = None
    immune: Optional[dict[str, Any]] = None
    pqc: Optional[dict[str, Any]] = None


class FlowList(Out):
    count: int
    items: list[Flow]


class Interfaces(Out):
    interfaces: list[str]
    details: Optional[list[dict[str, Any]]] = None  # absent when probing failed
    error: Optional[str] = None


class Capabilities(Out):
    definitions: dict[str, str]
    statuses: list[str]
    scoring_policy: str
    hardware_backed_count: int
    modules: dict[str, dict[str, Any]]


@router.get("/api/health", response_model=Health)
def health() -> JSONResponse:
    """Liveness plus a cheap write probe: 503 when the data dir or database
    cannot be written (a merely busy database stays 200)."""
    body = engine.system.health()
    return JSONResponse(body, status_code=200 if body["ok"] else 503)


@router.get("/api/health/system", response_model=HealthSystem,
            dependencies=[Depends(require("read"))])
def system_health() -> dict:
    """System Health: per-subsystem state + reason + runtime metrics.

    The frontend's health panel reads this; ``/api/health`` stays the
    public liveness probe. States: HEALTHY / DEGRADED / UNAVAILABLE /
    SIMULATED (see spectra.health for the rules and thresholds).
    """
    return engine.system.health_report()


@router.get("/api/status", response_model=Status,
           dependencies=[Depends(require("read"))])
def status() -> dict:
    return engine.system.status


@router.get("/api/stats", response_model=Stats,
           dependencies=[Depends(require("read"))])
def stats() -> dict:
    return engine.system.snapshot()


@router.get("/api/flows", response_model=FlowList,
           dependencies=[Depends(require("read"))])
def flows(limit: int = Query(100, ge=1, le=1000)) -> dict:
    """Recent in-memory flows; ``limit`` is bounded so one request cannot
    serialize an unbounded buffer."""
    return engine.detection.recent_flows(limit)


@router.get("/api/detections", response_model=FlowList,
           dependencies=[Depends(require("read"))])
def detections(limit: int = Query(100, ge=1, le=1000)) -> dict:
    """Recent in-memory detections (bounded ``limit``, same as /api/flows)."""
    return engine.detection.recent_detections(limit)


@router.post("/api/capture/start", response_model=Status,
             dependencies=[Depends(require("capture:manage"))])
def capture_start(req: CaptureRequest) -> dict:
    """Start a live NIC capture (PCAP processing: /api/captures/{id}/process)."""
    try:
        return engine.capture.start(req.mode, iface=req.iface,
                                    bpf_filter=req.bpf_filter)
    except CaptureError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/capture/stop", response_model=Status,
             dependencies=[Depends(require("capture:manage"))])
def capture_stop() -> dict:
    return engine.capture.stop()


@router.get("/api/interfaces", response_model=Interfaces,
           dependencies=[Depends(require("read"))])
def interfaces() -> dict:
    """List capture interfaces (delegates to the system service)."""
    return engine.system.interfaces()


@router.get("/api/capabilities", response_model=Capabilities,
           dependencies=[Depends(require("read"))])
def capabilities() -> dict:
    """Maturity, contract and live availability per advanced module."""
    try:
        live = engine.capability_status()
    except Exception:  # noqa: BLE001 - transparency must never 500
        live = None
    return module_capabilities(live)


@router.get("/api/metrics", response_class=PlainTextResponse,
           dependencies=[Depends(require("read"))])
def metrics() -> Response:
    """Prometheus text exposition format 0.0.4.

    Needs a session with ``read``; a scraper that cannot hold a 12-hour session
    can instead present the optional ``SPECTRA_METRICS_TOKEN`` as a bearer token
    (this route only - see :func:`spectra.api.security.auth_gate`).
    """
    return Response(content=engine.system.metrics(),
                    media_type="text/plain; version=0.0.4")
