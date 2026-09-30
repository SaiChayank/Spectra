"""Core routes: health, status, snapshots, live buffers, capture, system info."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from ...capabilities import module_capabilities
from ...capture import CaptureError
from ..runtime import engine
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
    bpf_filter: str = ""


@router.get("/api/health")
def health() -> dict:
    return engine.system.health()


@router.get("/api/status",
           dependencies=[Depends(require("read"))])
def status() -> dict:
    return engine.system.status


@router.get("/api/stats",
           dependencies=[Depends(require("read"))])
def stats() -> dict:
    return engine.system.snapshot()


@router.get("/api/flows",
           dependencies=[Depends(require("read"))])
def flows(limit: int = 100) -> dict:
    return engine.detection.recent_flows(limit)


@router.get("/api/detections",
           dependencies=[Depends(require("read"))])
def detections(limit: int = 100) -> dict:
    return engine.detection.recent_detections(limit)


@router.post("/api/capture/start",
             dependencies=[Depends(require("capture:manage"))])
def capture_start(req: CaptureRequest) -> dict:
    """Start a live NIC capture (PCAP processing: /api/captures/{id}/process)."""
    try:
        return engine.capture.start(req.mode, iface=req.iface,
                                    bpf_filter=req.bpf_filter)
    except CaptureError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/capture/stop",
             dependencies=[Depends(require("capture:manage"))])
def capture_stop() -> dict:
    return engine.capture.stop()


@router.get("/api/interfaces",
           dependencies=[Depends(require("read"))])
def interfaces() -> dict:
    """List capture interfaces (delegates to the system service)."""
    return engine.system.interfaces()


@router.get("/api/capabilities",
           dependencies=[Depends(require("read"))])
def capabilities() -> dict:
    """Capability maturity per advanced module (REAL / LOCAL / SIMULATED / ...)."""
    return module_capabilities()


@router.get("/api/metrics", response_class=PlainTextResponse,
           dependencies=[Depends(require("read"))])
def metrics() -> str:
    """Prometheus text exposition format (text/plain; version 0.0.4)."""
    return engine.system.metrics()
