"""PQC readiness routes (Module 1).

The offline scan reads a managed capture (``capture_id``), never a path
supplied by the client - see :func:`spectra.api.routers.capture_pcap_path`.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from ..runtime import engine
from ..security import require
from . import capture_pcap_path

log = logging.getLogger("spectra.api")

router = APIRouter(dependencies=[Depends(require("read"))])


@router.get("/api/pqc")
def pqc_report(sector: str | None = None, roadmap: bool = True) -> dict:
    """Quantum posture of everything seen by the running engine."""
    return engine.detection.pqc_snapshot(include_roadmap=roadmap, sector=sector)


@router.get("/api/pqc/inventory")
def pqc_inventory(sector: str | None = None,
                  limit: int = Query(200, ge=1, le=1000)) -> dict:
    snap = engine.detection.pqc_snapshot(include_roadmap=False, sector=sector)
    return {"summary": snap["summary"],
            "endpoints": snap["endpoints"][:limit]}


@router.get("/api/pqc/scan",
            dependencies=[Depends(require("investigate"))])
def pqc_scan(capture_id: int = Query(ge=1), sector: str | None = None) -> dict:
    """Run an offline PQC readiness scan over a managed capture.

    Reads a capture file and reports findings, so it is an investigation
    probe (ANALYST+) rather than a read; failures answer a generic 500 -
    the underlying exception (which may carry server paths) is logged.
    """
    from ...modules.pqc.scan import scan_pcap

    path = capture_pcap_path(capture_id)
    try:
        return scan_pcap(path, sector=sector)
    except Exception as exc:  # noqa: BLE001 - surface scan failures to the client
        log.exception("pqc scan failed for capture %s", capture_id)
        raise HTTPException(status_code=500, detail="scan failed") from exc
