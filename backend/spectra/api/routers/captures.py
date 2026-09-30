"""Managed capture resources: import, list, details, process, delete.

No route here accepts a filesystem path. An import carries the file bytes
(multipart); every other route addresses a capture id this API generated,
and the service behind them is the only code that maps ids to stored files.
Live capture start/stop lives on ``/api/capture/start|stop`` (live mode only).
"""

from __future__ import annotations

from contextlib import contextmanager

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile

from ...capture import CaptureFileError, CaptureTooLargeError
from ...services.captures import (
    CAPTURE_STATUSES,
    CaptureConflict,
    CaptureDuplicate,
    CaptureNotFound,
)
from ...store import StoreError
from ..runtime import engine
from ..security import require

#: Reads are any signed-in role; mutating routes (import/process/delete) are
#: gated per-route with ``capture:manage`` (ADMIN).
router = APIRouter(dependencies=[Depends(require("read"))])

_STATUS_PATTERN = "^(" + "|".join(CAPTURE_STATUSES) + ")$"


@contextmanager
def _translate():
    """Map capture-resource failures to HTTP errors (order matters)."""
    try:
        yield
    except CaptureDuplicate as exc:
        raise HTTPException(status_code=409, detail={
            "error": "duplicate capture",
            "capture_id": exc.capture_id,
            "message": str(exc),
        }) from exc
    except CaptureNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CaptureConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except CaptureTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except CaptureFileError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except StoreError as exc:
        raise HTTPException(status_code=500,
                            detail=f"persistence failure: {exc}") from exc


@router.post("/api/captures",
             dependencies=[Depends(require("capture:manage"))])
def captures_import(file: UploadFile = File(...)) -> dict:
    """Import a PCAP/PCAPNG: validate -> store under a generated name -> row.

    Filename, extension, signature and size are validated before anything is
    persisted; the stored file name is generated, never the client's.
    Identical content already imported returns 409 with the existing id.
    """
    with _translate():
        chunks = iter(lambda: file.file.read(64 * 1024), b"")
        return engine.capture_resources.import_file(file.filename, chunks)


@router.get("/api/captures")
def captures_list(
    limit: int = Query(20, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status: str | None = Query(None, pattern=_STATUS_PATTERN),
) -> dict:
    """Page through capture resources (newest first), optionally by status."""
    with _translate():
        return engine.capture_resources.list_captures(
            limit=limit, offset=offset, status=status)


@router.get("/api/captures/{capture_id}")
def capture_details(capture_id: int) -> dict:
    """One capture's persisted metadata and lifecycle state."""
    with _translate():
        return engine.capture_resources.details(capture_id)


@router.post("/api/captures/{capture_id}/process",
             dependencies=[Depends(require("capture:manage"))])
def capture_process(capture_id: int) -> dict:
    """Process (or reprocess) a stored capture through detection.

    Non-blocking: returns the resource as PROCESSING; poll this route (or
    ``/api/status``) until the status is terminal.
    """
    with _translate():
        return engine.capture_resources.process(capture_id)


@router.delete("/api/captures/{capture_id}",
               dependencies=[Depends(require("capture:manage"))])
def capture_delete(capture_id: int) -> dict:
    """Delete a capture row and its stored file (refused while it runs).

    Flow history is kept: the flows foreign key is ``ON DELETE SET NULL``.
    """
    with _translate():
        return engine.capture_resources.delete(capture_id)
