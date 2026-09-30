"""API routers: thin HTTP layer over the application services.

Each router only validates input, maps service results to responses and
translates service exceptions to HTTP errors - no detection or business
logic lives here.

The one shared helper, :func:`capture_pcap_path`, is where a managed capture
id becomes a local file for the offline analysis tools (training, PQC scan,
shadow mode): the service re-validates the stored name and existence inside
the capture store, and this function maps its failures to HTTP - routers
never accept or construct a path themselves.
"""

from __future__ import annotations

from fastapi import HTTPException

from ...capture import CaptureFileError
from ...services.captures import CaptureConflict, CaptureNotFound
from ..runtime import engine


def capture_pcap_path(capture_id: int) -> str:
    """Resolve a managed capture id to its stored PCAP path (HTTP errors)."""
    try:
        return engine.capture_resources.path_for(capture_id)
    except CaptureNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CaptureConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except CaptureFileError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
