"""5G/6G edge routes (Module 8) over the detection service."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ...capabilities import SIMULATED
from ..runtime import engine
from ..security import require

#: Report is any signed-in role; the slice preview is an investigation probe
#: (ANALYST+); link/deploy mutate runtime configuration (ADMIN).
router = APIRouter(dependencies=[Depends(require("read"))])


class EdgeLinkRequest(BaseModel):
    link: str = Field(min_length=1)


class EdgeDeployRequest(BaseModel):
    node: str = Field(min_length=1)
    slice: str = Field("default", pattern="^(urllc|embb|mmtc|default)$")


class EdgeSliceRequest(BaseModel):
    record: dict
    level: int = Field(2, ge=0, le=3)


@router.get("/api/edge/report")
def edge_report() -> dict:
    """Slices, micro-detector state, NTN link profiles, deployments."""
    return engine.detection.edge_report()


@router.post("/api/edge/link",
             dependencies=[Depends(require("config:manage"))])
def edge_link(req: EdgeLinkRequest) -> dict:
    """Switch the non-terrestrial backhaul profile (NTN support)."""
    from ...modules.edge import EdgeError

    try:
        return engine.detection.edge_set_link(req.link)
    except EdgeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/edge/deploy",
             dependencies=[Depends(require("config:manage"))])
def edge_deploy(req: EdgeDeployRequest) -> dict:
    """Register a micro-detector deployment on a MEC node.

    The registry is an in-process simulation - the response marks itself
    ``capability: SIMULATED`` so consumers never mistake it for a real
    MEC/5G control-plane integration.
    """
    from ...modules.edge import EdgeError

    try:
        result = engine.detection.edge_deploy(req.node, req.slice)
    except EdgeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result["capability"] = SIMULATED
    return result


@router.post("/api/edge/slice",
             dependencies=[Depends(require("investigate"))])
def edge_slice(req: EdgeSliceRequest) -> dict:
    """Classify a flow record onto a slice and preview its policy."""
    from ...modules.edge import SLICES, apply_slice_policy, classify_slice

    slice_id = classify_slice(req.record)
    adjusted, note = apply_slice_policy(req.level, slice_id)
    return {
        "slice": slice_id,
        "policy": SLICES[slice_id],
        "level": req.level,
        "adjusted_level": adjusted,
        "note": note,
    }
