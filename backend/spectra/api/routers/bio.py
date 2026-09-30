"""Bio-inspired detection routes (Module 6) over the detection service."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..runtime import engine
from ..security import require

router = APIRouter(dependencies=[Depends(require("read"))])


class BioAssessRequest(BaseModel):
    features: list[float] | None = None
    score: float | None = Field(None, ge=0, le=100)
    anomaly: bool = False


@router.get("/api/bio/status")
def bio_status() -> dict:
    """Immune self-model, SNN calibration, swarm pheromones, memory cells."""
    return engine.detection.bio_report()


@router.post("/api/bio/assess",
             dependencies=[Depends(require("investigate"))])
def bio_assess(req: BioAssessRequest) -> dict:
    """Danger-theory response for one flow (explicit vector or latest)."""
    from ...features.extractor import N_FEATURES

    if req.features is not None and len(req.features) != N_FEATURES:
        raise HTTPException(
            status_code=400,
            detail=f"expected {N_FEATURES} features, "
                   f"got {len(req.features)}")
    try:
        return engine.detection.bio_assess(req.features, score=req.score,
                                           anomaly=req.anomaly)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
