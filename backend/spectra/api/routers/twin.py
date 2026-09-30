"""Digital-twin routes (Module 4) over the engine twin facade."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..runtime import engine
from ..security import require
from . import capture_pcap_path

router = APIRouter(dependencies=[Depends(require("investigate"))])


class SimulateRequest(BaseModel):
    initial: list[str] | None = None
    seed: int = 7
    rounds: int = Field(12, ge=1, le=256)
    capability: float = Field(0.6, ge=0.0, le=1.0)
    monitoring: float | None = Field(None, ge=0.0, le=1.0)
    controls: dict = Field(default_factory=dict)
    actions: list[dict] = Field(default_factory=list)


class PlaybookRequest(SimulateRequest):
    name: str | None = None
    playbook: dict | None = None


class ShadowRequest(BaseModel):
    capture_id: int | None = Field(None, ge=1)
    contamination: float = Field(0.05, gt=0.0, lt=1.0)
    threshold: float = Field(3.5, gt=0.0)
    retrain: bool = True


def _sim_kwargs(req: SimulateRequest) -> dict:
    return {
        "initial": req.initial,
        "seed": req.seed,
        "rounds": req.rounds,
        "capability": req.capability,
        "monitoring": req.monitoring,
        "controls": req.controls,
    }


@router.get("/api/twin/topology")
def twin_topology(min_flows: int = Query(1, ge=0, le=10_000)) -> dict:
    """Twin replica: assets, zones, propagation edges, criticality."""
    return engine.twin_topology(min_flows=min_flows)


@router.get("/api/twin/playbooks")
def twin_playbooks() -> dict:
    return engine.twin_playbooks()


@router.post("/api/twin/simulate")
def twin_simulate(req: SimulateRequest) -> dict:
    """Deterministic attack-propagation run (seedable, paired draws)."""
    from ...modules.twin import SimulationError

    try:
        return engine.twin_simulate(actions=req.actions, **_sim_kwargs(req))
    except SimulationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/twin/playbook")
def twin_playbook(req: PlaybookRequest) -> dict:
    """Rehearse a playbook: before/after metrics + pass/fail verdict."""
    from ...modules.twin import SimulationError

    try:
        return engine.twin_validate(name=req.name, playbook=req.playbook,
                                    **_sim_kwargs(req))
    except (SimulationError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/twin/evaluate")
def twin_evaluate(req: SimulateRequest) -> dict:
    """Rehearse every library playbook against one scenario, ranked."""
    from ...modules.twin import SimulationError

    try:
        return engine.twin_evaluate(**_sim_kwargs(req))
    except SimulationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/twin/recommend")
def twin_recommend(req: SimulateRequest) -> dict:
    """Auto-generate a containment playbook from current detections + rehearse."""
    from ...modules.twin import SimulationError

    try:
        return engine.twin_recommend(**_sim_kwargs(req))
    except SimulationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/twin/shadow")
def twin_shadow(req: ShadowRequest) -> dict:
    """Shadow-mode comparison: production vs legacy z-score rule (+ candidate).

    ``capture_id`` references a stored capture (no filesystem paths here);
    without it the window comes from recent scored flows.
    """
    path = (capture_pcap_path(req.capture_id)
            if req.capture_id is not None else None)
    try:
        return engine.model.shadow(pcap=path, contamination=req.contamination,
                                   threshold=req.threshold, retrain=req.retrain)
    except Exception as exc:  # noqa: BLE001 - surface shadow failures
        raise HTTPException(status_code=500,
                            detail=f"shadow run failed: {exc}") from exc
