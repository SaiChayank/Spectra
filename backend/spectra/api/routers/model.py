"""Model routes: info, training, drift/evasion/robustness analysis.

PCAP-consuming routes reference managed captures (``capture_id``), never a
server filesystem path - see :func:`spectra.api.routers.capture_pcap_path`.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ...capture import CaptureError
from ..runtime import engine
from ..security import require
from . import capture_pcap_path

#: Info is any signed-in role; drift/evasion/robustness are investigation
#: probes (ANALYST+); training is ADMIN (``model:manage`` - activate/rollback
#: will ride the same permission when a model registry lands).
router = APIRouter(dependencies=[Depends(require("read"))])


class TrainRequest(BaseModel):
    capture_id: int = Field(ge=1)
    contamination: float = Field(default=0.02, gt=0.0, lt=1.0)


class RobustnessRequest(BaseModel):
    capture_id: int | None = Field(None, ge=1)
    max_features: int = Field(12, ge=1, le=64)
    max_rounds: int = Field(6, ge=1, le=20)


@router.get("/api/model")
def model_info() -> dict:
    return engine.model.info()


@router.post("/api/model/train",
             dependencies=[Depends(require("model:manage"))])
def model_train(req: TrainRequest) -> dict:
    """Train the detector on a stored capture's benign baseline."""
    path = capture_pcap_path(req.capture_id)
    try:
        return engine.training.train_from_pcap(path,
                                               contamination=req.contamination)
    except CaptureError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/model/drift",
           dependencies=[Depends(require("investigate"))])
def model_drift() -> dict:
    """PSI of recent traffic against the training baseline (Module 3)."""
    return engine.model.drift_report()


@router.get("/api/model/evasion",
           dependencies=[Depends(require("investigate"))])
def model_evasion() -> dict:
    """Near-threshold score clustering analysis (Module 3)."""
    return engine.alerts.evasion_report()


@router.post("/api/model/robustness",
             dependencies=[Depends(require("investigate"))])
def model_robustness(req: RobustnessRequest) -> dict:
    """White-box evasion attack against the detector; measures robustness.

    ``capture_id`` is optional: without it the attack runs on the recent
    scored window instead of an offline capture.
    """
    path = (capture_pcap_path(req.capture_id)
            if req.capture_id is not None else None)
    try:
        return engine.model.robustness(pcap=path,
                                       max_features=req.max_features,
                                       max_rounds=req.max_rounds)
    except Exception as exc:  # noqa: BLE001 - surface attack failures
        raise HTTPException(status_code=500,
                            detail=f"robustness evaluation failed: {exc}") from exc
