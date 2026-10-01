"""Model routes: info, training, drift/evasion/robustness analysis + the
model registry (Prompt 14: candidates, validation gate, activate/rollback).

PCAP-consuming routes reference managed captures (``capture_id``), never a
server filesystem path - see :func:`spectra.api.routers.capture_pcap_path`.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ...capture import CaptureError
from ...services.model_registry import RegistryError
from ..runtime import engine
from ..security import require
from . import capture_pcap_path

#: Info + registry reads are any signed-in role; drift/evasion/robustness are
#: investigation probes (ANALYST+); training and every registry transition
#: (validate/activate/retire/rollback) are ADMIN (``model:manage``).
router = APIRouter(dependencies=[Depends(require("read"))])


class TrainRequest(BaseModel):
    capture_id: int = Field(ge=1)
    contamination: float = Field(default=0.02, gt=0.0, lt=1.0)
    #: Register+validate+activate (default: training's product contract is
    #: an immediately usable model).  ``false`` registers a CANDIDATE only -
    #: the session detector stays untouched until an explicit activation.
    activate: bool = True


class RobustnessRequest(BaseModel):
    capture_id: int | None = Field(None, ge=1)
    max_features: int = Field(12, ge=1, le=64)
    max_rounds: int = Field(6, ge=1, le=20)


@router.get("/api/model")
def model_info() -> dict:
    return engine.model.info()


@router.post("/api/model/train",
             dependencies=[Depends(require("model:manage"))])
def model_train(req: TrainRequest,
                principal: dict = Depends(require("model:manage"))) -> dict:
    """Train the detector on a stored capture's benign baseline.

    Registers a registry CANDIDATE; with ``activate`` (default true) the
    audited validate -> activate chain follows.  Response carries
    ``registry: {model_id, status, activated}`` when persistence is on.
    """
    path = capture_pcap_path(req.capture_id)
    try:
        return engine.training.train_from_pcap(
            path, contamination=req.contamination, activate=req.activate,
            actor=principal["username"])
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


# -- model registry (Prompt 14) -------------------------------------------------
# Reads ride the router's ``read``; every transition is ``model:manage``.
# ``/compare`` and ``/rollback`` are declared before ``/{model_id}`` so
# FastAPI never parses them as ids.


def _registry_error(exc: RegistryError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=str(exc))


@router.get("/api/model/registry")
def model_registry_list() -> dict:
    """Registry rows (newest first) + the ACTIVE model.

    ``enabled: false`` with no items means persistence is off - the
    lifecycle is a persistence feature, not an error.
    """
    return engine.registry.list()


@router.get("/api/model/registry/compare")
def model_registry_compare(a: str, b: str) -> dict:
    """Field-by-field diff of two registry models (lineage evidence)."""
    try:
        return engine.registry.compare(a, b)
    except RegistryError as exc:
        raise _registry_error(exc) from exc


@router.get("/api/model/registry/{model_id}")
def model_registry_get(model_id: str) -> dict:
    try:
        return engine.registry.get(model_id)
    except RegistryError as exc:
        raise _registry_error(exc) from exc


@router.post("/api/model/registry/{model_id}/validate",
             dependencies=[Depends(require("model:manage"))])
def model_registry_validate(model_id: str,
                            principal: dict = Depends(
                                require("model:manage"))) -> dict:
    """CANDIDATE -> VALIDATED (or FAILED with the failing checks recorded)."""
    try:
        return engine.registry.validate(model_id,
                                        actor=principal["username"])
    except RegistryError as exc:
        raise _registry_error(exc) from exc


@router.post("/api/model/registry/{model_id}/activate",
             dependencies=[Depends(require("model:manage"))])
def model_registry_activate(model_id: str,
                            principal: dict = Depends(
                                require("model:manage"))) -> dict:
    """VALIDATED/RETIRED -> ACTIVE: swaps the session model (audited)."""
    try:
        return engine.registry.activate(model_id, actor=principal["username"])
    except RegistryError as exc:
        raise _registry_error(exc) from exc


@router.post("/api/model/registry/{model_id}/retire",
             dependencies=[Depends(require("model:manage"))])
def model_registry_retire(model_id: str,
                          principal: dict = Depends(
                              require("model:manage"))) -> dict:
    """CANDIDATE/VALIDATED -> RETIRED (the ACTIVE model cannot retire)."""
    try:
        return engine.registry.retire(model_id, actor=principal["username"])
    except RegistryError as exc:
        raise _registry_error(exc) from exc


@router.post("/api/model/registry/rollback",
             dependencies=[Depends(require("model:manage"))])
def model_registry_rollback(
        principal: dict = Depends(require("model:manage"))) -> dict:
    """Re-activate the most recently superseded model (audited rollback)."""
    try:
        return engine.registry.rollback(actor=principal["username"])
    except RegistryError as exc:
        raise _registry_error(exc) from exc
