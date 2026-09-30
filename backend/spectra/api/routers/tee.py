"""Confidential-computing / TEE routes (Module 2) over the model service."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..runtime import engine
from ..security import require

router = APIRouter(dependencies=[Depends(require("investigate"))])


class TeeAttestRequest(BaseModel):
    nonce: str | None = None


class TeeVerifyRequest(BaseModel):
    quote: dict
    measurement: str | None = None
    max_age: float = Field(600.0, gt=0)
    nonce: str | None = None


class TeeInferRequest(BaseModel):
    features: list[float]


class TeeFederateRequest(BaseModel):
    deltas: list[list[float]] | None = None
    shareholders: int = Field(3, ge=2, le=16)
    seed: int = 7


@router.post("/api/tee/attest")
def tee_attest(req: TeeAttestRequest) -> dict:
    """Nonce-bound signed quote of the model measurement."""
    from ...modules.tee import TeeError

    try:
        return engine.model.tee_attest(req.nonce)
    except TeeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/tee/verify")
def tee_verify(req: TeeVerifyRequest) -> dict:
    """Verify a quote: signature, provenance, freshness, measurement."""
    from ...modules.tee import TeeError

    try:
        return engine.model.tee_verify(req.quote, measurement=req.measurement,
                                       max_age=req.max_age, nonce=req.nonce)
    except TeeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/tee/infer")
def tee_infer(req: TeeInferRequest) -> dict:
    """Protected inference: features in, score + sealed receipt out."""
    from ...features.extractor import N_FEATURES
    from ...modules.tee import TeeError

    if len(req.features) != N_FEATURES:
        raise HTTPException(status_code=400,
                            detail=f"expected {N_FEATURES} features, "
                                   f"got {len(req.features)}")
    try:
        return engine.model.tee_infer(req.features)
    except TeeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/tee/federate")
def tee_federate(req: TeeFederateRequest) -> dict:
    """Additive secret-sharing round; returns a safe summary only.

    Per-party shares, per-shareholder aggregates and the round seed stay
    inside the process - the response carries round identity, threshold,
    verification status, aggregate digest and the summed aggregate.
    """
    from ...modules.tee import FederatedError, TeeError

    try:
        return engine.model.tee_federate(deltas=req.deltas,
                                         shareholders=req.shareholders,
                                         seed=req.seed)
    except (FederatedError, TeeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
