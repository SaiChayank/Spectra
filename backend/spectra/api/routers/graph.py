"""Cross-domain correlation routes (Module 7) over the correlation service."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from ..runtime import engine
from ..security import require

router = APIRouter(dependencies=[Depends(require("investigate"))])


@router.get("/api/graph")
def graph_view(ntype: str | None = None, sector: str | None = None,
               limit: int = Query(500, ge=1, le=2000)) -> dict:
    """Full graph (nodes + edges) for the dashboard visualisation."""
    return engine.correlation.snapshot(ntype=ntype, sector=sector, limit=limit)


@router.get("/api/graph/summary")
def graph_summary() -> dict:
    return engine.correlation.summary()


@router.get("/api/graph/node")
def graph_node(id: str) -> dict:
    result = engine.correlation.neighbors(id)
    if result["node"] is None:
        raise HTTPException(status_code=404, detail=f"unknown node: {id}")
    return result


@router.get("/api/graph/cascade")
def graph_cascade(id: str, depth: int = Query(4, ge=1, le=8)) -> dict:
    """Blast-radius / kill-chain score starting from a node."""
    result = engine.correlation.cascade(id, max_depth=depth)
    if not result["found"]:
        raise HTTPException(status_code=404, detail=f"unknown node: {id}")
    return result


@router.get("/api/graph/path")
def graph_path(src: str, dst: str) -> dict:
    path = engine.correlation.shortest_path(src, dst)
    if path is None:
        raise HTTPException(status_code=404, detail="no path between nodes")
    return {"src": src, "dst": dst, "hops": len(path) - 1, "path": path}
