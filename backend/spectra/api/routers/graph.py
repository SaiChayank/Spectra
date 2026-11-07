"""Cross-domain correlation routes (Module 7) over the correlation service."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from ..runtime import engine
from ..security import require

router = APIRouter(dependencies=[Depends(require("investigate"))])


def _check_window(window_s: float | None) -> None:
    if window_s is not None and not window_s > 0:   # also rejects NaN
        raise HTTPException(status_code=400, detail="window_s must be > 0")


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
def graph_cascade(id: str, depth: int = Query(4, ge=1, le=8),
                  window_s: float | None = None) -> dict:
    """Blast-radius / kill-chain score starting from a node.

    ``window_s``: only edges last seen within that many seconds of the newest
    contact count (omit for all history).
    """
    _check_window(window_s)
    result = engine.correlation.cascade(id, max_depth=depth, window_s=window_s)
    if not result["found"]:
        raise HTTPException(status_code=404, detail=f"unknown node: {id}")
    return result


@router.get("/api/graph/path")
def graph_path(src: str, dst: str, window_s: float | None = None) -> dict:
    _check_window(window_s)
    path = engine.correlation.shortest_path(src, dst, window_s=window_s)
    if path is None:
        raise HTTPException(status_code=404, detail="no path between nodes")
    return {"src": src, "dst": dst, "hops": len(path) - 1, "path": path,
            "window_s": window_s}
