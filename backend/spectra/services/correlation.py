"""Cross-domain correlation service over the attack graph (Module 7)."""

from __future__ import annotations

import logging

from ..modules.corr import CorrelationGraph, cascade
from ..store import Store
from ..domain import FlowRecord
from .resilience import FailureTracker

log = logging.getLogger("spectra.engine")


class CorrelationService:
    """Owns the correlation graph: hydration, guarded observation, queries.

    Observation is guarded here (component ``correlation``) so the hot path
    never has to wrap graph updates itself.
    """

    def __init__(self, graph: CorrelationGraph, store: Store | None,
                 failures: FailureTracker) -> None:
        self.graph = graph
        self.store = store
        self.failures = failures

    def hydrate(self) -> int:
        """Rebuild the correlation graph from persisted flow history.

        Runs at API startup and again at the start of every capture so the
        cross-domain view keeps prior evidence instead of resetting empty.
        Returns the number of records replayed (0 when persistence is off).
        """
        if self.store is None:
            return 0
        try:
            return self.graph.hydrate(self.store)
        except Exception as exc:  # noqa: BLE001 - hydration must never block capture
            log.warning("graph hydration failed: %s", exc)
            return 0

    def reset_session(self) -> None:
        """Fresh live view per capture, re-seeded from persisted history."""
        self.graph.reset()
        self.hydrate()

    def observe(self, record: FlowRecord) -> None:
        """Feed one flow record into the graph; failures are counted, not raised."""
        try:
            self.graph.observe(record)
        except Exception as exc:  # noqa: BLE001 - correlation must never kill capture
            self.failures.record("correlation", exc)

    # -- queries -------------------------------------------------------------

    def snapshot(self, ntype: str | None = None, sector: str | None = None,
                 limit: int = 500) -> dict:
        return {
            "summary": self.graph.summary(),
            "nodes": self.graph.nodes_list(ntype=ntype, sector=sector, limit=limit),
            "edges": self.graph.edges_list(limit=min(limit * 4, 5000)),
        }

    def cascade(self, node_id: str, max_depth: int = 4) -> dict:
        return cascade(self.graph, node_id, max_depth=max_depth)

    def summary(self) -> dict:
        return self.graph.summary()

    def neighbors(self, node_id: str) -> dict:
        return self.graph.neighbors(node_id)

    def shortest_path(self, src: str, dst: str):
        return self.graph.shortest_path(src, dst)
