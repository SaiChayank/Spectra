"""Module 7: Cross-Domain Correlation.

Public surface:
    CorrelationGraph - builds a host/ip/domain/sector graph from flow records
    cascade          - blast-radius / kill-chain score for a starting node
"""

from .cascade import cascade
from .graph import (
    EDGE_IN_SECTOR,
    EDGE_SERVED_BY,
    EDGE_TALKS_TO,
    NODE_DOMAIN,
    NODE_HOST,
    NODE_IP,
    NODE_SECTOR,
    CorrelationGraph,
)

__all__ = [
    "CorrelationGraph",
    "cascade",
    "EDGE_IN_SECTOR",
    "EDGE_SERVED_BY",
    "EDGE_TALKS_TO",
    "NODE_DOMAIN",
    "NODE_HOST",
    "NODE_IP",
    "NODE_SECTOR",
]
