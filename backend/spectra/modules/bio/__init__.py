"""Module 6: Biological-Inspired & Neuromorphic Detection.

Public surface:
    BioSystem         - orchestrates the three mechanisms per flow
    SelfModel         - benign "self" (median/MAD) for affinity scoring
    TimingSNN         - spiking temporal-coding timing anomaly detector
    Swarm             - pheromone-weighted decentralized agent committee
    assess_immunity   - danger-theory response level for one flow
    RESPONSES         - escalating ladder (ignore/monitor/alert/isolate)
"""

from .danger import (
    AFFINITY_LEVELS,
    DANGER_LEVELS,
    MemoryCells,
    RESPONSES,
    SelfModel,
    assess_immunity,
    band_level,
    danger_signals,
    danger_total,
)
from .snn import TimingSNN
from .swarm import Swarm
from .system import BioSystem

__all__ = [
    "AFFINITY_LEVELS",
    "BioSystem",
    "DANGER_LEVELS",
    "MemoryCells",
    "RESPONSES",
    "SelfModel",
    "Swarm",
    "TimingSNN",
    "assess_immunity",
    "band_level",
    "danger_signals",
    "danger_total",
]
