"""Module 8: 5G/6G & Edge-Native Architecture.

Public surface:
    classify_slice    - flow -> URLLC / eMBB / mMTC / default slice
    apply_slice_policy- differentiated response ladder per slice
    SLICES            - slice registry with policies
    MicroDetector     - lightweight MEC micro-detector (sub-10ms budget)
    EdgeSystem        - link profiles, deployments, micro-detector state
    LINK_PROFILES     - terrestrial / UAV / LEO / GEO RTT profiles
"""

from .mec import (
    LINK_PROFILES,
    LATENCY_BUDGET_MS,
    MICRO_FEATURES,
    EdgeError,
    EdgeSystem,
    MicroDetector,
)
from .slices import SLICES, apply_slice_policy, classify_slice

__all__ = [
    "EdgeError",
    "EdgeSystem",
    "LINK_PROFILES",
    "LATENCY_BUDGET_MS",
    "MICRO_FEATURES",
    "MicroDetector",
    "SLICES",
    "apply_slice_policy",
    "classify_slice",
]
