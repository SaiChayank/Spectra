"""Module 4: Digital Twin cyber simulation layer.

Public surface:
    build_topology        - replica of the observed network (zones, assets)
    simulate              - deterministic, seedable attack propagation
    validate_playbook     - before/after IR rehearsal with a verdict
    evaluate_library      - rank every playbook against one scenario
    playbook_from_detections - auto-generate containment actions from alerts
    run_shadow            - parallel-run comparison vs a legacy baseline
"""

from .playbook import (
    LIBRARY,
    evaluate_library,
    playbook_from_detections,
    validate_playbook,
)
from .shadow import ZScoreDetector, run_shadow
from .simulate import SimulationError, quick_summary, resolve_initial, simulate
from .topology import build_topology

__all__ = [
    "LIBRARY",
    "SimulationError",
    "ZScoreDetector",
    "build_topology",
    "evaluate_library",
    "playbook_from_detections",
    "quick_summary",
    "resolve_initial",
    "run_shadow",
    "simulate",
    "validate_playbook",
]
