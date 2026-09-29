"""Module 3: Adversarial Resilience.

Public surface:
    attack / attack_batch - greedy feature-space evasion attacks + robustness
    watch / ScoreWindow   - threshold-hugging meta-anomaly detection
"""

from .evasion import attack, attack_batch
from .watch import ScoreWindow, score_boundary, watch

__all__ = [
    "attack",
    "attack_batch",
    "watch",
    "ScoreWindow",
    "score_boundary",
]
