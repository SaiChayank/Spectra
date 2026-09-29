"""Module 6: swarm intelligence - decentralized detection agents.

Five heterogeneous agents vote per flow; a weighted quorum decides.  The
weights are pheromones: agents that agree with the consensus gain trail
strength, disagreeing agents lose it, so the swarm adapts to which signals
are actually reliable on this traffic.  No agent is authoritative - the
verdict survives any subset of agents going quiet (>= MIN_AGENTS votes),
which is the "no single point of failure" property from the spec.
"""

from __future__ import annotations

import numpy as np

from ...features.extractor import FEATURE_NAMES
from .danger import SelfModel

QUORUM = 0.5          # weighted share of concern needed for a swarm flag
MIN_AGENTS = 2        # below this the swarm has no quorum
BOOST = 1.06          # pheromone reinforcement for agents matching consensus
DECAY = 0.97          # pheromone decay for agents opposing consensus
W_MIN, W_MAX = 0.3, 3.0
ENTROPY_Z = 2.5       # size_entropy deviation that concerns the entropy agent
CADENCE_REGULARITY = 0.15
CADENCE_MIN_MEAN_S = 0.05

IDX_ENTROPY = FEATURE_NAMES.index("size_entropy")
IDX_IAT_MEAN = FEATURE_NAMES.index("iat_mean_s")
IDX_IAT_STD = FEATURE_NAMES.index("iat_std_s")


class Swarm:
    """Pheromone-weighted agent committee."""

    AGENTS = ("forest", "immune", "snn", "entropy", "cadence")

    def __init__(self) -> None:
        self.weights: dict[str, float] = {a: 1.0 for a in self.AGENTS}

    def votes(self, x, *, score=None, boundary: float = 98.0,
              immune_level: int | None = None, snn_score=None,
              snn_threshold: float = 98.0,
              self_model: SelfModel | None = None) -> dict[str, int]:
        """Raw per-agent votes; agents without their input abstain (absent)."""
        x = np.asarray(x, dtype=np.float64)
        votes: dict[str, int] = {}

        if score is not None:
            votes["forest"] = 1 if float(score) >= boundary else 0
        if immune_level is not None:
            votes["immune"] = 1 if int(immune_level) >= 2 else 0
        if snn_score is not None:
            votes["snn"] = 1 if float(snn_score) >= snn_threshold else 0

        if self_model is not None and self_model.trained:
            z = float(self_model.robust_z(x)[IDX_ENTROPY])
            votes["entropy"] = 1 if z >= ENTROPY_Z else 0

        mean_iat = float(x[IDX_IAT_MEAN])
        std_iat = float(x[IDX_IAT_STD])
        regular = (mean_iat >= CADENCE_MIN_MEAN_S and mean_iat > 0
                   and (std_iat / mean_iat) < CADENCE_REGULARITY)
        votes["cadence"] = 1 if regular else 0
        return votes

    def vote(self, x, *, reinforce: bool = True, **kwargs) -> dict:
        """Consensus verdict; pheromones update when ``reinforce`` is set."""
        votes = self.votes(x, **kwargs)
        abstained = [a for a in self.AGENTS if a not in votes]
        if len(votes) < MIN_AGENTS:
            return {
                "available": False,
                "flag": False,
                "reason": f"only {len(votes)} agent(s) have input; "
                          f"need >= {MIN_AGENTS}",
                "abstained": abstained,
                "weights": {k: round(v, 3) for k, v in self.weights.items()},
            }

        participants = list(votes)
        total_w = sum(self.weights[a] for a in participants)
        ratio = sum(self.weights[a] * votes[a] for a in participants) / total_w
        flag = ratio >= QUORUM

        if reinforce:
            for a in participants:
                w = self.weights[a] * (BOOST if votes[a] == int(flag) else DECAY)
                self.weights[a] = float(np.clip(w, W_MIN, W_MAX))

        margin = abs(ratio - QUORUM) * 2.0
        return {
            "available": True,
            "flag": bool(flag),
            "ratio": round(float(ratio), 4),
            "quorum": QUORUM,
            "margin": round(float(margin), 4),
            "n_agents": len(participants),
            "abstained": abstained,
            "votes": votes,
            "weights": {k: round(v, 3) for k, v in self.weights.items()},
        }

    def status(self) -> dict:
        return {
            "agents": list(self.AGENTS),
            "quorum": QUORUM,
            "min_agents": MIN_AGENTS,
            "weights": {k: round(v, 3) for k, v in self.weights.items()},
        }
