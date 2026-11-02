"""Module 6 orchestrator: immune danger + SNN timing + swarm consensus.

One entry point (``assess``) runs the three bio-inspired mechanisms over a
feature vector and returns a single escalating response plus the details
of every sub-module.  State that needs training (self model, SNN
calibration, pheromones, memory cells) persists next to the main model.
"""

from __future__ import annotations

import os
from collections import Counter

import joblib
import numpy as np

from ...features.extractor import N_FEATURES
from ...ml.integrity import digest_ok, write_digest
from ..adv.watch import score_boundary
from .danger import MemoryCells, RESPONSES, SelfModel, assess_immunity
from .snn import TimingSNN
from .swarm import Swarm

BIO_VERSION = 1


class BioSystem:
    def __init__(self, contamination: float = 0.02) -> None:
        self.contamination = float(contamination)
        self.self_model = SelfModel()
        self.snn = TimingSNN()
        self.swarm = Swarm()
        self.memory = MemoryCells()
        self.n_assessed = 0
        self.level_hist: Counter = Counter()

    # -- training -----------------------------------------------------------

    @property
    def available(self) -> bool:
        return self.self_model.trained

    def fit(self, X) -> dict:
        """Fit the self model and calibrate the SNN on benign traffic."""
        X = np.asarray(X, dtype=np.float64)
        if X.ndim != 2 or X.shape[0] < 10:
            raise ValueError(
                f"bio system needs >= 10 benign flows, got "
                f"{X.shape[0] if X.ndim == 2 else 0}")
        if X.shape[1] != N_FEATURES:
            raise ValueError(
                f"expected {N_FEATURES} features, got {X.shape[1]}")
        self.self_model.fit(X)
        self.snn.fit(X)
        self.memory = MemoryCells()
        self.n_assessed = 0
        self.level_hist = Counter()
        return {
            "n_train": int(X.shape[0]),
            "snn_threshold": round(self.snn.threshold, 6),
            "self_trained": self.self_model.trained,
            "snn_trained": self.snn.trained,
        }

    # -- inference ----------------------------------------------------------

    def assess(self, x, *, score: float | None = None,
               anomaly: bool = False, drift_level: str | None = None,
               evasion: bool = False, timing_scale: float = 1.0,
               reinforce: bool = True) -> dict:
        """Immune + SNN + swarm assessment of one flow."""
        if not self.available:
            return {"available": False,
                    "reason": "bio system not trained - retrain the model"}
        x = np.asarray(x, dtype=np.float64).reshape(-1)
        if x.shape[0] != N_FEATURES:
            raise ValueError(
                f"expected {N_FEATURES} features, got {x.shape[0]}")

        immune = assess_immunity(x, self.self_model, self.memory,
                                 score=score, anomaly=anomaly,
                                 drift_level=drift_level, evasion=evasion)
        snn_score: float | None = None
        if self.snn.trained:
            snn_score = float(self.snn.score(x, timing_scale=timing_scale)[0])
        snn = {
            "available": self.snn.trained,
            "score": None if snn_score is None else round(snn_score, 2),
            "threshold_pct": self.snn.threshold_pct,
        }
        swarm = self.swarm.vote(
            x,
            score=score,
            boundary=score_boundary(self.contamination),
            immune_level=immune.get("level"),
            snn_score=snn_score,
            snn_threshold=self.snn.threshold_pct,
            self_model=self.self_model,
            reinforce=reinforce,
        )

        self.n_assessed += 1
        self.level_hist[int(immune.get("level", 0))] += 1
        return {
            "available": True,
            "level": int(immune["level"]),
            "response": RESPONSES[int(immune["level"])],
            "immune": immune,
            "snn": snn,
            "swarm": swarm,
            "timing_scale": round(float(timing_scale), 3),
        }

    def remember(self, x, level: int) -> bool:
        """Store a confirmed (alert/isolate) pattern as a memory cell."""
        if level < 2 or not self.available:
            return False
        return self.memory.add(np.asarray(x, dtype=np.float64), self.self_model)

    # -- reporting ----------------------------------------------------------

    def status(self) -> dict:
        return {
            "available": self.available,
            "contamination": self.contamination,
            "self_model": {
                "trained": self.self_model.trained,
                "n_features": N_FEATURES,
            },
            "snn": {
                "trained": self.snn.trained,
                "threshold": round(self.snn.threshold, 6)
                if self.snn.trained else None,
                "threshold_pct": self.snn.threshold_pct,
            },
            "swarm": self.swarm.status(),
            "memory_cells": len(self.memory),
            "assessed": self.n_assessed,
            "response_histogram": {
                RESPONSES[i]: int(self.level_hist.get(i, 0))
                for i in range(len(RESPONSES))
            },
        }

    # -- persistence --------------------------------------------------------

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        joblib.dump({
            "version": BIO_VERSION,
            "contamination": self.contamination,
            "self_med": self.self_model.med,
            "self_mad": self.self_model.mad,
            "snn": {
                "w_in": self.snn.w_in,
                "w_out": self.snn.w_out,
                "med": self.snn.med,
                "mad": self.snn.mad,
                "baseline": self.snn.baseline,
                "threshold": self.snn.threshold,
                "threshold_pct": self.snn.threshold_pct,
            },
            "weights": dict(self.swarm.weights),
            "memory": [c for c in self.memory.cells],
        }, path)
        write_digest(path)

    def load(self, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        if not digest_ok(path):
            return False
        blob = joblib.load(path)
        if blob.get("version") != BIO_VERSION:
            return False
        self.contamination = float(blob.get("contamination", self.contamination))
        med, mad = blob.get("self_med"), blob.get("self_mad")
        if med is None or mad is None:
            return False
        self.self_model.med = np.asarray(med, dtype=np.float64)
        self.self_model.mad = np.asarray(mad, dtype=np.float64)
        s = blob.get("snn") or {}
        if s.get("w_in") is not None:
            self.snn.w_in = np.asarray(s["w_in"], dtype=np.float64)
        if s.get("w_out") is not None:
            self.snn.w_out = np.asarray(s["w_out"], dtype=np.float64)
        self.snn.med = s.get("med")
        self.snn.mad = s.get("mad")
        self.snn.baseline = s.get("baseline")
        self.snn.threshold = float(s.get("threshold", 0.0))
        self.snn.threshold_pct = float(s.get("threshold_pct", 98.0))
        for name, w in (blob.get("weights") or {}).items():
            if name in self.swarm.weights:
                self.swarm.weights[name] = float(w)
        self.memory.cells = [np.asarray(c, dtype=np.float64)
                             for c in (blob.get("memory") or [])]
        return True
