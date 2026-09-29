"""Module 6: immune-system analog built on danger theory.

Classical "non-self" detection reacts to anything foreign, which fires on
every newly invented benign protocol.  Danger theory (Cohen, Aickelin)
instead reacts to *danger*: how far a stimulus deviates from the trained
self ("affinity") combined with contextual danger signals from around the
engine (detector score, drift, active evasion watch, cadence).  Spectra
scores every flow on both axes and maps them to an escalating response:

    0 ignore   - looks like self, no context signals
    1 monitor  - one axis is mildly elevated
    2 alert    - the danger axis is strong (or both axes elevated)
    3 isolate  - imminent danger (both axes hot, or a memory-cell hit)

Memory cells remember confirmed attack patterns so a repeat offender
escalates one level faster - the immunological memory analog.
"""

from __future__ import annotations

import numpy as np

from ...features.extractor import FEATURE_NAMES

RESPONSES = ("ignore", "monitor", "alert", "isolate")

# how far a feature may deviate before counting as fully "non-self"
Z_CAP = 6.0
# band edges mapping each axis onto response levels 0..3
AFFINITY_LEVELS = (0.35, 0.55, 0.75)
DANGER_LEVELS = (0.20, 0.50, 0.95)

# cadence (beacon) rule: metronomic inter-arrival times are a danger signal
BEACON_MIN_MEAN_S = 0.05      # slower than this is not a C2-style cadence
BEACON_REGULARITY = 0.15      # std/mean below this = metronomic
RATE_SPIKE_Z = 3.0            # robust z of packets_per_s that reads as a burst

IDX_RATE = FEATURE_NAMES.index("packets_per_s")
IDX_IAT_MEAN = FEATURE_NAMES.index("iat_mean_s")
IDX_IAT_STD = FEATURE_NAMES.index("iat_std_s")


def band_level(value: float, bands: tuple[float, ...]) -> int:
    """0..3: how many band edges this value has reached (ascending edges)."""
    level = 0
    for edge in bands:
        if value >= edge:
            level += 1
    return level


class SelfModel:
    """The benign "self": per-feature median and robust scale (MAD)."""

    def __init__(self) -> None:
        self.med: np.ndarray | None = None
        self.mad: np.ndarray | None = None

    @property
    def trained(self) -> bool:
        return self.med is not None

    def fit(self, X) -> "SelfModel":
        X = np.asarray(X, dtype=np.float64)
        if X.ndim != 2 or X.shape[0] == 0:
            raise ValueError("self model needs a non-empty 2-D matrix")
        if X.shape[1] != len(FEATURE_NAMES):
            raise ValueError(
                f"expected {len(FEATURE_NAMES)} features, got {X.shape[1]}")
        self.med = np.median(X, axis=0)
        mad = np.median(np.abs(X - self.med), axis=0) * 1.4826
        # degenerate (constant) features: plain range, then 1.0
        span = np.ptp(X, axis=0)
        mad = np.where(mad > 1e-9, mad, np.where(span > 1e-9, span / 3.5, 1.0))
        self.mad = mad.astype(np.float64)
        return self

    def robust_z(self, x) -> np.ndarray:
        """|x - median| / MAD, capped at Z_CAP (needs fit)."""
        if not self.trained:
            raise RuntimeError("self model is not fitted")
        x = np.asarray(x, dtype=np.float64)
        return np.minimum(np.abs(x - self.med) / self.mad, Z_CAP)

    def affinity(self, x) -> float:
        """Deviation from self in [0, 1]: mean capped robust |z| / Z_CAP."""
        return float(np.mean(self.robust_z(x) / Z_CAP))

    def distance(self, a, b) -> float:
        """Robust RMS distance between two vectors, in MAD units."""
        if not self.trained:
            raise RuntimeError("self model is not fitted")
        d = (np.asarray(a, dtype=np.float64) -
             np.asarray(b, dtype=np.float64)) / self.mad
        return float(np.sqrt(np.mean(d * d)))


def danger_signals(x, *, score=None, anomaly: bool = False,
                   drift_level: str | None = None, evasion: bool = False,
                   self_model: SelfModel | None = None) -> list[dict]:
    """Contextual danger signals for one flow (Module 6 input #2).

    Each signal is independent of the raw affinity: they describe what is
    happening *around* the flow (detector verdict, global drift, whether
    the detector itself is under fire).
    """
    x = np.asarray(x, dtype=np.float64)
    signals: list[dict] = []

    def add(name: str, fired: bool, weight: float, detail: str) -> None:
        signals.append({
            "name": name,
            "fired": bool(fired),
            "weight": round(float(weight if fired else 0.0), 4),
            "detail": detail,
        })

    hot = score is not None and float(score) >= 70.0
    add("score_hot", hot, 0.35,
        f"score={float(score):.1f}" if score is not None else "no score")
    add("detector_flag", bool(anomaly), 0.45, "iForest flagged the flow")
    if drift_level in ("moderate", "significant"):
        weight = 0.25 if drift_level == "moderate" else 0.45
        add("drift", True, weight, f"psi={drift_level}")
    else:
        add("drift", False, 0.25, "psi=stable")
    add("evasion_watch", bool(evasion), 0.35,
        "threshold-hugging watch active")

    # rate spike: burst of packets relative to the benign self
    rate_fired = False
    if self_model is not None and self_model.trained:
        rate_z = float(self_model.robust_z(x)[IDX_RATE])
        rate_fired = rate_z >= RATE_SPIKE_Z
    add("rate_spike", rate_fired, 0.30,
        "packets_per_s far above self" if rate_fired else "rate within self")

    # metronomic cadence: constant inter-arrival times (beaconing C2)
    mean_iat = float(x[IDX_IAT_MEAN])
    std_iat = float(x[IDX_IAT_STD])
    regular = (mean_iat >= BEACON_MIN_MEAN_S
               and mean_iat > 0
               and (std_iat / mean_iat) < BEACON_REGULARITY)
    add("beacon_cadence", regular, 0.30,
        "inter-arrival times are metronomic" if regular else "cadence varies")
    return signals


def danger_total(signals: list[dict]) -> float:
    """Sum of fired signal weights, capped at 1.0."""
    return float(min(1.0, sum(s["weight"] for s in signals if s["fired"])))


class MemoryCells:
    """Confirmed attack patterns (max size, de-duplicated by distance)."""

    TOL = 0.75       # robust RMS distance (MAD units) to count as "same cell"
    MAX = 32

    def __init__(self) -> None:
        self.cells: list[np.ndarray] = []

    def __len__(self) -> int:
        return len(self.cells)

    def hit(self, x, model: SelfModel) -> bool:
        if not model.trained or not self.cells:
            return False
        x = np.asarray(x, dtype=np.float64)
        return any(model.distance(x, c) <= self.TOL for c in self.cells)

    def add(self, x, model: SelfModel) -> bool:
        """Store a confirmed pattern; False when it duplicates a cell."""
        if not model.trained:
            return False
        x = np.asarray(x, dtype=np.float64)
        if self.hit(x, model):
            return False
        if len(self.cells) >= self.MAX:
            self.cells.pop(0)
        self.cells.append(x.copy())
        return True


def assess_immunity(x, model: SelfModel, memory: MemoryCells, *,
                    score=None, anomaly: bool = False,
                    drift_level: str | None = None,
                    evasion: bool = False) -> dict:
    """Combine affinity + danger into one escalating response level."""
    if not model.trained:
        return {"available": False, "reason": "self model not trained"}
    x = np.asarray(x, dtype=np.float64)
    affinity = model.affinity(x)
    signals = danger_signals(x, score=score, anomaly=anomaly,
                             drift_level=drift_level, evasion=evasion,
                             self_model=model)
    total = danger_total(signals)
    memory_hit = memory.hit(x, model)
    level = max(band_level(affinity, AFFINITY_LEVELS),
                band_level(total, DANGER_LEVELS))
    if memory_hit:
        level = min(3, level + 1)
    return {
        "available": True,
        "level": int(level),
        "response": RESPONSES[level],
        "affinity": round(affinity, 4),
        "danger_total": round(total, 4),
        "memory_hit": bool(memory_hit),
        "signals": signals,
    }
