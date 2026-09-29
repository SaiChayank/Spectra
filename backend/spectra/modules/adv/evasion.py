"""White-box evasion attacks against SpectraDetector (Module 3).

The Isolation Forest is a tree ensemble, so gradients are unavailable. The
attack is a greedy coordinate search in *feature space*: each step pulls the
most extreme features (by z-score) part-way toward their training mean and
keeps the move only when it lowers the raw anomaly score. Success = the flow
drops below the detection threshold.

This models a real adversary who does not see the model but knows the traffic
statistics he must imitate: shrinking burst sizes, regularising inter-arrival
times, padding flows - the classic "live off the land" shaping. The output is
used two ways:

  * robustness metrics (how cheaply can anomalies be disguised?)
  * the perturbation report tells analysts which features need hardening
    (e.g. "attacks mostly change packet-count variance").
"""

from __future__ import annotations

import numpy as np

from ...ml.model import NotTrainedError, SpectraDetector

# fraction of the distance-to-mean tried per step (coarse -> fine).
# A large first step matters: a point far outside the training range sits in
# the same isolation-forest leaf no matter where you nudge it *inside* that
# out-of-range region - only a step that crosses back into range changes the
# path (and therefore the score).
_STEP_FRACTIONS = (0.9, 0.5, 0.25, 0.1)


def attack(detector: SpectraDetector, x: np.ndarray,
           max_features: int = 12, max_rounds: int = 6) -> dict:
    """Try to make flow x evade detection. Returns the attack report.

    Never claims success without re-checking with detector.predict().
    """
    if not detector.is_trained:
        raise NotTrainedError("model is not trained yet")

    x0 = np.asarray(x, dtype=np.float64).reshape(-1)
    current = x0.copy()

    raw0 = float(detector._raw(x0)[0])
    evaded0 = bool(raw0 > detector._threshold)  # was it even an anomaly?
    score0 = float(detector.score(x0)[0])

    mean = detector.scaler.mean_.astype(np.float64)
    z0 = detector.scaler.transform(x0.reshape(1, -1))[0]
    # attack the most out-of-distribution features first
    order = np.argsort(-np.abs(z0))[:max_features]

    changed: set[int] = set()
    n_calls = 0
    rounds = 0
    best = current
    best_raw = raw0

    while rounds < max_rounds:
        rounds += 1
        improved = False
        for idx in order:
            if best_raw <= detector._threshold:
                break
            target = float(mean[idx])
            distance = target - float(best[idx])
            if abs(distance) < 1e-12:
                continue
            for frac in _STEP_FRACTIONS:
                candidate = best.copy()
                value = best[idx] + distance * frac
                if value < 0:
                    value = 0.0
                candidate[idx] = value
                n_calls += 1
                raw = float(detector._raw(candidate)[0])
                if raw < best_raw - 1e-9:
                    changed.add(int(idx))
                    best = candidate
                    best_raw = raw
                    improved = True
                    break
        if not improved:
            break

    evaded = bool(detector._raw(best)[0] <= detector._threshold)
    success = evaded and evaded0  # only "evaded" if it was flagged first

    delta = best - x0
    non_zero = np.abs(delta) > 1e-12
    changes = [
        {
            "index": int(idx),
            "feature": detector.feature_names[idx],
            "from": round(float(x0[idx]), 4),
            "to": round(float(best[idx]), 4),
            "z_before": round(float(z0[idx]), 2),
        }
        for idx in sorted(changed)
    ]
    return {
        "evaded": success,
        "was_anomalous": evaded0,
        "score_before": score0,
        "score_after": round(float(detector.score(best)[0]), 2),
        "raw_margin": round(float(detector._threshold - best_raw), 6),
        "features_changed": int(non_zero.sum()),
        "l1": round(float(np.abs(delta).sum()), 4),
        "l2": round(float(np.sqrt((delta ** 2).sum())), 4),
        "relative_l1": round(float(np.abs(delta).sum()
                                   / max(1e-9, np.abs(x0).sum())), 4),
        "model_calls": n_calls,
        "rounds": rounds,
        "changes": changes,
        "perturbed": best.tolist(),
    }


def attack_batch(detector: SpectraDetector, X: np.ndarray,
                 max_features: int = 12, max_rounds: int = 6) -> dict:
    """Attack every currently-detected row; aggregate robustness metrics."""
    if not detector.is_trained:
        raise NotTrainedError("model is not trained yet")
    X = np.atleast_2d(np.asarray(X, dtype=np.float64))
    if len(X) == 0:
        return {"evaluated": 0, "flagged": 0, "evaded": 0, "evasion_rate": 0.0,
                "median_l2": None, "median_relative_l1": None,
                "most_targeted_features": [], "level": "no_anomalies",
                "reports": []}

    flags = detector.predict(X)
    anomalous = X[flags]
    reports = [attack(detector, row, max_features=max_features,
                      max_rounds=max_rounds) for row in anomalous]

    evaded = [r for r in reports if r["evaded"]]
    changed_counts: dict[str, int] = {}
    for r in evaded:
        for c in r["changes"]:
            changed_counts[c["feature"]] = changed_counts.get(c["feature"], 0) + 1

    return {
        "evaluated": int(len(X)),
        "flagged": int(len(anomalous)),
        "evaded": len(evaded),
        "evasion_rate": round(len(evaded) / len(reports), 4) if reports else 0.0,
        "median_l2": round(float(np.median([r["l2"] for r in evaded])), 4)
        if evaded else None,
        "median_relative_l1": round(float(np.median(
            [r["relative_l1"] for r in evaded])), 4) if evaded else None,
        "most_targeted_features": sorted(
            changed_counts.items(), key=lambda kv: -kv[1])[:8],
        "level": ("fragile" if reports and len(evaded) / len(reports) >= 0.6
                  else "hardened" if not evaded and reports
                  else "partially_robust" if reports else "no_anomalies"),
        "reports": reports[:20],
    }
