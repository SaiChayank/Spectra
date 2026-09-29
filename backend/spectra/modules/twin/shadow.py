"""Module 4: shadow-mode deployment - quantify improvement over existing tools.

Runs two *candidate* detectors beside the production model on the exact same
window and reports agreement / misses / lift:

    reference : the production Spectra detector (ground truth for agreement)
    baseline  : a naive per-feature z-score rule (stand-in for a legacy tool)
    candidate : optional alternative configuration (e.g. other contamination)

Metrics are computed with numpy only; everything degrades gracefully when the
production model is untrained (``available: False``).
"""

from __future__ import annotations

import time

import numpy as np


class ZScoreDetector:
    """Classic per-feature z-score threshold rule (the 'existing tool')."""

    def __init__(self, threshold: float = 3.5):
        self.threshold = float(threshold)
        self.mean_: np.ndarray | None = None
        self.std_: np.ndarray | None = None

    def fit(self, X: np.ndarray) -> "ZScoreDetector":
        X = np.asarray(X, dtype=np.float64)
        self.mean_ = X.mean(axis=0)
        std = X.std(axis=0)
        self.std_ = np.where(std < 1e-9, 1.0, std)
        return self

    def _z(self, X: np.ndarray) -> np.ndarray:
        if self.mean_ is None or self.std_ is None:
            raise RuntimeError("ZScoreDetector is not fitted")
        return (np.asarray(X, dtype=np.float64) - self.mean_) / self.std_

    def score(self, X: np.ndarray) -> np.ndarray:
        peak = np.abs(self._z(X)).max(axis=1)
        # squash unbounded z into the 0..100 range used across Spectra
        return 100.0 * (1.0 - 1.0 / (1.0 + peak / self.threshold))

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (np.abs(self._z(X)).max(axis=1) > self.threshold).astype(int)


def _binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "flags": int(np.sum(y_pred == 1)),
    }


def run_shadow(reference, X: np.ndarray, candidate=None,
               feature_names: list[str] | None = None,
               threshold: float = 3.5, labels: np.ndarray | None = None) -> dict:
    """Compare detectors on one window; ``reference`` is production Spectra."""
    if not getattr(reference, "is_trained", False):
        return {"available": False, "reason": "model not trained"}
    X = np.asarray(X, dtype=np.float64)
    if X.ndim != 2 or len(X) == 0:
        return {"available": False, "reason": "no scored flows yet"}

    t0 = time.perf_counter()
    ref_flags = np.asarray(reference.predict(X)).astype(int)
    ref_scores = np.asarray(reference.score(X), dtype=np.float64)
    ref_ms = (time.perf_counter() - t0) * 1000

    t1 = time.perf_counter()
    base = ZScoreDetector(threshold=threshold).fit(X)
    base_flags = base.predict(X).astype(int)
    base_ms = (time.perf_counter() - t1) * 1000

    cand_flags = None
    cand_scores = None
    cand_ms = None
    if candidate is not None:
        t2 = time.perf_counter()
        if getattr(candidate, "is_trained", True):
            cand_flags = np.asarray(candidate.predict(X)).astype(int)
            cand_scores = np.asarray(candidate.score(X), dtype=np.float64)
        else:
            cand = ZScoreDetector(threshold=threshold * 0.75).fit(X)
            cand_flags = cand.predict(X).astype(int)
            cand_scores = cand.score(X)
        cand_ms = (time.perf_counter() - t2) * 1000

    n = len(X)
    ref_rate = float(ref_flags.mean())

    def agree(a: np.ndarray) -> float:
        return round(float(np.mean(a == ref_flags)), 4)

    comparison = {
        "reference_flags": int(ref_flags.sum()),
        "baseline_flags": int(base_flags.sum()),
        "baseline_vs_reference": _binary_metrics(ref_flags, base_flags),
        "baseline_agreement": agree(base_flags),
        "missed_by_baseline": int(np.sum((ref_flags == 1) & (base_flags == 0))),
        "extra_from_baseline": int(np.sum((ref_flags == 0) & (base_flags == 1))),
    }
    improvement: dict = {}
    if cand_flags is not None:
        comparison["candidate_flags"] = int(cand_flags.sum())
        comparison["candidate_vs_reference"] = _binary_metrics(ref_flags, cand_flags)
        comparison["candidate_agreement"] = agree(cand_flags)
        comparison["missed_by_candidate"] = int(
            np.sum((ref_flags == 1) & (cand_flags == 0)))
        base_m = comparison["baseline_vs_reference"]
        cand_m = comparison["candidate_vs_reference"]
        improvement = {
            "f1_lift_vs_baseline": round(cand_m["f1"] - base_m["f1"], 4),
            "recall_lift_vs_baseline": round(cand_m["recall"] - base_m["recall"], 4),
            "flags_delta_vs_baseline": cand_m["flags"] - base_m["flags"],
            "latency_delta_ms": round((cand_ms or 0) - base_ms, 3),
        }

    truth = np.asarray(labels if labels is not None else ref_flags).astype(int)
    truth_name = "labels" if labels is not None else "reference"

    top_features: list[dict] = []
    if feature_names is not None:
        flagged = X[ref_flags == 1]
        if len(flagged):
            z = np.abs((flagged - base.mean_) / base.std_).mean(axis=0)
            order = np.argsort(z)[::-1][:5]
            top_features = [
                {"feature": str(feature_names[i]) if i < len(feature_names)
                            else f"f{i}", "z": round(float(z[i]), 2)}
                for i in order if z[i] > threshold * 0.5
            ]

    verdict_bits = []
    base_f1 = comparison["baseline_vs_reference"]["f1"]
    verdict_bits.append(f"legacy z-score rule recovers {base_f1:.0%} of "
                        f"production detections")
    if cand_flags is not None:
        cand_f1 = comparison["candidate_vs_reference"]["f1"]
        verdict_bits.append(
            "candidate " + ("outperforms" if cand_f1 >= base_f1 else "trails")
            + " the baseline rule")

    return {
        "available": True,
        "window": n,
        "anomaly_rate": round(ref_rate, 4),
        "scores": {
            "mean": round(float(ref_scores.mean()), 2),
            "p95": round(float(np.percentile(ref_scores, 95)), 2),
        },
        "comparison": comparison,
        "improvement": improvement,
        "latency_ms": {
            "reference": round(ref_ms, 3),
            "baseline": round(base_ms, 3),
            "candidate": round(cand_ms, 3) if cand_ms is not None else None,
        },
        "truth": truth_name,
        "baseline_vs_truth": _binary_metrics(truth, base_flags),
        "candidate_vs_truth": (_binary_metrics(truth, cand_flags)
                               if cand_flags is not None else None),
        "top_features": top_features,
        "verdict": " ".join(verdict_bits),
    }


__all__ = ["ZScoreDetector", "run_shadow"]
