"""Anomaly detection model.

Ensemble of a StandardScaler and an Isolation Forest trained on a baseline of
benign flows. Scoring produces both a 0-100 anomaly score (percentile of the
training distribution) and per-feature explanations for the analyst.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ..features.extractor import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    N_FEATURES,
    feature_schema_digest,
)

MODEL_VERSION = 1


class NotTrainedError(RuntimeError):
    pass


class SpectraDetector:
    # Per-instance state rebuilt lazily; the class default keeps unpickling of
    # models saved before the fast path existed safe (they start at None).
    _fast = None

    def __init__(self, n_estimators: int = 300, contamination: float = 0.02, random_state: int = 42):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination="auto",
            random_state=random_state,
            n_jobs=-1,
        )
        self.feature_names = list(FEATURE_NAMES)
        self.trained_at: str | None = None
        self.n_train = 0
        self._train_raw: np.ndarray | None = None
        self._threshold: float = 0.0
        # baseline distribution for drift detection (PSI)
        self._baseline_edges: np.ndarray | None = None   # (n_features, bins+1)
        self._baseline_props: np.ndarray | None = None   # (n_features, bins)

    N_BASELINE_BINS = 40

    # -- training -----------------------------------------------------------

    def _make_baseline(self, X: np.ndarray) -> None:
        edges = []
        props = []
        for col in range(X.shape[1]):
            lo = float(np.min(X[:, col]))
            hi = float(np.max(X[:, col]))
            if not np.isfinite(lo) or not np.isfinite(hi) or hi <= lo:
                hi = lo + 1e-6
            e = np.linspace(lo, hi, self.N_BASELINE_BINS + 1)
            counts, _ = np.histogram(X[:, col], bins=e)
            p = counts.astype(np.float64) + 1e-6
            p /= p.sum()
            edges.append(e)
            props.append(p)
        self._baseline_edges = np.array(edges)
        self._baseline_props = np.array(props)

    @property
    def has_baseline(self) -> bool:
        return getattr(self, "_baseline_props", None) is not None

    def fit(self, X: np.ndarray) -> dict:
        X = self._check(X)
        if len(X) < 10:
            raise ValueError(
                f"need at least 10 flows to train, got {len(X)} - "
                "point at a PCAP with more baseline traffic."
            )
        self._fast = None  # trees are being replaced; rebuild the fast path after
        Z = self.scaler.fit_transform(X)
        self.model.fit(Z)
        raw = -self.model.decision_function(Z)  # higher = more anomalous
        self._train_raw = np.sort(raw)
        self._threshold = float(np.percentile(raw, 100 * (1 - self.contamination)))
        self._make_baseline(X)
        self.n_train = int(len(X))
        self.trained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return {
            "n_train": self.n_train,
            "threshold": round(self._threshold, 6),
            "train_score_mean": round(float(raw.mean()), 6),
            "train_score_p99": round(float(np.percentile(raw, 99)), 6),
            "contamination": self.contamination,
        }

    # -- inference ----------------------------------------------------------

    @property
    def is_trained(self) -> bool:
        return self._train_raw is not None

    def _build_fast(self) -> None:
        """Prepare the single-row fast path (mirrors sklearn's scoring exactly).

        sklearn's IsolationForest.decision_function pays ~300 per-tree task
        dispatches (joblib + validation + sparse alloc) per call, which costs
        ~10 ms for a one-row input - unacceptable on the ingest path. The
        computation is equivalent to summing, per tree,
        ``decision_path_lengths[leaf] + avg_path_lengths[leaf] - 1`` over the
        forest, so we pre-convert the tree node arrays to Python lists once and
        walk them directly. ``tests/test_model.py::test_fast_raw_matches_sklearn``
        asserts bit-identical output; any environment where the prerequisites
        are missing falls back to sklearn's decision_function.
        """
        try:
            from sklearn.ensemble._iforest import _average_path_length

            m = self.model
            if not self.is_trained or m._max_features != N_FEATURES:
                self._fast = False  # feature subsampling -> keep the sklearn path
                return
            trees = [
                (t.tree_.children_left.tolist(),
                 t.tree_.children_right.tolist(),
                 t.tree_.feature.tolist(),
                 t.tree_.threshold.tolist())
                for t in m.estimators_
            ]
            max_samples = getattr(m, "_max_samples", None) or m.max_samples_
            denom = (len(m.estimators_)
                     * float(np.atleast_1d(_average_path_length([max_samples]))[0]))
            if denom == 0.0 or not m._decision_path_lengths:
                self._fast = False
                return
            self._fast = (
                trees,
                m._decision_path_lengths,
                m._average_path_length_per_tree,
                denom,
                float(m.offset_),
            )
        except Exception:  # noqa: BLE001 - any doubt -> sklearn path (always correct)
            self._fast = False

    def _raw_fast(self, z_row: np.ndarray) -> float:
        trees, dpls, apls, denom, offset = self._fast
        x = z_row.tolist()
        depths = 0.0
        for (cl, cr, ft, th), dpl, apl in zip(trees, dpls, apls):
            node = 0
            while cl[node] != -1:
                node = cl[node] if x[ft[node]] <= th[node] else cr[node]
            depths += dpl[node] + apl[node] - 1.0
        return float(2.0 ** (-depths / denom) + offset)

    def _raw(self, X: np.ndarray) -> np.ndarray:
        if not self.is_trained:
            raise NotTrainedError("model is not trained yet")
        X = self._check(X)
        Z = self.scaler.transform(X)
        if X.shape[0] == 1:
            if self._fast is None:
                self._build_fast()
            if self._fast:
                return np.array([self._raw_fast(Z[0])])
        return -self.model.decision_function(Z)

    def score(self, X: np.ndarray) -> np.ndarray:
        """0-100 anomaly score (percentile rank against the training set)."""
        raw = self._raw(X)
        train = self._train_raw
        idx = np.searchsorted(train, raw, side="left")
        pct = 100.0 * idx / max(1, len(train) - 1)
        return np.clip(np.round(pct, 2), 0.0, 100.0)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Boolean anomaly labels using the training-derived threshold."""
        return self._raw(X) > self._threshold

    def explain(self, x: np.ndarray, top: int = 3) -> list[dict]:
        """Top features driving the anomaly score, by z-score magnitude."""
        z = self.scaler.transform(x.reshape(1, -1))[0]
        order = np.argsort(np.abs(z))[::-1][:top]
        return [
            {
                "feature": self.feature_names[i],
                "z_score": round(float(z[i]), 2),
                "value": round(float(x[i]), 4),
            }
            for i in order
            if abs(z[i]) > 0.5
        ]

    # -- drift --------------------------------------------------------------

    def psi(self, X: np.ndarray) -> dict:
        """Population Stability Index of X against the training baseline.

        PSI < 0.10 = stable, 0.10-0.25 = moderate drift, > 0.25 = significant
        (values shifted enough that model scores are no longer calibrated).
        """
        if not self.has_baseline:
            return {"available": False, "reason": "model predates drift support - retrain"}
        X = self._check(X)
        if len(X) == 0:
            return {"available": True, "n": 0, "psi": 0.0, "level": "stable",
                    "features": []}

        eps = 1e-6
        rows = []
        for i, name in enumerate(self.feature_names):
            counts, _ = np.histogram(X[:, i], bins=self._baseline_edges[i])
            q = counts.astype(np.float64) + eps
            q /= q.sum()
            p = self._baseline_props[i]
            # skip constant (degenerate) baselines
            if np.allclose(p, p[0]):
                rows.append({"feature": name, "psi": 0.0, "constant": True})
                continue
            val = float(np.sum((q - p) * np.log(q / p)))
            rows.append({"feature": name, "psi": round(val, 4)})

        values = [r["psi"] for r in rows]
        overall = float(np.mean(values)) if values else 0.0
        level = ("significant" if overall > 0.25
                 else "moderate" if overall > 0.10 else "stable")
        rows.sort(key=lambda r: -r["psi"])
        return {
            "available": True,
            "n": int(len(X)),
            "psi": round(overall, 4),
            "level": level,
            "features": rows[:10],
        }

    # -- persistence --------------------------------------------------------

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        # Keep the fast-path caches out of the artifact; they are rebuilt
        # lazily on first score after load (saves ~1 MB of tree lists).
        fast, self._fast = self._fast, None
        try:
            joblib.dump(
                {
                    "version": MODEL_VERSION,
                    "detector": self,
                },
                path,
            )
        finally:
            self._fast = fast

    @classmethod
    def load(cls, path: str) -> "SpectraDetector":
        blob = joblib.load(path)
        if blob.get("version") != MODEL_VERSION:
            raise ValueError("model file version mismatch - retrain the model")
        det = blob["detector"]
        if not isinstance(det, cls):  # pragma: no cover - defensive
            raise ValueError("unexpected object in model file")
        return det

    def info(self) -> dict:
        return {
            "trained": self.is_trained,
            "trained_at": self.trained_at,
            "n_train": self.n_train,
            "n_features": N_FEATURES,
            "feature_names": self.feature_names,
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "threshold": round(self._threshold, 6) if self.is_trained else None,
            "version": MODEL_VERSION,
        }

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _check(X: np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=np.float32)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        if X.shape[1] != N_FEATURES:
            raise ValueError(f"expected {N_FEATURES} features, got {X.shape[1]}")
        return np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
