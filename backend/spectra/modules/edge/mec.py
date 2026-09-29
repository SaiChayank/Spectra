"""Module 8: MEC micro-detectors + non-terrestrial link profiles.

MicroDetector is the lightweight edge twin of the main Isolation Forest:
a 12-feature robust z-score ensemble that scores a flow in microseconds -
small enough to run on a MEC node inside the sub-10ms detection budget.
It trains from the same benign baseline and speaks the same 0-100 score
language as the central model, so edge and center stay comparable.

Non-terrestrial backhaul (satellite / UAV) legitimately stretches timing,
so each link profile carries an RTT that maps to a timing scale the
neuromorphic detector divides by - remote clinics on GEO links stop
false-positiving on their own latency.
"""

from __future__ import annotations

import hashlib
import os
import time

import joblib
import numpy as np

from ...features.extractor import FEATURE_NAMES

EDGE_VERSION = 1
MICRO_FEATURES = (
    "duration_s", "packets_total", "bytes_total", "bytes_mean",
    "iat_mean_s", "iat_std_s", "packets_per_s", "bytes_per_s",
    "size_entropy", "payload_ratio", "dst_port_norm", "tls_present",
)
MICRO_IDX = tuple(FEATURE_NAMES.index(n) for n in MICRO_FEATURES)
MICRO_THRESHOLD_PCT = 98.0
LATENCY_BUDGET_MS = 10.0

TERRESTRIAL_RTT_MS = 15.0
LINK_PROFILES: dict[str, dict] = {
    "terrestrial": {"rtt_ms": 15.0, "jitter_ms": 5.0,
                    "label": "fiber / 5G non-standalone"},
    "uav": {"rtt_ms": 45.0, "jitter_ms": 15.0,
            "label": "UAV aerial backhaul"},
    "leo_satellite": {"rtt_ms": 40.0, "jitter_ms": 10.0,
                      "label": "LEO satellite constellation"},
    "geostationary": {"rtt_ms": 600.0, "jitter_ms": 30.0,
                      "label": "GEO satellite (remote clinics)"},
}


class EdgeError(ValueError):
    pass


class MicroDetector:
    """Lightweight robust z-score ensemble for MEC nodes."""

    def __init__(self) -> None:
        self.med: np.ndarray | None = None
        self.mad: np.ndarray | None = None
        self.baseline: np.ndarray | None = None
        self.threshold: float = 0.0
        self.threshold_pct: float = MICRO_THRESHOLD_PCT
        self.last_benchmark_ms: dict | None = None

    @property
    def trained(self) -> bool:
        return self.baseline is not None

    @property
    def n_features(self) -> int:
        return len(MICRO_FEATURES)

    def fit(self, X) -> dict:
        X = np.asarray(X, dtype=np.float64)
        if X.ndim != 2 or X.shape[0] < 10:
            raise EdgeError("micro detector needs >= 10 benign flows")
        if X.shape[1] != len(FEATURE_NAMES):
            raise EdgeError(
                f"expected {len(FEATURE_NAMES)} features, got {X.shape[1]}")
        cols = X[:, MICRO_IDX]
        self.med = np.median(cols, axis=0)
        mad = np.median(np.abs(cols - self.med), axis=0) * 1.4826
        span = np.ptp(cols, axis=0)
        self.mad = np.where(mad > 1e-9, mad,
                            np.where(span > 1e-9, span / 3.5, 1.0))
        raw = self._raw(cols)
        self.baseline = np.sort(raw)
        self.threshold = float(np.percentile(raw, 99.0))
        bench = self.benchmark(X)
        return {
            "n_train": int(X.shape[0]),
            "n_features": self.n_features,
            "threshold": round(self.threshold, 6),
            "latency_ms": bench,
        }

    def _raw(self, cols: np.ndarray) -> np.ndarray:
        z = np.abs(cols - self.med) / self.mad
        return np.mean(np.minimum(z, 6.0) / 6.0, axis=1)

    def score(self, x) -> float:
        """0-100 micro score (percentile vs the benign baseline)."""
        if not self.trained:
            raise EdgeError("micro detector not trained")
        x = np.asarray(x, dtype=np.float64).reshape(-1)
        if x.shape[0] != len(FEATURE_NAMES):
            raise EdgeError(
                f"expected {len(FEATURE_NAMES)} features, got {x.shape[0]}")
        raw = float(self._raw(x[None, MICRO_IDX])[0])
        idx = int(np.searchsorted(self.baseline, raw, side="left"))
        pct = 100.0 * idx / max(1, len(self.baseline) - 1)
        return float(np.clip(round(pct, 2), 0.0, 100.0))

    def predict(self, x) -> bool:
        return self.score(x) >= self.threshold_pct

    def benchmark(self, X, repeats: int = 3) -> dict:
        """Measure per-flow scoring latency (p50/p95, ms)."""
        if not self.trained or X is None or len(X) == 0:
            return {"available": False}
        X = np.asarray(X, dtype=np.float64)
        samples: list[float] = []
        for _ in range(repeats):
            for row in X:
                t0 = time.perf_counter()
                self._raw(row[None, MICRO_IDX])
                samples.append((time.perf_counter() - t0) * 1000.0)
        arr = np.asarray(samples)
        out = {
            "available": True,
            "n": int(len(arr)),
            "p50_ms": round(float(np.percentile(arr, 50)), 4),
            "p95_ms": round(float(np.percentile(arr, 95)), 4),
            "budget_ms": LATENCY_BUDGET_MS,
            "within_budget": bool(np.percentile(arr, 95) < LATENCY_BUDGET_MS),
        }
        self.last_benchmark_ms = out
        return out

    def digest(self) -> str | None:
        """Stable digest of the deployed edge model (for attestation)."""
        if not self.trained:
            return None
        h = hashlib.sha256()
        h.update("|".join(MICRO_FEATURES).encode("utf-8"))
        h.update(np.asarray(self.med, dtype=np.float64).tobytes())
        h.update(np.asarray(self.mad, dtype=np.float64).tobytes())
        h.update(repr(round(self.threshold, 9)).encode("utf-8"))
        return h.hexdigest()


class EdgeSystem:
    """Edge runtime: micro-detector, slice deployments, NTN link profile."""

    def __init__(self) -> None:
        self.link = "terrestrial"
        self.micro = MicroDetector()
        self.deployments: list[dict] = []

    # -- link profiles ------------------------------------------------------

    def set_link(self, name: str) -> dict:
        if name not in LINK_PROFILES:
            raise EdgeError(
                f"unknown link profile {name!r}; known: "
                f"{sorted(LINK_PROFILES)}")
        self.link = name
        return self.link_info()

    def link_info(self) -> dict:
        prof = LINK_PROFILES[self.link]
        return {
            "link": self.link,
            "label": prof["label"],
            "rtt_ms": prof["rtt_ms"],
            "jitter_ms": prof["jitter_ms"],
            "timing_scale": round(self.timing_scale(), 3),
        }

    def timing_scale(self) -> float:
        """RTT multiple vs terrestrial - the SNN divides timing by this."""
        rtt = LINK_PROFILES[self.link]["rtt_ms"]
        return max(1.0, rtt / TERRESTRIAL_RTT_MS)

    # -- training + deployment ----------------------------------------------

    def fit(self, X) -> dict:
        info = self.micro.fit(X)
        info["link"] = self.link
        return info

    def deploy(self, node: str, slice_id: str) -> dict:
        """Register a micro-detector deployment profile for a MEC node."""
        if not self.micro.trained:
            raise EdgeError("micro detector not trained - train first")
        if not node:
            raise EdgeError("edge node id is required")
        profile = {
            "node": str(node),
            "slice": str(slice_id or "default"),
            "link": self.link,
            "features": list(MICRO_FEATURES),
            "digest": self.micro.digest(),
            "threshold_pct": self.micro.threshold_pct,
            "budget_ms": LATENCY_BUDGET_MS,
            "deployed_at": round(time.time(), 3),
        }
        self.deployments = [d for d in self.deployments
                            if d["node"] != profile["node"]]
        self.deployments.append(profile)
        return profile

    def report(self) -> dict:
        micro = {
            "trained": self.micro.trained,
            "n_features": self.micro.n_features,
            "features": list(MICRO_FEATURES),
            "threshold": round(self.micro.threshold, 6)
            if self.micro.trained else None,
            "threshold_pct": self.micro.threshold_pct,
            "digest": self.micro.digest(),
            "latency": self.micro.last_benchmark_ms,
            "budget_ms": LATENCY_BUDGET_MS,
        }
        return {
            "link": self.link_info(),
            "link_profiles": {k: dict(v) for k, v in LINK_PROFILES.items()},
            "micro": micro,
            "deployments": list(self.deployments),
        }

    # -- persistence --------------------------------------------------------

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        joblib.dump({
            "version": EDGE_VERSION,
            "med": self.micro.med,
            "mad": self.micro.mad,
            "baseline": self.micro.baseline,
            "threshold": self.micro.threshold,
            "threshold_pct": self.micro.threshold_pct,
            "link": self.link,
            "deployments": self.deployments,
        }, path)

    def load(self, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        blob = joblib.load(path)
        if blob.get("version") != EDGE_VERSION:
            return False
        if blob.get("baseline") is None or blob.get("med") is None:
            return False
        self.micro.med = np.asarray(blob["med"], dtype=np.float64)
        self.micro.mad = np.asarray(blob["mad"], dtype=np.float64)
        self.micro.baseline = np.asarray(blob["baseline"], dtype=np.float64)
        self.micro.threshold = float(blob.get("threshold", 0.0))
        self.micro.threshold_pct = float(
            blob.get("threshold_pct", MICRO_THRESHOLD_PCT))
        if blob.get("link") in LINK_PROFILES:
            self.link = blob["link"]
        self.deployments = list(blob.get("deployments") or [])
        return True
