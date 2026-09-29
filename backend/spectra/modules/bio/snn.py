"""Module 6: neuromorphic temporal coding (spiking neural network).

A compact leaky integrate-and-fire (LIF) network for timing anomalies -
the "payment flow cadence" detector from the spec.  Encoding is temporal:
each timing feature's *deviation from the benign norm* becomes a spike
latency (deviant features spike early, in-sync; well-behaved features spike
late or not at all).  Coincident early spikes summate in the hidden pool
and drive the readout neuron above threshold, so flows whose timing departs
from self produce more output activity than benign ones.

The scored signal is *peak x earliness*: coincidence alone is ambiguous
("all features deviant" and "all features perfectly normal" both fire in
sync), so the readout peak is weighted by how early it arrived - only
deviant timing bursts fire at t=0, benign activity arrives late.

Everything is deterministic (fixed seed) and vectorized across the batch -
no new dependencies, numpy only.
"""

from __future__ import annotations

import numpy as np

from ...features.extractor import FEATURE_NAMES

# timing features that define the neuromorphic input code
TIMING_FEATURES = (
    "duration_s", "iat_mean_s", "iat_std_s", "iat_min_s", "iat_max_s",
    "iat_fwd_mean_s", "iat_fwd_std_s", "iat_fwd_mad_s", "packets_per_s",
)
IDX = tuple(FEATURE_NAMES.index(n) for n in TIMING_FEATURES)

HIDDEN = 16          # interneurons in the LIF pool
T_STEPS = 24         # simulation steps per flow
LEAK = 0.9           # membrane leak per step
THETA = 1.2          # hidden membrane threshold (spike)
OUT_THETA = 1.5      # readout membrane threshold (spike)
DEV_SCALE = 3.0      # robust deviation counted as "fully deviant"
SEED = 1337
DEFAULT_THRESHOLD_PCT = 98.0   # score percentile that flags a timing anomaly


class TimingSNN:
    """One hidden LIF pool + one readout neuron, calibrated on benign traffic."""

    def __init__(self) -> None:
        rng = np.random.default_rng(SEED)
        # excitatory-only pool: more coincident input -> strictly more drive,
        # so the "deviation -> spiking" mapping is monotone and testable
        self.w_in = np.abs(rng.normal(size=(len(IDX), HIDDEN)))
        self.w_out = np.abs(rng.normal(size=HIDDEN))
        self.med: np.ndarray | None = None
        self.mad: np.ndarray | None = None
        self.baseline: np.ndarray | None = None   # benign metric values, sorted
        self.threshold: float = 0.0
        self.threshold_pct: float = DEFAULT_THRESHOLD_PCT

    @property
    def trained(self) -> bool:
        return self.baseline is not None

    # -- encoding + simulation ---------------------------------------------

    def _latencies(self, X: np.ndarray, timing_scale: float) -> np.ndarray:
        """Spike latency per timing feature: deviant -> early (small t)."""
        cols = np.asarray(X, dtype=np.float64)[:, IDX]
        if timing_scale and timing_scale != 1.0:
            # non-terrestrial link (satellite/UAV backhaul): what counts as
            # "normal" timing legitimately stretches with the RTT
            cols = cols / float(timing_scale)
        dev = np.abs(cols - self.med) / (DEV_SCALE * self.mad)
        dev = np.clip(np.nan_to_num(dev, nan=0.0, posinf=1.0), 0.0, 1.0)
        lat = np.rint((1.0 - dev) * (T_STEPS - 1)).astype(np.int32)
        return lat

    def _simulate(self, lat: np.ndarray
                  ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Run the LIF network; returns (peaks, spike counts, metrics).

        The metric is peak x earliness: the readout peak weighted by how
        early the first output spike arrived (early = deviant timing burst,
        late = benign activity).  This is the quantity the score percentiles
        against the benign window.
        """
        n = lat.shape[0]
        v_h = np.zeros((n, HIDDEN))
        v_o = np.zeros(n)
        counts = np.zeros(n)
        peak = np.zeros(n)
        first = np.full(n, T_STEPS, dtype=np.int32)
        for t in range(T_STEPS):
            firing = (lat == t).astype(np.float64)         # (n, D)
            v_h = LEAK * v_h + firing @ self.w_in
            sp = v_h >= THETA
            v_h = np.where(sp, 0.0, v_h)                    # reset
            v_o = LEAK * v_o + sp @ self.w_out
            peak = np.maximum(peak, v_o)
            crossed = v_o >= OUT_THETA
            first = np.where((first == T_STEPS) & crossed, t, first)
            counts = counts + crossed.astype(np.float64)
            v_o = np.where(crossed, 0.0, v_o)
        metric = peak * (1.0 + (T_STEPS - first) / T_STEPS)
        return peak, counts, metric

    # -- training + scoring -------------------------------------------------

    def fit(self, X, timing_scale: float = 1.0) -> "TimingSNN":
        X = np.asarray(X, dtype=np.float64)
        if X.ndim != 2 or X.shape[0] == 0:
            raise ValueError("snn needs a non-empty 2-D matrix")
        cols = X[:, IDX]
        if timing_scale and timing_scale != 1.0:
            cols = cols / float(timing_scale)
        self.med = np.median(cols, axis=0)
        mad = np.median(np.abs(cols - self.med), axis=0) * 1.4826
        span = np.ptp(cols, axis=0)
        self.mad = np.where(mad > 1e-9, mad,
                            np.where(span > 1e-9, span / 3.5, 1.0))
        _, _, metric = self._simulate(self._latencies(X, timing_scale))
        self.baseline = np.sort(metric)
        self.threshold = float(np.percentile(metric, 99.0))
        return self

    def activity(self, X, timing_scale: float = 1.0) -> tuple[np.ndarray, np.ndarray]:
        """(output peaks, output spike counts) for a batch."""
        if not self.trained:
            raise RuntimeError("snn is not trained")
        X = np.asarray(X, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        if X.shape[1] != len(FEATURE_NAMES):
            raise ValueError(
                f"expected {len(FEATURE_NAMES)} features, got {X.shape[1]}")
        peak, counts, _ = self._simulate(self._latencies(X, timing_scale))
        return peak, counts

    def score(self, X, timing_scale: float = 1.0) -> np.ndarray:
        """0-100 timing-anomaly score (percentile vs the benign window)."""
        _, _, metric = self.activity_metric(X, timing_scale)
        idx = np.searchsorted(self.baseline, metric, side="left")
        pct = 100.0 * idx / max(1, len(self.baseline) - 1)
        return np.clip(np.round(pct, 2), 0.0, 100.0)

    def activity_metric(self, X, timing_scale: float = 1.0):
        """(peaks, counts, earliness-weighted metrics) for a batch."""
        if not self.trained:
            raise RuntimeError("snn is not trained")
        X = np.asarray(X, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        if X.shape[1] != len(FEATURE_NAMES):
            raise ValueError(
                f"expected {len(FEATURE_NAMES)} features, got {X.shape[1]}")
        return self._simulate(self._latencies(X, timing_scale))

    def predict(self, X, timing_scale: float = 1.0) -> np.ndarray:
        return self.score(X, timing_scale) >= self.threshold_pct
