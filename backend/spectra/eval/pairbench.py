"""Pair-level beaconing benchmark core (docs/35 Phase E0).

A *pair* is (source host, destination IP, SNI-or-"") with the start time and total bytes of each of its flows.  Scorers map
``(times, sizes)`` to a float, higher = more beacon-like.  Only metadata (times, byte counts) is used.

``rita_style`` is a re-implementation of the idea behind RITA's beacon score (skew and median-absolute-deviation of the gaps and of
the flow sizes).  It is NOT RITA; results must not be reported as "RITA" until the real tool is run on Zeek logs of the same data.

``inject_beacons`` makes SYNTHETIC positive pairs with an exact interval and jitter.  They are idealised (no packet loss, no
sleeping laptop), so they bound what a detector can do; they do not measure detection of any real C2 framework.
"""
from __future__ import annotations

import random
import statistics
from collections import defaultdict
from collections.abc import Callable, Iterable

from ..modules.corr.graph import cadence_stats

Pair = tuple[str, str, str]
Series = tuple[list[float], list[float]]  # (sorted start times, sizes in the same order)
Scorer = Callable[[list[float], list[float]], float]


def pair_series(flows: Iterable, min_flows: int = 10) -> dict[Pair, Series]:
    """Group flows into outbound pairs; keep pairs with at least ``min_flows`` flows."""
    acc: dict[Pair, list[tuple[float, float]]] = defaultdict(list)
    for f in flows:
        tls = f.tls
        sni = (getattr(tls, "sni", None) or "") if tls else ""
        acc[(f.src_ip, f.dst_ip, sni)].append((f.start_ts, float(f.bytes_fwd + f.bytes_bwd)))
    out: dict[Pair, Series] = {}
    for k, v in acc.items():
        if len(v) >= min_flows:
            v.sort()
            out[k] = ([t for t, _ in v], [s for _, s in v])
    return out


def _bowley(xs: list[float]) -> float:
    q = statistics.quantiles(xs, n=4, method="inclusive")
    lo, mid, hi = q
    return 0.0 if hi == lo else (lo + hi - 2 * mid) / (hi - lo)


def _mad(xs: list[float]) -> float:
    m = statistics.median(xs)
    return statistics.median(abs(x - m) for x in xs)


def spectra_regularity(times: list[float], sizes: list[float]) -> float:
    """Spectra's current per-pair signal (modules.corr.graph.cadence_stats): 1 - cv of start gaps."""
    s = cadence_stats(times)
    return s["regularity"] if s else 0.0


def rita_style(times: list[float], sizes: list[float]) -> float:
    """Average of a gap-regularity score and a size-regularity score, each 1 - (|Bowley skew| + MAD/scale)/2, clamped to [0, 1]."""
    if len(times) < 4:
        return 0.0
    gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
    ts = 1 - (abs(_bowley(gaps)) + _mad(gaps) / 30.0) / 2
    ds = 1 - (abs(_bowley(sizes)) + _mad(sizes) / 128.0) / 2
    return max(0.0, min(1.0, ts)) * 0.5 + max(0.0, min(1.0, ds)) * 0.5


def periodogram_peak(times: list[float], sizes: list[float]) -> float:
    """Jitter-tolerant baseline: share of gap histogram mass in the best window of width 1.5x the median gap / 3.

    Robust to uniform jitter up to roughly +-50 % because the window is wide; weaker below because uniform noise on a window of
    width w/3 captures at most the proportional part.  Included as a reference, not as the final detector.
    """
    if len(times) < 4:
        return 0.0
    gaps = sorted(b - a for a, b in zip(times, times[1:], strict=False))
    med = statistics.median(gaps)
    if med <= 0:
        return 0.0
    w = med / 3.0
    best, j = 0, 0
    for i, g in enumerate(gaps):
        while gaps[j] < g - w:
            j += 1
        best = max(best, i - j + 1)
    return best / len(gaps)


SCORERS: dict[str, Scorer] = {
    "spectra_regularity": spectra_regularity,
    "rita_style": rita_style,
    "gap_mode_share": periodogram_peak,
}


def inject_beacons(n: int, *, interval_s: float, jitter: float, n_flows: int = 30, size_mean: float = 900.0,
                   size_cv: float = 0.05, seed: int = 1337) -> list[Series]:
    """``n`` synthetic beacon series.  Gap = interval * (1 + U(-jitter, +jitter)); size ~ Normal(mean, cv*mean), floored at 1."""
    rng = random.Random(seed)
    out: list[Series] = []
    for _ in range(n):
        t, times = rng.uniform(0, interval_s), []
        for _ in range(n_flows):
            times.append(t)
            t += interval_s * (1 + rng.uniform(-jitter, jitter))
        sizes = [max(1.0, rng.gauss(size_mean, size_cv * size_mean)) for _ in times]
        out.append((times, sizes))
    return out


def steady_negatives(n: int, *, interval_s: float, shape: float = 4.0, n_flows: int = 30, size_mean: float = 900.0,
                     size_cv: float = 0.5, seed: int = 4242) -> list[Series]:
    """Hard NEGATIVES: steady non-beacon services.  Gaps are gamma renewals with mean ``interval_s`` (cv = 1/sqrt(shape): shape 4 -> 0.5,
    the same gap spread as a beacon with ~87 % uniform jitter); sizes vary with ``size_cv`` (0.05 = worst case, same as a beacon)."""
    rng = random.Random(seed)
    out: list[Series] = []
    for _ in range(n):
        t, times = rng.uniform(0, interval_s), []
        for _ in range(n_flows):
            times.append(t)
            t += rng.gammavariate(shape, interval_s / shape)
        sizes = [max(1.0, rng.gauss(size_mean, size_cv * size_mean)) for _ in times]
        out.append((times, sizes))
    return out


def evaluate(benign: dict[Pair, Series], positives: list[Series], scorers: dict[str, Scorer] | None = None,
             bootstrap: int = 0, seed: int = 1337) -> dict:
    """Per scorer: pair-level ROC-AUC, PR-AUC and recall at 1 % / 0.1 % benign-pair FPR (see eval.metrics.score_metrics)."""
    from .metrics import score_metrics
    out = {}
    for name, fn in (scorers or SCORERS).items():
        neg = [fn(t, s) for t, s in benign.values()]
        pos = [fn(t, s) for t, s in positives]
        out[name] = score_metrics(pos, neg, bootstrap, seed)
    return out
