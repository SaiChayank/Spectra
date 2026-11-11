"""Pair-level benchmark core: scorers behave on constructed series (docs/35 E0)."""
import random

from spectra.eval.pairbench import SCORERS, evaluate, inject_beacons, rita_style, spectra_regularity


def _poisson_pair(rng, n=30, rate=1 / 60):
    t, times = 0.0, []
    for _ in range(n):
        t += rng.expovariate(rate)
        times.append(t)
    return times, [float(rng.randint(100, 5000)) for _ in times]


def test_metronome_beats_poisson_on_every_scorer():
    rng = random.Random(1)
    benign = {("h", f"d{i}", ""): _poisson_pair(rng) for i in range(200)}
    pos = inject_beacons(20, interval_s=60, jitter=0.0)
    res = evaluate(benign, pos)
    for name in SCORERS:
        assert res[name]["roc_auc"] > 0.95, name


def test_regularity_falls_with_jitter_and_is_deterministic():
    scores = []
    for j in (0.0, 0.25, 0.75):
        t, s = inject_beacons(1, interval_s=60, jitter=j, seed=5)[0]
        scores.append(spectra_regularity(t, s))
    assert scores[0] > scores[1] > scores[2]
    assert inject_beacons(2, interval_s=60, jitter=0.3, seed=9) == inject_beacons(2, interval_s=60, jitter=0.3, seed=9)


def test_too_short_series_score_zero():
    assert rita_style([1.0, 2.0], [1.0, 1.0]) == 0.0


def test_steady_negatives_defeat_gap_regularity_at_matching_spread():
    from spectra.eval.pairbench import steady_negatives
    neg = {("s", i): v for i, v in enumerate(steady_negatives(100, interval_s=60, size_cv=0.05))}
    pos = inject_beacons(100, interval_s=60, jitter=0.9)
    assert evaluate(neg, pos)["spectra_regularity"]["roc_auc"] < 0.7  # timing alone cannot separate them
