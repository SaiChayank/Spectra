"""snn_score must not depend on the CPU (HANDOFF_FINDINGS 2026-11-19: 63.41 here vs 65.85 in CI).

The LIF update sums weights through ``@``; BLAS kernels add terms in a CPU-specific order, and float rounding then
flips a ``>= threshold`` comparison on some flows.  The weights are therefore kept on an exact binary grid, so every
partial sum is exact and the result is the same in any summation order.
"""
import itertools

import numpy as np

from spectra.modules.bio.snn import HIDDEN, IDX, TimingSNN


def _patterns(d: int) -> np.ndarray:
    return np.array(list(itertools.product((0.0, 1.0), repeat=d)))


def test_hidden_input_sums_are_order_independent():
    w = TimingSNN().w_in
    f = _patterns(len(IDX))                                   # every possible set of coincident input spikes
    fwd = f @ w
    rev = f[:, ::-1] @ w[::-1]                                # same sum, opposite order
    loop = np.array([[sum(f[i, k] * w[k, j] for k in range(len(IDX))) for j in range(HIDDEN)] for i in range(len(f))])
    assert np.array_equal(fwd, rev) and np.array_equal(fwd, loop)


def test_readout_sums_are_order_independent():
    w = TimingSNN().w_out
    s = _patterns(HIDDEN)[:: 7]                               # 9,363 of the 65,536 hidden spike patterns
    assert np.array_equal(s @ w, s[:, ::-1] @ w[::-1])


def test_scores_are_identical_across_runs_and_batch_orders():
    rng = np.random.default_rng(7)
    X = np.abs(rng.normal(size=(400, 39))) * rng.uniform(0.01, 50, size=39)
    a = TimingSNN().fit(X[:300]).score(X[300:])
    b = TimingSNN().fit(X[:300][::-1]).score(X[300:][::-1])[::-1]     # another object, reversed rows
    assert np.array_equal(a, b)
