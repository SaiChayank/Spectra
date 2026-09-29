"""Detector model: fast single-row scoring must be bit-identical to sklearn.

The ingest path scores one flow at a time. sklearn's IsolationForest pays
~10 ms of per-tree dispatch overhead (joblib task + validation + sparse alloc)
on single-row inputs, so SpectraDetector walks pre-converted tree node arrays
directly instead. These tests pin that the fast path reproduces
``-decision_function`` exactly, stays wired through refit/save/load, and falls
back to sklearn when disabled.
"""

import numpy as np

from spectra.features.extractor import N_FEATURES
from spectra.ml.model import SpectraDetector


def _trained(seed: int = 3, n_estimators: int = 64):
    rng = np.random.default_rng(seed)
    X = rng.normal(0.0, 1.0, size=(60, N_FEATURES))
    det = SpectraDetector(n_estimators=n_estimators, contamination=0.05,
                          random_state=1)
    info = det.fit(X)
    assert info["n_train"] == 60
    return det, X


def _probe_rows(train: np.ndarray, seed: int = 11) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return np.vstack([
        train[:5],
        rng.normal(0, 2, (40, N_FEATURES)),
        rng.uniform(0, 100, (20, N_FEATURES)),
        np.zeros((3, N_FEATURES)),
        np.ones((3, N_FEATURES)),
        np.full((2, N_FEATURES), 1e6),
    ]).astype(np.float32)


def _sklearn_raw(det: SpectraDetector, x: np.ndarray) -> float:
    Z = det.scaler.transform(x.reshape(1, -1))
    return float(-det.model.decision_function(Z)[0])


def test_fast_raw_matches_sklearn():
    det, train = _trained()
    for x in _probe_rows(train):
        got = float(det._raw(x.reshape(1, -1))[0])
        assert got == _sklearn_raw(det, x), "fast path diverged from sklearn"
    assert det._fast, "fast path should be engaged after the first score"


def test_score_identical_with_fast_path_disabled():
    det, train = _trained()
    for x in _probe_rows(train, seed=21):
        with_fast = float(det.score(x.reshape(1, -1))[0])
        det._fast = False  # force the sklearn fallback
        without = float(det.score(x.reshape(1, -1))[0])
        det._fast = None   # allow a rebuild for the next row
        assert with_fast == without


def test_predict_identical_with_fast_path_disabled():
    det, train = _trained()
    for x in _probe_rows(train, seed=22):
        with_fast = bool(det.predict(x.reshape(1, -1))[0])
        det._fast = False
        without = bool(det.predict(x.reshape(1, -1))[0])
        det._fast = None
        assert with_fast == without


def test_refit_invalidates_stale_fast_path():
    det, X = _trained()
    det._raw(np.zeros((1, N_FEATURES), dtype=np.float32))  # builds fast caches
    assert det._fast
    det.fit(X * 1.75 + 3.0)  # new forest; a stale walk would diverge
    for x in _probe_rows(X, seed=31):
        assert float(det._raw(x.reshape(1, -1))[0]) == _sklearn_raw(det, x)


def test_save_excludes_and_rebuilds_fast_path(tmp_path):
    det, train = _trained()
    det._raw(np.zeros((1, N_FEATURES), dtype=np.float32))
    assert det._fast
    path = tmp_path / "model.joblib"
    det.save(str(path))
    assert det._fast, "save must not clobber the in-memory cache"
    loaded = SpectraDetector.load(str(path))
    assert loaded._fast is None, "artifact must not carry the fast-path caches"
    x = _probe_rows(train, seed=41)[3]
    assert float(loaded._raw(x.reshape(1, -1))[0]) == _sklearn_raw(loaded, x)


def test_batch_rows_take_the_sklearn_path():
    det, train = _trained()
    rows = _probe_rows(train, seed=51)
    fast_batch = det._raw(rows)
    det._fast = False
    slow_batch = det._raw(rows)
    np.testing.assert_array_equal(fast_batch, slow_batch)
