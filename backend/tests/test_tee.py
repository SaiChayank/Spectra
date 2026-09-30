"""Module 2: confidential computing - attestation, sealed inference,
federated aggregation."""

from __future__ import annotations

import json
import time

import numpy as np
import pytest

from spectra.features.extractor import N_FEATURES
from spectra.modules.tee import (
    FederatedError,
    TeeEnclave,
    TeeError,
    digest_features,
    federated_round,
    measure_file,
    recombine,
)


class StubDetector:
    """Detector stub with a fixed verdict (enclave does not care how)."""

    def __init__(self, score: float = 88.8, flagged: bool = True,
                 trained: bool = True):
        self._score = score
        self._flagged = flagged
        self.is_trained = trained

    def score(self, X):
        rows = np.atleast_2d(X)
        return np.full(len(rows), self._score)

    def predict(self, X):
        rows = np.atleast_2d(X)
        return np.full(len(rows), self._flagged, dtype=bool)


def make_model(tmp_path, payload: bytes = b"model-weights-v1") -> str:
    path = tmp_path / "model.joblib"
    path.write_bytes(payload)
    return str(path)


@pytest.fixture()
def tee(tmp_path) -> TeeEnclave:
    return TeeEnclave(make_model(tmp_path),
                      key_path=str(tmp_path / "tee.key"))


# -- measurement + attestation ----------------------------------------------


def test_measurement_tracks_artifact_bytes(tmp_path):
    path = make_model(tmp_path, b"weights-A")
    first = measure_file(path)
    assert first and len(first) == 64

    TeeEnclave(path, key_path=str(tmp_path / "k.key"))  # side-effect: key file
    make_model(tmp_path, b"weights-B (tampered)")
    assert measure_file(path) != first
    assert measure_file(str(tmp_path / "missing.bin")) is None


def test_quote_roundtrip(tee):
    quote = tee.quote(nonce="challenge-1")
    assert quote["nonce"] == "challenge-1"
    assert quote["measurement"] == tee.measurement

    rep = tee.verify(quote, nonce="challenge-1")
    assert rep["ok"] is True
    assert all(c["ok"] for c in rep["checks"])
    names = [c["name"] for c in rep["checks"]]
    for expected in ("signature", "provenance", "freshness", "measurement",
                     "nonce"):
        assert expected in names


def test_quote_rejects_forged_nonce_and_stale_timestamp(tee, tmp_path):
    quote = tee.quote(nonce="a")

    # wrong challenge nonce
    rep = tee.verify(quote, nonce="b")
    assert rep["ok"] is False
    assert not [c for c in rep["checks"] if c["name"] == "nonce"][0]["ok"]

    # expired quote
    old = dict(quote)
    old["ts"] = time.time() - 10_000
    rep = tee.verify(old, max_age=600.0)
    assert rep["ok"] is False
    assert not [c for c in rep["checks"] if c["name"] == "freshness"][0]["ok"]


def test_quote_detects_model_tamper(tee, tmp_path):
    quote = tee.quote()
    assert tee.verify(quote)["ok"] is True

    make_model(tmp_path, b"model-weights-v1-EVIL")
    tee.remeasure()
    rep = tee.verify(quote)
    assert rep["ok"] is False
    failed = [c["name"] for c in rep["checks"] if not c["ok"]]
    assert failed == ["measurement"]


def test_quote_rejects_foreign_signer(tee, tmp_path):
    """A quote signed by some other enclave key fails provenance."""
    intruder = TeeEnclave(make_model(tmp_path),
                          key_path=str(tmp_path / "intruder.key"))
    foreign = intruder.quote()
    rep = tee.verify(foreign)
    assert rep["ok"] is False
    failed = [c["name"] for c in rep["checks"] if not c["ok"]]
    assert "provenance" in failed


def test_quote_rejects_tampered_body(tee):
    quote = tee.quote()
    for field, value in (("measurement", "0" * 64), ("nonce", "evil"),
                         ("ts", quote["ts"] + 1)):
        broken = dict(quote)
        broken[field] = value
        rep = tee.verify(broken)
        assert rep["ok"] is False
        assert not [c for c in rep["checks"] if c["name"] == "signature"][0]["ok"]
    # malformed quote reports structure, never crashes
    rep = tee.verify({"measurement": "x"})
    assert rep["ok"] is False
    assert rep["reason"] == "malformed quote"


def test_attest_requires_artifact(tmp_path):
    missing = TeeEnclave(str(tmp_path / "gone.joblib"),
                         key_path=str(tmp_path / "k.key"))
    with pytest.raises(TeeError):
        missing.quote()


# -- protected inference -----------------------------------------------------


def test_sealed_inference_receipt(tee):
    features = [0.25] * N_FEATURES
    out = tee.infer(StubDetector(), features)
    assert out["score"] == 88.8
    assert out["flagged"] is True
    assert out["claims"]["payload_bytes"] == 0
    assert out["claims"]["features_only"] is True
    assert out["claims"]["model_measurement"] == tee.measurement

    rep = tee.verify_receipt(out["receipt"], features,
                             {"score": out["score"], "flagged": out["flagged"]})
    assert rep["ok"] is True
    assert all(c["ok"] for c in rep["checks"])

    # any change to inputs or outputs breaks the sealed binding
    tampered = list(features)
    tampered[0] = 0.99
    assert tee.verify_receipt(out["receipt"], tampered,
                              {"score": out["score"],
                               "flagged": out["flagged"]})["ok"] is False
    assert tee.verify_receipt(out["receipt"], features,
                              {"score": 1.0,
                               "flagged": out["flagged"]})["ok"] is False


def test_infer_only_accepts_flow_metadata(tee):
    detector = StubDetector()
    with pytest.raises(TeeError):
        tee.infer(detector, [0.1] * (N_FEATURES - 1))       # wrong length
    with pytest.raises(TeeError):
        tee.infer(detector, ["payload", "bytes"] * 10)      # raw payload
    with pytest.raises(TeeError):
        tee.infer(detector, [float("nan")] * N_FEATURES)    # non-finite
    with pytest.raises(TeeError):
        tee.infer(StubDetector(trained=False), [0.1] * N_FEATURES)


def test_receipt_is_bound_to_model(tmp_path):
    tee = TeeEnclave(make_model(tmp_path),
                     key_path=str(tmp_path / "tee.key"))
    features = [0.5] * N_FEATURES
    out = tee.infer(StubDetector(), features)
    body = {"score": out["score"], "flagged": out["flagged"]}

    make_model(tmp_path, b"model-weights-v2")
    tee.remeasure()
    assert tee.verify_receipt(out["receipt"], features, body)["ok"] is False


def test_digest_features_is_payload_free():
    a = digest_features([0.1] * N_FEATURES)
    b = digest_features([0.1] * N_FEATURES)
    assert a == b and len(a) == 64
    # rounding matches what gets sealed (metadata granularity only)
    assert digest_features([0.1234567] * N_FEATURES) == \
        digest_features([0.123457] * N_FEATURES)


# -- federated / secure multi-party ------------------------------------------


def test_federated_round_is_exact():
    rng = np.random.default_rng(3)
    deltas = [rng.normal(0, 0.5, size=12).tolist() for _ in range(4)]
    report = federated_round(deltas, shareholders=3, seed=11)

    assert report["parties"] == 4
    assert report["shareholders"] == 3
    assert report["dim"] == 12
    assert report["exact"] is True
    assert report["claims"]["raw_data_egress"] == 0

    agg = np.asarray(recombine(report["aggregate_shares"], k=3)) / report["quantize"]
    want = np.sum(np.asarray(deltas), axis=0)
    assert np.allclose(agg, want, atol=1e-5)

    # each party individually recombines from all k of its shares
    p2 = np.asarray(recombine(report["party_shares"][1], k=3)) / report["quantize"]
    assert np.allclose(p2, np.asarray(deltas[1]), atol=1e-5)


def test_single_shareholder_leaks_nothing():
    deltas = [[0.1, -0.2, 0.3], [0.4, 0.05, -0.15]]
    report = federated_round(deltas, shareholders=3, seed=7)
    quant = report["quantize"]
    secret = np.rint(np.sum(np.asarray(deltas), axis=0) * quant).astype(np.int64)

    # no single share sums to the secret (overwhelming probability; fixed seed)
    for j in range(3):
        partial = np.asarray(report["aggregate_shares"][j], dtype=np.int64)
        assert not np.array_equal(partial, secret)


def test_k_of_k_partial_recombination_rejected():
    deltas = [[0.1, 0.2], [0.3, 0.4]]
    report = federated_round(deltas, shareholders=3, seed=7)
    with pytest.raises(FederatedError):
        recombine(report["aggregate_shares"][:2], k=3)
    with pytest.raises(FederatedError):
        recombine([], k=3)


def test_federated_validation():
    with pytest.raises(FederatedError):
        federated_round([[0.1]])                       # single party
    with pytest.raises(FederatedError):
        federated_round([[0.1], [0.2, 0.3]])           # dim mismatch
    with pytest.raises(FederatedError):
        federated_round([[0.1], [0.2]], shareholders=1)
    with pytest.raises(FederatedError):
        federated_round([[float("inf")], [0.2]])       # non-finite
    with pytest.raises(FederatedError):
        federated_round([[], []])                      # empty deltas


# -- engine integration ------------------------------------------------------


def test_engine_tee_methods(tmp_path):
    from spectra.demo import make_baseline_pcap
    from spectra.pipeline import SpectraEngine

    baseline = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=30)
    engine = SpectraEngine(model_path=str(tmp_path / "m.joblib"), persist=False)
    engine.train_from_pcap(baseline, contamination=0.05)

    quote = engine.tee_attest(nonce="engine-1")
    assert engine.tee_verify(quote, nonce="engine-1")["ok"] is True

    features = [0.1] * N_FEATURES
    sealed = engine.tee_infer(features)
    assert sealed["claims"]["payload_bytes"] == 0
    rep = engine.tee.verify_receipt(
        sealed["receipt"], features,
        {"score": sealed["score"], "flagged": sealed["flagged"]})
    assert rep["ok"] is True

    feed = [[0.1, 0.2], [0.3, 0.4]]
    report = engine.tee_federate(deltas=feed, shareholders=2)
    assert report["exact"] is True
    with pytest.raises(Exception):
        engine.tee_federate(deltas=[[0.1]])            # one party -> error


# -- API ---------------------------------------------------------------------


def test_tee_api(tmp_path, upload_capture):
    from fastapi.testclient import TestClient

    from spectra.api.app import app
    from spectra.demo import make_baseline_pcap

    client = TestClient(app)
    if not client.get("/api/model").json().get("trained", False):
        baseline = make_baseline_pcap(str(tmp_path / "b.pcap"), n_flows=30)
        base_id = upload_capture(client, baseline)["capture_id"]
        assert client.post("/api/model/train",
                           json={"capture_id": base_id,
                                 "contamination": 0.05}).status_code == 200

    quote = client.post("/api/tee/attest", json={"nonce": "api-1"}).json()
    assert quote["measurement"] and quote["signature"]

    good = client.post("/api/tee/verify",
                       json={"quote": quote, "nonce": "api-1"})
    assert good.json()["ok"] is True

    bad = client.post("/api/tee/verify",
                      json={"quote": quote, "measurement": "0" * 64})
    assert bad.json()["ok"] is False

    fed = client.post("/api/tee/federate",
                      json={"deltas": [[0.1, 0.2], [0.3, 0.4]],
                            "shareholders": 3})
    assert fed.status_code == 200 and fed.json()["exact"] is True

    one_party = client.post("/api/tee/federate", json={"deltas": [[0.1]]})
    assert one_party.status_code == 400

    infer = client.post("/api/tee/infer", json={"features": [0.1] * 3})
    assert infer.status_code == 400

    infer = client.post("/api/tee/infer", json={"features": [0.1] * N_FEATURES})
    assert infer.status_code == 200
    assert infer.json()["receipt"]["signature"]
    json.dumps(infer.json())
