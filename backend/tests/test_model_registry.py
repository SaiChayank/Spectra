"""Model registry (Prompt 14): state machine, trust rules, API surface.

Hermetic by construction: every engine here gets its own store and a
``Config`` whose ``data_dir``/``model_path`` point inside ``tmp_path``.
Two engine-level invariants are pinned explicitly:

* a **deployed** engine (``model_path == config.model_path``) is
  registry-authoritative at startup: rows exist -> the ACTIVE artifact only
  (untrained when none or trust checks fail), never a legacy fallback;
* an engine built with a **custom** model_path (the test-suite's isolation
  pattern everywhere else) keeps legacy load semantics - shared-DB registry
  rows never override an explicit artifact choice.
"""

from __future__ import annotations

import os

import numpy as np
import pytest

from spectra.config import Config
from spectra.demo import make_baseline_pcap
from spectra.features.extractor import FEATURE_NAMES, N_FEATURES
from spectra.ml.model import SpectraDetector
from spectra.pipeline import SpectraEngine
from spectra.services.model_registry import (
    ModelRegistryService,
    RegistryConflict,
    RegistryError,
    RegistryNotFound,
    RegistryUnavailable,
    sha256_file,
)
from spectra.store import Store


# -- helpers -------------------------------------------------------------------

def _cfg(tmp_path, name: str = "deployed.joblib") -> Config:
    """A config fully contained in tmp_path (artifacts + deployed copy)."""
    cfg = Config(persist=True)
    cfg.data_dir = str(tmp_path / "data")
    cfg.capture_store_dir = str(tmp_path / "data" / "captures")
    cfg.model_path = str(tmp_path / "data" / name)
    cfg.ensure_dirs()
    return cfg


def _engine(tmp_path, cfg: Config | None = None, **kwargs) -> SpectraEngine:
    cfg = cfg or _cfg(tmp_path)
    store = Store(str(tmp_path / "registry_test.db"))
    return SpectraEngine(config=cfg, store=store, model_path=cfg.model_path,
                         idle_timeout=30.0, **kwargs)


def _baseline(tmp_path, n_flows: int = 40, seed: int = 7) -> str:
    return make_baseline_pcap(str(tmp_path / f"b{seed}_{n_flows}.pcap"),
                              n_flows=n_flows, seed=seed)


# -- train -> register -> validate -> activate ---------------------------------

def test_train_registers_validates_and_activates(tmp_path):
    engine = _engine(tmp_path)
    events: list[dict] = []
    engine.subscribe(events.append)
    assert not engine.detector.is_trained

    info = engine.train_from_pcap(_baseline(tmp_path), contamination=0.05)

    reg = info["registry"]
    assert reg["activated"] is True and reg["status"] == "ACTIVE"

    listing = engine.registry.list()
    assert listing["enabled"] is True and listing["count"] == 1
    active = listing["active"]
    assert active["model_id"] == reg["model_id"]
    assert active["status"] == "ACTIVE"
    assert active["metrics"]["passed"] is True

    # Session side effects (the activation hook).
    assert engine.detector.is_trained
    assert engine.status["model_trained"] is True
    assert engine.detector.contamination == pytest.approx(0.05)
    assert engine.alerts._contamination == pytest.approx(0.05)

    # Deployed copy: model_path bytes == the registered artifact's sha256.
    assert os.path.isfile(engine.model_path)
    assert sha256_file(engine.model_path) == active["artifact_sha256"]

    # The `model` event announces the swap.
    assert any(e.get("type") == "model" for e in events)

    # Audited chain: register -> validate -> activate, plus model.train with
    # the registry identity.
    entries = engine.audit_service.entries(limit=50)["items"]
    kinds = [e["kind"] for e in entries]
    for expected in ("model.train", "model.register", "model.validate",
                     "model.activate"):
        assert expected in kinds, f"missing {expected} in {kinds}"
    train = next(e for e in entries if e["kind"] == "model.train")
    assert train["payload"]["model_id"] == reg["model_id"]
    assert train["payload"]["activated"] is True
    assert train["payload"]["model_sha256"] == active["artifact_sha256"]
    activation = next(e for e in entries if e["kind"] == "model.activate")
    assert activation["payload"]["applied"] is True
    assert activation["payload"]["model_id"] == reg["model_id"]


def test_candidate_only_train_leaves_session_untouched(tmp_path):
    engine = _engine(tmp_path)

    info = engine.train_from_pcap(_baseline(tmp_path), activate=False)

    reg = info["registry"]
    assert reg["activated"] is False and reg["status"] == "CANDIDATE"
    # Session model untouched: untrained in, untrained out; nothing deployed.
    assert engine.detector.is_trained is False
    assert engine.status["model_trained"] is False
    assert not os.path.isfile(engine.model_path)
    assert engine.registry.active() is None

    # Explicit chain afterwards: validate -> activate deploys the candidate.
    model_id = reg["model_id"]
    row = engine.registry.validate(model_id, actor="tester")
    assert row["status"] == "VALIDATED"
    row = engine.registry.activate(model_id, actor="tester")
    assert row["status"] == "ACTIVE" and row["applied"] is True
    assert engine.detector.is_trained
    assert sha256_file(engine.model_path) == row["artifact_sha256"]


def test_single_active_invariant_and_reactivate(tmp_path):
    engine = _engine(tmp_path)
    first = engine.train_from_pcap(_baseline(tmp_path, seed=7),
                                   contamination=0.05)["registry"]["model_id"]
    second = engine.train_from_pcap(_baseline(tmp_path, seed=11, n_flows=60),
                                    contamination=0.05)["registry"]["model_id"]

    # Training B superseded A - exactly one ACTIVE, A is RETIRED.
    assert engine.registry.active()["model_id"] == second
    assert engine.registry.get(first)["status"] == "RETIRED"
    assert engine.store.model_registry_count() == 2

    # Activating the already-active model is a conflict, not a no-op.
    with pytest.raises(RegistryConflict):
        engine.registry.activate(second, actor="tester")

    # RETIRED -> ACTIVE (re-activation) works and swaps the session back.
    row = engine.registry.activate(first, actor="tester")
    assert row["status"] == "ACTIVE"
    assert engine.registry.active()["model_id"] == first
    assert engine.registry.get(second)["status"] == "RETIRED"
    # The re-activated model's own identity is live again (different baseline).
    assert engine.detector.n_train == engine.registry.get(first)["n_train"]


def test_rollback_walks_the_activation_cursor(tmp_path):
    engine = _engine(tmp_path)
    a = engine.train_from_pcap(_baseline(tmp_path, seed=7),
                               contamination=0.05)["registry"]["model_id"]
    n_a = engine.detector.n_train
    b = engine.train_from_pcap(_baseline(tmp_path, seed=11, n_flows=60),
                               contamination=0.05)["registry"]["model_id"]
    n_b = engine.detector.n_train
    assert n_a != n_b  # distinguishable baselines make the swap observable

    back = engine.registry.rollback(actor="analyst")
    assert back["model_id"] == a
    assert engine.detector.n_train == n_a
    entries = engine.audit_service.entries(limit=10)["items"]
    rollback = next(e for e in entries if e["kind"] == "model.rollback")
    assert rollback["payload"]["previous"] == b
    assert rollback["actor"] == "analyst"

    # The cursor moves: rolling back again cycles to B.
    again = engine.registry.rollback(actor="analyst")
    assert again["model_id"] == b
    assert engine.detector.n_train == n_b


def test_rollback_without_previous_model_conflicts(tmp_path):
    cfg = _cfg(tmp_path)
    engine = _engine(tmp_path, cfg)
    # A single trained model: adoption-style one-row registry, no cursor.
    engine.train_from_pcap(_baseline(tmp_path), activate=True)
    with pytest.raises(RegistryConflict, match="no previously activated"):
        engine.registry.rollback(actor="tester")


def test_retire_guards(tmp_path):
    engine = _engine(tmp_path)
    model_id = engine.train_from_pcap(
        _baseline(tmp_path), activate=False)["registry"]["model_id"]
    # Cannot retire the ACTIVE model (there is none yet: candidate only).
    engine.registry.validate(model_id, actor="t")
    engine.registry.activate(model_id, actor="t")
    with pytest.raises(RegistryConflict, match="activate another"):
        engine.registry.retire(model_id, actor="t")

    # Candidate lifecycle: CANDIDATE -> RETIRED is allowed; twice is not.
    other = engine.train_from_pcap(
        _baseline(tmp_path, seed=11, n_flows=60),
        activate=False)["registry"]["model_id"]
    retired = engine.registry.retire(other, actor="t")
    assert retired["status"] == "RETIRED"
    with pytest.raises(RegistryConflict, match="already retired"):
        engine.registry.retire(other, actor="t")


# -- trust rules ---------------------------------------------------------------

def test_validation_gate_fails_tampered_artifact(tmp_path):
    engine = _engine(tmp_path)
    model_id = engine.train_from_pcap(
        _baseline(tmp_path), activate=False)["registry"]["model_id"]
    row = engine.registry.get(model_id)
    path = engine.registry.artifact_path(row)

    # Tamper: byte-level corruption must fail both load and gate.
    with open(path, "ab") as fh:
        fh.write(b"corrupted")

    with pytest.raises(RegistryError, match="sha256 mismatch"):
        engine.registry.trust_load(row)

    failed = engine.registry.validate(model_id, actor="t")
    assert failed["status"] == "FAILED"
    assert "sha256" in (failed["error"] or "")
    assert failed["metrics"]["passed"] is False
    # FAILED is not activatable.
    with pytest.raises(RegistryConflict, match="VALIDATED or RETIRED"):
        engine.registry.activate(model_id, actor="t")


def test_artifact_path_containment(tmp_path):
    cfg = _cfg(tmp_path)
    svc = ModelRegistryService(cfg, store=None)
    with pytest.raises(RegistryError, match="escapes"):
        svc.artifact_path({"model_id": "x", "artifact": "../../evil.joblib"})


def test_feature_schema_mismatch_rejected_on_load(tmp_path):
    det = SpectraDetector(contamination=0.05)
    det.fit(np.random.default_rng(0).normal(size=(50, N_FEATURES)))
    det.feature_names = list(FEATURE_NAMES)[:-1] + ["bogus_feature"]
    path = str(tmp_path / "schema_mismatch.joblib")
    det.save(path)
    with pytest.raises(ValueError, match="feature schema mismatch"):
        SpectraDetector.load(path)


def test_registry_unavailable_without_store(tmp_path):
    cfg = _cfg(tmp_path)
    svc = ModelRegistryService(cfg, store=None)
    assert svc.enabled is False
    assert svc.count() == 0 and svc.active() is None
    listing = svc.list()
    assert listing == {"enabled": False, "count": 0, "offset": 0,
                       "active": None, "items": []}
    for call in (lambda: svc.get("mdl_x"),
                 lambda: svc.validate("mdl_x"),
                 lambda: svc.activate("mdl_x"),
                 lambda: svc.rollback(),
                 lambda: svc.retire("mdl_x")):
        with pytest.raises(RegistryUnavailable):
            call()

    # Legacy train path: no store -> no registry key, session fitted in place.
    engine = SpectraEngine(model_path=str(tmp_path / "m.joblib"), persist=False)
    info = engine.train_from_pcap(_baseline(tmp_path), contamination=0.05)
    assert "registry" not in info
    assert engine.detector.is_trained


# -- startup / adoption --------------------------------------------------------

def test_deployed_engine_loads_active_regardless_of_deployed_file(tmp_path):
    cfg = _cfg(tmp_path)
    engine = _engine(tmp_path, cfg)
    model_id = engine.train_from_pcap(
        _baseline(tmp_path), contamination=0.05)["registry"]["model_id"]
    n_train = engine.detector.n_train

    # Corrupt the deployed copy: a registry-authoritative engine must ignore
    # it and load the ACTIVE artifact from the registry.
    with open(cfg.model_path, "wb") as fh:
        fh.write(b"not a model")
    reloaded = SpectraEngine(config=cfg, store=engine.store,
                             model_path=cfg.model_path, idle_timeout=30.0)
    assert reloaded.detector.is_trained
    assert reloaded.detector.n_train == n_train
    assert reloaded.registry.active()["model_id"] == model_id

    # Rows exist but none is ACTIVE -> untrained (no legacy fallback).
    engine.store.model_registry_set_status(model_id, "RETIRED", retired_at=1.0)
    untrained = SpectraEngine(config=cfg, store=engine.store,
                              model_path=cfg.model_path, idle_timeout=30.0)
    # Re-seed the deployed file with a *valid* model - still not loaded.
    engine.detector.save(cfg.model_path)
    untrained2 = SpectraEngine(config=cfg, store=engine.store,
                               model_path=cfg.model_path, idle_timeout=30.0)
    assert untrained2.registry.count() == 1
    assert untrained2.registry.active() is None
    assert not untrained2.detector.is_trained
    assert not untrained.detector.is_trained


def test_custom_model_path_engine_keeps_legacy_load(tmp_path):
    cfg = _cfg(tmp_path)
    engine = _engine(tmp_path, cfg)          # authoritative: fills the registry
    engine.train_from_pcap(_baseline(tmp_path), activate=True)
    assert engine.registry.active() is not None

    # Explicit artifact override: the registry must not follow this engine.
    override = str(tmp_path / "override.joblib")
    custom = SpectraEngine(config=cfg, store=engine.store, model_path=override,
                           idle_timeout=30.0)
    assert not custom.detector.is_trained  # override file missing -> legacy


def test_adoption_registers_legacy_artifact_once(tmp_path):
    cfg = _cfg(tmp_path)
    store = Store(str(tmp_path / "adopt.db"))

    # A pre-registry deployment: trained model at the deployed path.
    det = SpectraDetector(contamination=0.05)
    det.fit(np.random.default_rng(3).normal(size=(60, N_FEATURES)))
    det.save(cfg.model_path)

    engine = SpectraEngine(config=cfg, store=store, model_path=cfg.model_path,
                           idle_timeout=30.0)
    assert engine.registry.count() == 0       # rows are what adoption adds
    assert engine.detector.is_trained         # legacy load (empty registry)

    row = engine.adopt_model()
    assert row is not None and row["status"] == "ACTIVE"
    assert row["source"].startswith("adopted:")

    entries = engine.audit_service.entries(limit=20)["items"]
    activation = next(e for e in entries if e["kind"] == "model.activate")
    assert activation["payload"].get("adopted") is True
    assert activation["payload"]["model_id"] == row["model_id"]

    # Idempotent: a populated registry never adopts again.
    assert engine.adopt_model() is None
    assert engine.registry.count() == 1

    # ...and the next engine loads the adopted ACTIVE row from the registry.
    reloaded = SpectraEngine(config=cfg, store=store, model_path=cfg.model_path,
                             idle_timeout=30.0)
    assert reloaded.registry.active()["model_id"] == row["model_id"]
    assert reloaded.detector.is_trained


# -- compare / not-found -------------------------------------------------------

def test_compare_and_unknown_model(tmp_path):
    engine = _engine(tmp_path)
    a = engine.train_from_pcap(
        _baseline(tmp_path), activate=False)["registry"]["model_id"]
    b = engine.train_from_pcap(
        _baseline(tmp_path, seed=11, n_flows=60),
        activate=False)["registry"]["model_id"]

    diff = engine.registry.compare(a, b)
    assert diff["a"]["model_id"] == a and diff["b"]["model_id"] == b
    assert diff["diff"]["same_artifact"] is False
    assert diff["diff"]["same_feature_schema"] is True
    assert diff["diff"]["n_train"]["delta"] == 20   # 60 - 40
    assert diff["diff"]["status"] == {"a": "CANDIDATE", "b": "CANDIDATE"}

    with pytest.raises(RegistryNotFound):
        engine.registry.get("mdl_missing")
    with pytest.raises(RegistryNotFound):
        engine.registry.compare(a, "mdl_missing")


# -- API surface ---------------------------------------------------------------

def test_api_registry_reads_and_role_gates(client, viewer_client,
                                           analyst_client):
    # Reads: any signed-in role (router-level `read`).
    for c in (client, viewer_client, analyst_client):
        res = c.get("/api/model/registry")
        assert res.status_code == 200, res.text
        body = res.json()
        assert {"enabled", "count", "active", "items"} <= set(body)

    # Writes: model:manage (ADMIN) only - checked before the handler runs.
    for role_client in (viewer_client, analyst_client):
        assert role_client.post(
            "/api/model/registry/mdl_x/validate").status_code == 403
        assert role_client.post(
            "/api/model/registry/mdl_x/activate").status_code == 403
        assert role_client.post(
            "/api/model/registry/mdl_x/retire").status_code == 403
        assert role_client.post(
            "/api/model/registry/rollback").status_code == 403

    # Unknown model for an admin: 404 from the service, not a 500.
    res = client.post("/api/model/registry/mdl_missing/validate")
    assert res.status_code == 404, res.text
    res = client.get("/api/model/registry/mdl_missing")
    assert res.status_code == 404, res.text


def test_api_registry_candidate_flow_and_rollback(client, upload_capture,
                                                  tmp_path):
    baseline = _baseline(tmp_path, seed=7)
    capture_id = upload_capture(client, baseline)["capture_id"]

    # Candidate-only training through the API.
    res = client.post("/api/model/train", json={
        "capture_id": capture_id, "contamination": 0.05, "activate": False})
    assert res.status_code == 200, res.text
    reg = res.json()["registry"]
    assert reg["activated"] is False and reg["status"] == "CANDIDATE"
    model_id = reg["model_id"]

    res = client.post(f"/api/model/registry/{model_id}/validate")
    assert res.status_code == 200 and res.json()["status"] == "VALIDATED"

    res = client.post(f"/api/model/registry/{model_id}/activate")
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "ACTIVE" and res.json()["applied"] is True

    res = client.get("/api/model/registry")
    assert res.json()["active"]["model_id"] == model_id

    # Second model supersedes it; rollback returns to the first.
    res = client.post("/api/model/train", json={
        "capture_id": capture_id, "contamination": 0.05})
    assert res.status_code == 200, res.text
    reg2 = res.json()["registry"]
    assert reg2["activated"] is True
    assert reg2["model_id"] != model_id

    res = client.post("/api/model/registry/rollback")
    assert res.status_code == 200, res.text
    assert res.json()["model_id"] == model_id

    # Compare the two through the API.
    res = client.get(f"/api/model/registry/compare?a={model_id}"
                     f"&b={reg2['model_id']}")
    assert res.status_code == 200, res.text
    assert res.json()["diff"]["same_artifact"] is False
