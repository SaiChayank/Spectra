# Model registry (Prompt 14) — design notes

**Status: implemented.** Schema migration 10 (`model_registry` + the partial
single-ACTIVE index), `spectra.services.model_registry`,
`/api/model/registry*` routes, train → register/validate/activate, startup
ACTIVE load (deployed engines only; custom `model_path` engines keep legacy
semantics so test fixtures stay isolated), app-import adoption. Pinned by
`backend/tests/test_model_registry.py`.

## State machine
CANDIDATE -> VALIDATED -> ACTIVE -> RETIRED (superseded/retired)
CANDIDATE -> FAILED (validation gate)          RETIRED -> ACTIVE (re-activate/rollback)

* single ACTIVE enforced by partial unique index `models(status) WHERE status='ACTIVE'`
  plus one `BEGIN IMMEDIATE` transaction (retire old + promote new) = atomic.
* `last_activated_at` on each row is the rollback cursor:
  previous = RETIRED row with greatest last_activated_at < current's.

## Trust rules (only locally generated/verified artifacts load)
* artifacts live in `<data_dir>/model_artifacts/<model_id>.joblib`, immutable;
  `artifact_sha256` recorded at registration.
* every load (startup, activation, validation) = path containment + sha256 match
  + `SpectraDetector.load` which now rejects a feature-schema mismatch
  (`feature_names` digest vs current `FEATURE_NAMES`).
* startup: registry rows exist -> ACTIVE row's artifact only (untrained if none
  active or the artifact fails checks); registry empty -> legacy model_path load.

## Train semantics
* store present: fit a *scratch* detector, save artifact, register CANDIDATE.
  Session detector untouched unless `activate=True` (explicit, audited:
  register -> validate -> activate). No silent auto-activation.
* store absent (persist=False): legacy behavior (fit live detector + write
  model_path) — the lifecycle is a persistence feature.
* activation swaps the session detector, syncs engine.model_path +
  config.model_path (deployed copy), re-measures TEE, updates alert watch
  contamination, emits the `model` event, audits `model.activate`/`model.rollback`.

## Ops
register (train) / validate / activate / rollback / retire / inspect / compare
API: GET /api/model/registry, /registry/compare, /registry/{id};
     POST /registry/{id}/{validate,activate,retire}, /registry/rollback.
Writes require `model:manage` (ADMIN); reads `read`.

## Adoption
`app` import: if registry has no rows and model_path loads -> register+validate+
activate it as the first ACTIVE (audited; `adopted: true`). Gives existing
deployments an explicit active model without re-training.
