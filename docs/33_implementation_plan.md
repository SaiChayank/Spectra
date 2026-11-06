# Implementation Plan — Build-Out and Roadmap
## Spectra

**Version:** 1.0 · **Date:** 2026-09-30 · **Owner:** Engineering (plan is
self-contained; no role names required to execute it)

**What this plan is:** the end-to-end implementation plan for Spectra — from an
empty directory to the v1.0.0 system that exists today (Phases 0–8, recorded
*as-built* so the plan matches reality), then forward-looking phases (9–12)
covering every known gap: the traceability-matrix deltas
(`31_requirements_traceability_matrix.md`), the reconciliation backlog
(`00_reconciliation_note.md` §5), and the research-aligned improvements
(`32_related_research.md` §11).

**How to read it:** each phase lists small, ordered, verifiable steps. Every
step has a **Done-when** — a concrete check, usually a test or CLI command. A
phase is complete when all its steps' Done-when checks pass and its exit gate
is met. Estimate brackets (S/M/L) are relative effort, not durations.

**Ground rules that apply to every phase** (from `16_project_rules_file.md`,
`17_guardrails_context.md`):
- Metadata-only: no code path may decrypt, log, or persist payload. Any step
  touching capture/parse/features must preserve this and add a test for it.
- No fabricated evidence: security/validation docs are populated only with
  real, dated results.
- Persistence-off mode must keep working (detection never blocks on storage).
- Every schema change is a migration in `spectra/db/migrations.py` — nothing
  else may CREATE/ALTER.

---

## PART I — AS-BUILT (Phases 0–8: what was implemented, recorded here as the reference plan)

> These phases are **complete**. They are written here (1) as the reference for
> anyone rebuilding or porting the system, (2) so later phases build on an
> accurate baseline, and (3) because several steps double as regression checks
> you can re-run at any time.

### Phase 0 — Foundation & project scaffolding [S]
**Goal:** a runnable Python package with config, logging, and data model.

1. Create the package skeleton `backend/spectra/` with `pyproject.toml`
   (deps: scapy, numpy, scikit-learn, joblib, fastapi, uvicorn, pydantic) and
   `requirements.txt`.
   - **Done-when:** `pip install -r backend/requirements.txt` succeeds;
     `python -c "import spectra"` works.
2. Central config `config.py`: one `@dataclass Config`, every knob overridable
   via `SPECTRA_*` env vars, `Config.from_env()` with numeric coercion,
   `ensure_dirs()` for data/captures/models paths.
   - **Done-when:** unit test sets `SPECTRA_CONTAMINATION=0.05` and reads it back.
3. Domain records `domain.py`: TypedDicts for wire shapes (`FlowRecord`,
   `DetectionRecord`, `SystemEvent`) + dataclasses for state
   (`CaptureSession`, `ModelVersion`); imports nothing from the rest of the app.
   - **Done-when:** `python -c "from spectra import domain"` works; services
     later type-check against these shapes.
4. Logging setup (`setup_logging`) and version constant.
   - **Done-when:** `python -m spectra.cli status` runs against an uninitialized
     data dir without crashing.

### Phase 1 — Capture layer [M]
**Goal:** pluggable packet sources feeding a common interface.

1. `capture/base.py`: `CaptureSource` ABC + `CaptureError`.
   - **Done-when:** a fake source in tests can drive the pipeline without scapy.
2. `capture/pcap_file.py`: `PcapFileSource` using `scapy.utils.PcapReader`
   (streaming, never whole-file in memory).
   - **Done-when:** `test_end_to_end.py` scans `demo_pcaps/suspicious.pcap`
     and reports packets > 0.
3. `capture/live.py`: live NIC capture via scapy `AsyncSniffer`; friendly
   interface metadata (name/description/ip/mac, active adapter first); clear
   error when the platform lacks capture drivers (Npcap).
   - **Done-when:** `GET /api/interfaces` lists adapters; live start/stop round-
     trip works in the acceptance runner's `live` group (skips to WARN when
     Npcap is absent).
4. `capture/storage.py`: managed import store — basename-only filenames,
   `.pcap`/`.pcapng` extension check, magic-number signature check (5 magics),
   streamed size cap, **generated (uuid) stored names**, path re-derivation
   that rejects anything that is not a bare basename.
   - **Done-when:** `test_capture_resources.py` covers import validation,
     lifecycle, path-traversal rejection, delete safety.
5. Synthetic traffic generator `demo.py`: benign-baseline and
   suspicious-mixture PCAP generators with hand-crafted TLS ClientHello /
   ServerHello bytes.
   - **Done-when:** generated PCAPs parse; the suspicious mix contains ≥4
     beacon flows with different cadences.

### Phase 2 — Flow tracking & metadata parsing [M]
**Goal:** conversations + TLS/QUIC handshake metadata, payload never retained.

1. `parse/flow.py`: 5-tuple bidirectional `FlowTracker`; per-direction packet
   records (ts, size, direction, flags); idle timeout, max-packets, max-
   lifetime eviction; `Flow.record()` → dict.
   - **Done-when:** `test_flow.py` passes, including direction/byte accounting.
2. `parse/tls.py`: streaming TLS record/handshake parser (ClientHello,
   ServerHello, extensions, ALPN, version negotiation incl. TLS 1.3 synthetic
   fields), producing `TlsMetadata` with **JA3 and JA4** fingerprints.
   - **Done-when:** `test_tls.py` passes on hand-crafted handshakes; malformed
     frames never raise (fuzz cases → skipped parse, not crash).
3. `parse/quic.py`: QUIC Initial-packet path; CRYPTO frames feed the same TLS
   metadata pipeline.
   - **Done-when:** `test_quic.py` passes with 400-path malformed inputs.
4. **Privacy test:** payload bytes appear in parser memory only as framing
   cursors; assert no payload material reaches `Flow.record()` output or
   feature vectors.
   - **Done-when:** dedicated assertions in `test_flow.py`/`test_tls.py` pass
     (this is the NFR-1 evidence).
5. BPF-style filter language `filters.py` (pure Python; no libpcap).
   - **Done-when:** `test_filters.py` passes; `?filter=` works on API queries
     later.

### Phase 3 — Features & model [M]
**Goal:** fixed-length metadata vector + anomaly model with explanations.

1. `features/extractor.py`: the **39-feature vector** (timing/volume, IAT stats
   incl. MAD for beacon regularity, TCP flags, entropy, ports, TLS metadata) —
   never payload. Pin the schema: `FEATURE_SCHEMA_VERSION` + SHA-256
   `feature_schema_digest()` over ordered names.
   - **Done-when:** `N_FEATURES == 39`; digest changes if any name changes
     (test asserts the digest is embedded in saved models).
2. `ml/model.py` `SpectraDetector`: `StandardScaler` + `IsolationForest`
   (300 trees, contamination 0.02, seed 42); threshold at the (1−contamination)
   percentile of training scores; 0–100 score = percentile of the training
   distribution; σ-explanations per feature (robust z) for every detection.
   - **Done-when:** `test_model.py` trains on ≥10 flows, flags injected
     outliers, explanations are sorted by |z|.
3. Persistence: `save()`/`load()` via joblib; **load rejects artifacts whose
   schema digest differs**; PSI drift baseline (40 bins/feature) captured at
   fit time.
   - **Done-when:** cross-schema load raises; `model.info()` reports trained_at,
     n_train, contamination, threshold, version.
4. Inference fast path `_build_fast()`: pre-convert tree node arrays and walk
   them for single-row scoring (mirrors sklearn bit-for-bit), with automatic
   fallback to `decision_function` when prerequisites are missing; caches
   invalidated by `fit()`, excluded from `save()`.
   - **Done-when:** `test_model.py::test_fast_raw_matches_sklearn` passes with
     exact `==` on probe vectors; per-call p50 ≤ 0.5 ms (acceptance: 0.269 ms).
5. Bio/edge sidecars trained from the same baseline: `SelfModel` (median/MAD),
   `TimingSNN`, `MicroDetector` (12-feature subset).
   - **Done-when:** `spectra train` produces sidecars; `test_bio.py`,
     `test_edge_native.py` pass.

### Phase 4 — Persistence layer [M]
**Goal:** durable, migration-driven, bounded storage that never blocks detection.

1. `db/connection.py`: SQLite (WAL) wrapper with lock, transactions, FK toggling.
2. `db/migrations.py`: migration runner (idempotent, atomic, per-migration
   transaction, `schema_migrations` bookkeeping) + migrations:
   - v1 baseline (captures, flows, model_runs, audit_log + indexes) written
     all-`IF NOT EXISTS` so legacy DBs are adopted, not broken;
   - v2 flows rebuild with `capture_id` FK (copy → **verify row counts** →
     swap);
   - v3 events table + retention indexes;
   - v4 capture-resource columns (status lifecycle, generated names, hashes);
   - v5 users + sessions (scrypt hashes; sessions keyed by token **hash**);
   - v6 incidents + incident_notes.
   - **Done-when:** `test_migrations.py` covers all 6, including the
     legacy-DB adoption path and the v2 rebuild integrity check.
3. `db/repositories.py`: typed repositories for each table.
   - **Done-when:** `test_repositories.py` passes.
4. `db/batch.py` + `store.py`: batched writes (`SPECTRA_DB_BATCH_SIZE`,
   `SPECTRA_DB_FLUSH_INTERVAL`), row caps (`max_history_rows`,
   `event_max_rows`), store degradation to memory-only when persistence fails.
   - **Done-when:** `test_store.py` passes; engine still detects with
     persistence disabled.
5. `db/retention.py`: age-based policies per table (default **off**), row caps
   always on; audit log exempt (hash chain).
   - **Done-when:** retention unit tests; audit rows survive full retention pass.

### Phase 5 — Streaming runtime & services [L]
**Goal:** bounded, observable pipeline + a clean service layer.

1. `streaming.py`: `BoundedBuffer` with explicit policies — packet queue
   `drop_newest`, flow/publish queues `drop_oldest` — non-blocking puts,
   EOF draining, full telemetry (offered/accepted/dropped/max-depth).
2. Stage threads: capture → flow → inference → publish; LRU flow-table cap
   (`max_active_flows`), per-flow packet/memory limits.
   - **Done-when:** `test_streaming.py` passes incl. overload behavior and
     shutdown drain; `status["pipeline"]` exposes per-stage policy + drops.
3. Service decomposition (`services/`), acyclic wiring (leaf → root):
   `EventBus`, `FailureTracker` → `AuditService` → `AlertService` →
   `ModelService`; `CorrelationService` → `DetectionService` →
   `CaptureService` → `CaptureResourceService` → `TrainingService` →
   `SystemService`; plus `AuthService`, `IncidentService`.
4. `pipeline.py` `SpectraEngine`: composition root; store/detector as single
   shared points with re-binding seams for tests; historical attribute surface
   preserved via properties.
   - **Done-when:** `test_services.py` passes; CLI + API + tests all drive the
     same engine.

### Phase 6 — Strategic modules (M1–M8) [L]
**Goal:** the eight modules, in dependency order, each annotating flows but
never gating detection.

1. **M1 PQC** (`modules/pqc/`): cipher registry (classical/hybrid/PQ), scanner
   over TLS metadata, sector classifier (`sectors.py`; healthcare 1.0,
   fintech 0.9, smart-city 0.7), endpoint inventory, HNDL bulk-transfer
   screening, roadmap generator.
   - **Done-when:** `test_pqc.py` passes; `spectra pqc` prints readiness + roadmap.
2. **M5 Audit** (build before modules that emit audit events):
   Schnorr keypair (auto-minted, gitignored), hash-chained append-only log,
   Merkle leaves per session flow, checkpoints + inclusion proofs, compliance
   certificates.
   - **Done-when:** `test_audit.py` + `test_integrity.py` (tamper → verify fails).
3. **M7 Correlation** (`modules/corr/`): host/IP/SNI graph with sector tags,
   weighted edges, hydrate-from-store, cascade/blast-radius, kill-chain paths.
   - **Done-when:** `test_corr.py` passes; graph hydrates from persisted flows.
4. **M4 Twin** (`modules/twin/`): topology from graph, seeded deterministic
   attack simulation, playbook library + validation, z-score shadow comparator.
   - **Done-when:** `test_twin.py` passes; `spectra twin simulate` is
     reproducible for a fixed seed.
5. **M6 Bio** (`modules/bio/`): self-model affinity, 6 danger signals →
   0–3 response bands, SNN timing percentile, 5-agent swarm, memory cells.
   Annotation-only (cannot create detections) — enforced in
   `DetectionService`.
   - **Done-when:** `test_bio.py` passes; a swarm/danger flag alone never
     produces a detection row.
6. **M3 Adversarial** (`modules/adv/`): score-boundary attack, batch mode,
   evasion watch (near-miss rate on a score window), robustness report; drift
   vs evasion correlation through the PSI baseline.
   - **Done-when:** `test_adv.py` passes; robustness run yields evasion
     success rate + boundary distance.
7. **M2 TEE** (`modules/tee/`): model/feature digests, nonce-bound Schnorr
   attestation quotes, sealed inference receipts, Shamir k-of-k federated
   reconstruction.
   - **Done-when:** `test_tee.py` passes incl. malformed-input 400s; quote
     verification fails on nonce reuse.
8. **M8 Edge** (`modules/edge/`): 12-feature `MicroDetector`, `EdgeSystem`
   deploy/report simulation, slice classifier + per-slice policy temperament,
   NTN link profiles (RTT-based timing descaling).
   - **Done-when:** `test_edge.py`, `test_edge_native.py` pass; micro-detector
     p99 within the 10 ms budget (measured p50 0.0098 ms).

### Phase 7 — API, auth, CLI [L]
**Goal:** every capability reachable over REST/WS/CLI, behind default-deny auth.

1. Auth internals (`auth/passwords.py`): scrypt (n=16384, r=8, p=1, per-user
   salt), self-describing encodings, policy check on *set* only,
   `verify_dummy` for the unknown-user path.
2. `services/auth.py`: bootstrap (first admin from `SPECTRA_ADMIN_PASSWORD`
   or mode-600 generated file), login (no user enumeration — identical 401 +
   dummy verify), sessions (256-bit token, stored as SHA-256, HttpOnly
   SameSite=Lax cookie, Bearer/`?token=` accepted), absolute TTL, revoke-on-
   password-change, delete-cascades.
   - **Done-when:** `test_auth.py` passes: login success/failure, expiry,
     revocation, role matrices.
3. `api/security.py`: `auth_gate` default-deny middleware (public: `GET
   /api/health`, `POST /api/auth/login`), `require(permission)` dependency,
   WS principal resolution + mid-stream revalidation (close 4401 on
   logout/expiry).
4. `api/app.py` + 15 routers (core, captures, model, history, graph, pqc,
   audit, twin, bio, tee, edge, auth, users, incidents): route groups mirror
   the module matrix; every route declares its permission; uploads only via
   `POST /api/captures` (never a server path); duplicate content → 409;
   WebSocket `/ws/events` with per-client bounded queue (drop-oldest).
   - **Done-when:** `test_api.py` passes incl. 400-paths; default-deny route
     sweep test; WS auth test.
5. `api/runtime.py`: one engine per process; `cli.py` (12 commands: demo,
   train, scan, status, serve, pqc, adversarial, audit, twin, bio, tee, edge).
   - **Done-when:** `spectra demo --train && spectra scan … && spectra serve`
     happy path works end to end.
6. Incidents workflow (`services/incidents.py`, migration v6): OPEN →
   ACKNOWLEDGED → RESOLVED + analyst notes; optional FK to the flagged flow
   (`ON DELETE SET NULL`).
   - **Done-when:** `test_incidents.py` passes (lifecycle + RBAC).

### Phase 8 — Dashboard, tests, acceptance, release [L]
**Goal:** role-aware UI, full test coverage, reproducible acceptance, v1.0.0.

1. React 19 + TS + Vite dashboard: login/session restore, role gates from
   `/api/auth/me` permissions, Overview (stat cards, timeline, flows,
   detections), Capture panel (multipart import + lifecycle), Bio/TEE/Edge
   panels, WS live updates (`useEvents`), 3 s polling fallback, typed API
   client (`lib/api.ts`), 401-anywhere → sign-out.
   - **Done-when:** `npm run build` clean; manual walkthrough of every panel
     (recorded in the acceptance report §6).
2. pytest suite (~7.1k LOC, 27 files): units for parse/features/model/filters,
   integration for streaming/db/services/API/auth/RBAC, e2e capture runs,
   negative-path 400 sweeps per module.
   - **Done-when:** `python -m pytest tests -q` green (338 passing at v1.0.0).
3. `scripts/acceptance.py`: signs in as admin, exercises every route group +
   WS, 9 negative probes (must 4xx, never 5xx), 12-command CLI sweep,
   Npcap-gated live group; PASS/WARN/FAIL table; exit 1 on any FAIL.
   - **Done-when:** 102/102 PASS against a local server; `--skip-*` variants
     work.
4. Release hygiene: `.gitignore` for `backend/models/`, `backend/data/`,
   TEE key; no secrets tracked (verify `git check-ignore`); version tag
   `v1.0.0`; acceptance report written with real results only.
   - **Done-when:** zero `.key/.db/.joblib` tracked; acceptance report
     reproducible from the repo.

**Phase gate (Part I complete):** all tests green · acceptance 102/102 ·
dashboard walkthrough recorded · docs (`00`, `31`, `32`, `acceptance-report`)
in place.

---

## PART II — FORWARD PLAN (Phases 9–12: closing known gaps, then hardening and scale)

### Phase 9 — Gap closure (traceability + research backlog top items) [L]
**Goal:** fix every known requirement delta; land the highest-value
research-backed improvements. Ordered by dependency, then value.

#### 9A. Correlation: time-windowed edges (closes FR-2.2)
1. Add `first_ts`/`last_ts` + `flow_ids` to graph edges on `observe()`
   (from the flow record); extend `CorrelationGraph.observe` and `_edge`.
   - **Done-when:** edges carry timestamps; unit test asserts multi-day edges
     are distinguishable.
2. Add `window_s` parameter (default `None` = current behavior) to `cascade`,
   `_kill_chain`, `shortest_path`, and the API layer
   (`GET /api/graph/cascade?window_s=3600`); traversal skips edges whose
   contact windows fall outside the requested window.
   - **Done-when:** `test_corr.py` gains a case where a wide window links two
     sectors and a narrow one does not; API 400 on `window_s <= 0`.
3. Surface the chosen window in the cascade response so the UI can label it.
   - **Done-when:** response includes `window_s`; dashboard correlation view
     shows it.
4. Migration: none (in-memory graph). Persistence note: hydrated edges get
   windows by re-observing persisted flow rows — already timestamped.
   - **Done-when:** hydrate reproduces windows from stored flows (test).

#### 9B. Adversarial retraining via the twin shadow harness (FR-4.1 "continuous" + research §4.1)
1. Add `TrainingService.augmented_fit(flows, attacked: np.ndarray | None)`:
   concatenates attacked vectors (label-preserving? no — *benign-bounded*
   attack only: reuse `modules/adv/evasion.attack_batch` on benign vectors to
   harden the boundary) with the benign baseline before `fit`.
   - **Done-when:** unit test: retrained model's evasion success rate on the
     same attack set drops vs the base model.
2. Orchestrate: `POST /api/model/harden` (ADMIN, `model:manage`): generate
   attack set → shadow-compare candidate vs incumbent via
   `modules/twin/shadow.run_shadow` → *report only*; promotion stays a
   separate explicit step (`model registry` is Phase 11B).
   - **Done-when:** robustness regression check blocks recommendation when
     candidate is worse (response includes `promote: false` + reason).
3. Audit-chain every harden/shadow/promotion event (kinds: `model.harden`,
   `model.shadow`, `model.promote`).
   - **Done-when:** `test_audit.py` verifies the new kinds chain correctly.
4. Optional scheduler: `SPECTRA_HARDEN_INTERVAL_H` (default off) to run 9B
   periodically — this is the "continuous" behavior, opt-in.
   - **Done-when:** interval disabled by default; enabling it logs the run
     and respects the audit trail.

#### 9C. Synthetic-benign augmentation at train time (research §10.1 — attacks the documented FP/OOD failure)
1. Extend `demo.py` generators into a parameterized benign-diversity library
   (protocols × cadences × burst profiles) — generator output stays synthetic.
   - **Done-when:** generator produces ≥5 distinct benign profiles; profiles
     are individually parseable.
2. `spectra train --augment N` and `POST /api/model/train?augment=N`: mix N
   synthetic benign flows into the real baseline before fitting.
   - **Done-when:** `test_model.py` case: baseline + augmentation reduces
     false flags on a held-out benign set vs baseline alone.
3. Record augmentation provenance in `model_runs` (metrics JSON gains
   `augmented: N`) and in the model card template.
   - **Done-when:** `GET /api/history/model-runs` shows the augmentation count.

#### 9D. Per-host-pair beaconing aggregation (research §1.5)
1. In `CorrelationService`, maintain a rolling per-(src, dst-or-SNI) IAT
   window (bounded deque); compute mean/std regularity per pair.
2. Expose as a bio danger signal (cadence signal upgrades from per-flow to
   per-pair when the pair history exists) and as a graph edge weight.
   - **Done-when:** `test_bio.py` case: a jittered 4-flow beacon pair scores
     higher than a per-flow view; `test_corr.py` asserts the edge weight
     reflects regularity.
3. Config: `SPECTRA_PAIR_WINDOW_FLOWS` (default 32).
   - **Done-when:** env override changes behavior in a unit test.

#### 9E. Rolling PSI drift baseline (research §1.6)
1. Keep a second, time-decayed feature histogram set alongside the training
   baseline; update it from scored flows (bounded, sampled).
2. `GET /api/model/drift` reports both `psi_vs_train` and `psi_vs_recent`;
   `AlertService` alerts on the *recent* comparison so slow drift is caught.
   - **Done-when:** unit test: a slow monotonic feature shift trips
     `psi_vs_recent` before `psi_vs_train`.

#### 9F. Audit-key hardening (research §6.1 — key evolution / KMS seam)
1. Introduce `AuditKeyProvider` (protocol): `current()` → (secret, pubkey),
   `rotate()`; ship a file-backed provider (current behavior) +
   `epoch` field in entries.
2. On rotation, entries reference the epoch; verification accepts epochs
   present in the log's key-history table (new migration v7:
   `audit_key_epochs(epoch, pubkey, created_at)`).
   - **Done-when:** `test_integrity.py` case: verification passes across a
     rotation; old-entry forgery with the current key fails.
3. KMS/HSM integration point documented (no cloud dependency in v1).
   - **Done-when:** provider swap is one class; doc notes the contract.

#### 9G. Federated dropout tolerance (research §3.2)
1. Upgrade k-of-k to k-of-n Shamir in `modules/tee/federated.py`; add share
   verification (public commitments per share).
   - **Done-when:** recombination succeeds with n−1 of n shares; tampered
     share is rejected.
2. `POST /api/tee/federate` accepts participant dropout in the middle of the
   session.
   - **Done-when:** test simulates a dropped participant; aggregate still
     reconstructed.

#### 9H. Twin topology staleness + JA4+ micro-signals (research §5.1, §1.7 — cheap honesty/features)
1. `/api/twin/topology` gains `hydrated_at` + `flow_lag` (newest persisted flow
   ts minus hydrate cursor); UI renders a staleness badge.
   - **Done-when:** test asserts lag grows without re-hydrate; UI copy updated.
2. Add JA4S (server fingerprint) and JA4L (latency bytes) extraction to
   `parse/tls.py` where the handshake provides them; store on flow rows
   (migration v8: nullable columns), expose in API + graph node attributes.
   - **Done-when:** parser tests cover the new fields; old DBs migrate in
     place with nulls.

**Phase 9 exit gate:** traceability matrix re-run: FR-2.2 → ✅; FR-4.1 → ✅
(scheduled mode); all new tests green; `acceptance.py` extended with a
`windowed-cascade` group + harden train path; README count rows updated.

### Phase 10 — Security hardening & evidence generation [L]
**Goal:** turn the security *templates* into real evidence and close the
planning-doc control deltas that matter at v1 scale.

1. **SAST in CI** (per `09_static…` doc): Semgrep + Bandit + pip-audit +
   gitleaks on every PR; custom rule: flag any new code path touching packet
   payload beyond framing (`parse/` only).
   - **Done-when:** CI config in repo; a deliberately payload-touching patch
     is blocked by the custom rule (test the rule itself).
2. **DAST**: run Schemathesis against `/openapi.json` + ZAP baseline on a
   staging server; include the metadata-only runtime probe (attempt payload
   retrieval via every endpoint — must be structurally impossible).
   - **Done-when:** report populated in `19_dast_report.md` with real, dated
     results; zero Critical/High open.
3. **SCA** (per `20_sca_report.md`): pip-audit + Dependabot-style pin review;
   license allowlist check.
   - **Done-when:** report populated; baseline green.
4. **Model evaluation & model card** (per `10_…`, `12_model_card.md`):
   two-baseline evaluation (synthetic + real capture, mirroring acceptance
   §6), precision/recall on the labeled demo set, cross-sector consistency
   table from `sectors.py` domain mixes, adversarial robustness numbers from
   9B.
   - **Done-when:** `10_model_evaluation_validation_report.md` populated with
     real results; `12_model_card.md` filled and versioned.
5. **Threat-model refresh** for the new surfaces (windowed correlation,
   hardening endpoint, key epochs): update `05_threat_modeling_document.md`
   trust-boundary notes; add ADRs (supersede ADR-002's software-analog note
   with the actual protocol-shape decision; ADR-005: audit key epochs).
   - **Done-when:** ADR log has entries 005+; threat model re-dated.
6. **Session/auth polish**: optional TOTP second factor for ADMIN (stdlib-
   implementable; stored as scrypt'd secret), account lockout with
   exponential backoff, `SPECTRA_SESSION_COOKIE_SECURE=True` behind TLS doc.
   - **Done-when:** `test_auth.py` extensions pass; lockout tested; doc
     updated. *(Deferred items from Planning Doc reconciliation — kept opt-in.)*
7. **Retention defaults proposal**: run the governance decision that sets
   `SPECTRA_*_RETENTION_DAYS` defaults per Data Governance (30-day style) for
   shipping profiles; keep default-off for the OSS/local profile, document
   both.
   - **Done-when:** config gains a `profile` note; runbook documents the
     shipping default.

**Phase 10 exit gate:** SAST/DAST/SCA evidence docs populated with real runs ·
model card + evaluation report signed internally · no Critical/High open ·
lockout/2FA tests green.

### Phase 11 — Operational readiness [M]
**Goal:** make it operable: packaging, observability, backup, runbook reality.

1. **Packaging**: publish `spectra` wheel (pyproject already defines the
   entry point); `spectra-cli` smoke test in CI; frontend production build
   served by the API (static mount) for single-process deployment.
   - **Done-when:** `pip install spectra && spectra serve` works from a clean
     venv; dashboard reachable at the API origin.
2. **Observability** (per `29_monitoring…`): `/api/metrics` gains a
   Prometheus text-format exposition (queue depths, drops, inference latency
   histograms, drift PSI, bio verdict counts); log scrubbing middleware test
   (no sensitive fields in logs — the SAST custom rule checks source, this
   checks runtime).
   - **Done-when:** metrics scrape verified with a local Prometheus; scrubbing
     test green.
3. **Backup/DR reality** (per `27_disaster_recovery_plan.md`): document +
   script `sqlite3 .backup` snapshotting, model artifact versioning, audit
   key escrow procedure; restore drill script.
   - **Done-when:** restore drill runs in CI on a fixture DB; RTO/RPO
     placeholders in `27_…` resolved with measured values (tiny scale, honest
     numbers).
4. **Runbook population** (per `30_operations_runbook.md`): real commands for
   capture failure, DB lock, disk-full, model-corrupt (load falls back),
   session-storm; on-call checklist.
   - **Done-when:** runbook steps verified by executing each once on a
     staging instance.
5. **Ops docs sync**: mark `00_reconciliation_note.md` ledger rows KEPT as the
   phases land (change control below).
   - **Done-when:** ledger updated in the same PRs as the code.

### Phase 12 — Scale-out roadmap (planning-doc alignment, behind flags) [L]
**Goal:** the deferred architecture from the planning docs, delivered as
opt-in profiles rather than rewrites. Each item is a *separate* mini-phase;
none starts before Phase 10's evidence exists.

#### 12A. Export pipeline / SIEM delivery (Security Payload doc)
1. Webhook emitter on `EventBus` (bounded queue, HMAC-signed payloads per
   `25_security_payload.md` schema; retry with exponential backoff, max 24 h).
   - **Done-when:** schema-validated payloads; delivery retry tested against a
     fixture sink; payload structurally excludes payload fields (test).
2. Config: `SPECTRA_WEBHOOK_URL`, `SPECTRA_WEBHOOK_SECRET`; per-tenant
   confidence threshold left to the multi-tenant phase.
   - **Done-when:** integration test delivers a detection end-to-end.

#### 12B. Model registry & staged rollout (Deployment/Rollback doc)
1. Migration v9: `model_registry(model_version, trained_at, path, status
   [staging|canary|production|retired], metrics_json, trained_by, augment)`;
   registry-backed `activate`/`rollback` (permission `model:manage`; audit-
   chained).
   - **Done-when:** rollback returns to last-known-good; audit entries exist;
     `GET /api/model` reports registry status.
2. Shadow-mode gate becomes mandatory for registry promotion (9B output is
   the evidence).
   - **Done-when:** promotion without a shadow result is rejected (400).

#### 12C. Multi-tenant profile (Threat-model TB-4; deferred at v1)
1. Migration v10: `tenants` + `tenant_id` on flows/captures/incidents (null =
   default tenant for backward compat); row-level scoping in repositories;
   tenant derived from the session user, never from client params.
   - **Done-when:** cross-tenant read test fails closed; default tenant
     behavior unchanged for existing DBs.
2. Per-tenant API keys (hashed) alongside interactive users; rate limits per
   key.
   - **Done-when:** rate-limit test; key revocation cascades.
3. This phase re-opens the DPIA (`06_data_privacy_impact_assessment.md`) —
   required before processing anything that is not synthetic.
   - **Done-when:** DPIA re-dated with the multi-tenant delta.

#### 12D. Hardware TEE path (ADR-002 delivery)
1. Keep the current protocol shape (9F-style (measurement ‖ digest ‖ nonce)
   binding); add an `AttestationProvider` protocol: `software` (today) vs
   `sgx|sev_snp` (vendor SDK behind an optional extra).
   - **Done-when:** quote verification passes through either provider with the
     same API contract; fallback flags `trust_level: reduced` when hardware is
     absent (never silently equivalent).
2. Constant-time scoring assessment for the fast path (side-channel note from
   research §3.3) — either document the residual risk or gate hardware mode to
   a batch-scoring path.
   - **Done-when:** TEE threat-model section updated; decision recorded as an
     ADR.

#### 12E. Distribution / clustering (Kafka-replacement at scale)
1. First step is *not* Kafka: extract the capture stage into a separate
   process feeding the existing ingest queue over the loopback/local socket
   with the same BoundedBuffer framing.
   - **Done-when:** two-process capture demo with counted drops; no detection
     semantic change.
2. Only if multi-node is actually required: swap the local socket for a queue
   (Redis Streams or Kafka) behind the same interface; the planning docs'
   Kafka/Pulsar choice is then a config profile, not a rewrite.
   - **Done-when:** queue profile passes the same streaming tests; feature
     parity documented.

**Phase 12 exit gate (per mini-phase):** flag-off behavior identical to
Phase 11; each profile ships with tests + a filled section in the matching
planning doc (reconciliation ledger row flipped to KEPT/ANALOG).

---

## Gates, risk register, change control

### Exit criteria summary
| Phase | Gate |
|---|---|
| 0–8 (done) | 338 tests green · acceptance 102/102 · walkthrough recorded |
| 9 | FR-2.2 ✅ · FR-4.1 scheduled mode ✅ · new tests + acceptance groups green |
| 10 | SAST/DAST/SCA + model evidence real & dated · no Critical/High open |
| 11 | Wheel install path · Prometheus scrape · restore drill in CI · runbook executed |
| 12.* | Flag-off parity · planning-doc ledger rows updated · DPIA/ADR where required |

### Risk register (top items)
| Risk | Phase | Mitigation |
|---|---|---|
| Windowed cascade perf on large graphs | 9A | bounded window + edge pruning; load test with 50k-flow hydrate (existing limit) |
| Augmented training skews scores | 9C | augmentation count capped & recorded; shadow-compare before recommending |
| Retraining regression | 9B | shadow gate is report-only until 12B makes it mandatory; audit trail on every run |
| Key rotation breaks old entries | 9F | epoch table + cross-epoch verification tests before shipping rotation |
| Multi-tenant leaks | 12C | tenant from session only; fail-closed repository scoping; DPIA refresh |
| Hardware TEE SDK churn | 12D | provider protocol isolates vendor SDKs; software provider remains the default |
| Scope creep in "scale-out" | 12 | each mini-phase independently shippable; none starts before Phase 10 evidence |

### Change control
- Schema changes only via migrations; every migration ships with its test.
- New routes declare a permission and appear in the default-deny sweep test.
- New audit event kinds must be verified by `test_integrity.py`.
- Docs rule: when a phase changes a decision recorded in
  `00_reconciliation_note.md` or a planning doc, update the ledger row in the
  same change set.
- Evidence documents (`10_`, `12_`, `19_`, `20_sca`, VAPT) are populated only
  with real, dated runs — never pre-filled.
