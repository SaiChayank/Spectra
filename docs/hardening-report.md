# Spectra — Engineering Hardening Report

**Version:** 1.0.0 · **Date:** 2026-10-03
**Predecessor:** `docs/acceptance-report.md` (Tracks 3 + 4, tag v1.0.0)
**Base commit:** `2f15ebb` (frontend rebuild) · **Scope:** fix-only hardening
pass over backend + frontend — authentication, files, API, ML, runtime,
database, advanced modules, performance. **No new features.**

Reproduce everything below:

```bash
cd backend
python -m pytest tests -q                 # 496 tests
python -m spectra.cli serve --port 8787   # API must be running for the runner
SPECTRA_ADMIN_PASSWORD=… python scripts/acceptance.py   # 156 checks
python scripts/perf.py [--quick] [--json out.json]       # performance (§4)
cd ../frontend && npm run build           # tsc && vite build
```

---

## 1. Method

1. **Inspect first.** Every item from the review was traced to the code path
   that could actually realise it before anything changed; items that turned
   out to be unreachable (or already defended) were left alone.
2. **Smallest safe change.** Each fix is local to the guard it adds. No
   refactor, no new dependency, no architecture change.
3. **Fixed, not documented away.** Every fix landed with a regression test —
   28 new tests in `backend/tests/test_hardening.py` (8 sections) plus one
   flaky-test repair in `tests/test_model_registry.py`. Nothing is skipped,
   xfailed, loosened or removed.
4. **Three independent evidence layers:** pytest (behaviour),
   `scripts/acceptance.py` (a *running* server + WebSocket + CLI + live NIC
   capture), `scripts/perf.py` (measured throughput/latency, including a
   back-to-back A/B against the pre-hardening tree — §4.2).

**Diff:** 35 modified files + 3 new (`scripts/perf.py`,
`spectra/ml/integrity.py`, `tests/test_hardening.py`) — 1 030 insertions,
151 deletions.

## 2. Findings fixed

### 2.1 Authentication & sessions

| Finding | Fix | Test |
|---|---|---|
| Password hashes used a legacy scrypt work factor | N=2¹⁶ for new hashes; `password_needs_rehash` upgrades a legacy hash on the next successful login | `test_password_hash_uses_current_scrypt_work_factor`, `test_legacy_password_hash_is_upgraded_on_login` |
| No rate limiting on login (online guessing) | `LoginThrottle`: 10 failures/60 s per *(ip, username)* + 40/60 s per ip, sliding window, bounded table → **429 + `Retry-After` before any scrypt work**; only credential failures count; success clears the key | `test_login_throttle_sheds_repeated_failures` |
| Auth responses could be cached by intermediaries | `Cache-Control: no-store` on every `/api/auth/*` response | `test_auth_responses_are_never_cached` |
| Comma-separated list env overrides broke config loading | `config` coerces list values instead of raising | `test_config_coerces_list_env_overrides` |
| Session lifetime | Absolute TTL (`session_ttl_minutes`, 12 h) — **no idle timeout** (§5.3) | covered by the auth suite |

### 2.2 Authorization & privilege

| Finding | Fix | Test |
|---|---|---|
| `/api/pqc/scan` was reachable by viewers | Requires `investigate`: viewer → 403, analyst → 404 (route hidden from roles that must not see it) | `test_investigation_probe_is_denied_to_viewers` |
| The last admin could be demoted (lockout) | **409** on demoting the final admin | `test_last_admin_cannot_be_demoted` |
| WebSocket accepted a connection once and never re-checked | `_writer` revalidates the principal while streaming → **4401** after logout/expiry | `test_websocket_session_revalidated_after_logout` |
| WebSocket accepted a foreign `Origin` | Allow-list (same host + configured origins) → **4403** otherwise | `test_websocket_rejects_foreign_origin_with_4403`, `test_websocket_accepts_same_host_and_configured_origins` |

### 2.3 Request limits, validation & error surface

| Finding | Fix | Test |
|---|---|---|
| Oversized / chunked bodies (a lying `Content-Length`, or none) | `_BodyLimit` counts declared *and* streamed bytes → **413** at 4 MiB | `test_oversized_json_body_is_refused_with_413`, `test_body_limit_counts_declared_and_streamed_bodies` |
| Validation errors echoed the request input back | 422 bodies are generic (field + reason only) | `test_validation_errors_never_echo_request_input` |
| A huge numeric id overflowed `int()` → 500 | Overflow → **422** "numeric parameter out of range" | `test_huge_numeric_ids_answer_422` |
| Internal failures leaked detail | Generic **500** on the history/model/twin/captures/robustness/pqc paths (log keeps the cause) | `test_internal_failures_answer_generic_500` |
| One request could pull an entire table | `Query(..., le=1000)` bounds on pagination | `test_pagination_limits_are_bounded` |
| Offline flow collection was unbounded | `MAX_COLLECT_FLOWS = 250 000` → `FlowBudgetError` → **400** on robustness/twin | `test_offline_flow_budget_answers_400` |

### 2.4 Files & malformed captures

| Finding | Fix | Test |
|---|---|---|
| **A 40-byte crafted PCAP could force a multi-GiB allocation** — scapy does `read(caplen)` with `caplen` straight from the record header (measured: 512 MiB claim → 536 MB peak) | `_SizeBoundedFile` clamps every read to the file's own size (gzip: 16 MiB), passed as a *stream* so the pcap↔pcapng fallback is clamped too. Measured peak now **11 632 B** | `test_crafted_record_length_cannot_drive_a_gigabyte_allocation` |
| Server storage paths in error text | Messages carry the **basename only** | `test_capture_errors_report_a_basename_not_a_path` |
| Failures *mid-iteration* (truncated record, broken block length) escaped as raw scapy errors → 500 | Mapped to `CaptureError` → **400** (also closes an fd leak on construction failure) | `test_truncated_pcapng_block_is_a_capture_error` |
| Handing scapy a stream instead of a path could break the PCAP→PCAPNG fallback | — regression guard: PCAPNG still reads end-to-end | `test_pcapng_captures_still_read_through_the_bounded_stream` |
| Upload filename used as a path | Basename-only at import and train (path traversal) | `test_capture_resources.py::test_import_sanitizes_traversal_filename`, `test_model_registry.py` (`escapes`) |
| BPF filter input | `MAX_FILTER_LENGTH=1024`, `MAX_FILTER_DEPTH=32` at the parser and the capture API; capture store refuses implausible files (`_MIN_CAPTURE_BYTES=24`) | `test_filter_expression_length_and_depth_are_capped` |
| Concurrent capture start | `_start_lock` makes start single-flight | covered by the capture suite |

### 2.5 ML lifecycle & artifact integrity

| Finding | Fix | Test |
|---|---|---|
| An artifact could be swapped/corrupted after registration | `ml/integrity.py`: sha256 **sidecar** per artifact, verified on load → `BioSystem().load()` returns `False` on mismatch | `test_artifact_digest_refuses_corrupted_state` |
| Concurrent registry read-modify-write | Registry calls serialised behind an `RLock` (`_registry_call`) | `test_model_registry.py` |
| Overlapping heavy analyses (train/analyze/robustness/shadow) | Single-flight `analysis_slot()` → `AnalysisBusy` → **409** | `test_analysis_slot_refuses_a_second_concurrent_run` |
| Double inference on the score+predict path | `score_and_predict` computes the score once | detection suite |
| Untrusted joblib / schema drift | Load refuses wrong `version`, wrong class, and a **feature-schema mismatch** | registry trust tests |
| Training path label leaked a directory | Basename-only in the training error message | `test_capture_errors_report_a_basename_not_a_path` |

### 2.6 Runtime bounds & resource exhaustion

| Finding | Fix | Test |
|---|---|---|
| Ghost-flow cache grew without bound on a long capture | Two-tier `_completed` cap (soft 8 192 / hard floor 4 096) with a recent-window sweep | `test_offline_flow_collection_is_budgeted` |
| Malformed filter could blow the stack (deep nesting) | Depth + length caps | `test_filter_expression_length_and_depth_are_capped` |
| Stage-queue / flow budgets | Bounded queue; `FlowBudgetError` (above); event row caps | `test_offline_flow_budget_answers_400` |

### 2.7 Persistence & schema

| Finding | Fix | Test |
|---|---|---|
| One poisoned batch was retried forever, wedging every later flush | `WriteBuffer.flush` **discards** the failing batch, then re-raises | `test_batch_flush_discards_a_poisoned_batch` |
| History/audit lookups had no covering index | Migration 11: `idx_audit_actor`, `idx_captures_hash` | `test_lookup_indexes_are_created` |
| Alert growth unbounded | `AlertRepository` capped at 50 000 rows (drops the least recently seen; `count/rows/resync/_prune`) | `test_repositories.py` |

### 2.8 Advanced modules & shutdown

| Finding | Fix | Test |
|---|---|---|
| The TEE quote did not declare its trust level | `QUOTE_ENVIRONMENT="SIMULATED"` **inside the signed payload**; verification checks it (8 checks) and the result reports the environment; the UI says "verification checks" | `test_tee_quote_labels_itself_simulated` |
| TEE key file mode | `KEY_FILE_MODE=0o600` + owner-only restriction (POSIX; asserted under `os.name == "posix"`) | same section |
| Process death left captures "running" and rows unflushed | FastAPI `lifespan` shutdown stops the capture, then closes the store (flushes staged rows) | health/shutdown suite |

### 2.9 Test-suite repair

`tests/test_model_registry.py::test_api_registry_candidate_flow_and_rollback`
trained two models on the *same* capture with the *same* settings and asserted
`same_artifact is False`. Training is deterministic (`random_state=42`) and
`trained_at` carries only second resolution, so the assertion held only when
the two fits straddled a wall-clock second — a ~50 % flake (it failed in one
run of this pass and passed in five subsequent runs only after the fix). The
second training now uses different settings, so the two artifacts genuinely
differ and the assertion is deterministic.

## 3. Evidence

| Layer | Result | Notes |
|---|---|---|
| **pytest** (`python -m pytest tests -q`) | **496 passed**, 0 failed, 82.0 s | 468 before this pass → +24 hardening → +4 capture-file |
| **Hardening suite** | **28 tests / 8 sections** | request limits (2), authentication (5), authorization (2), error surface (5), WebSocket (3), runtime bounds (5), persistence (2), capture files (4) |
| **Acceptance runner** | **156 / 156 checks**, 0 warnings | every HTTP route + WebSocket, the negative probes, the full CLI sweep, and a live Npcap capture |
| **Frontend build** | `tsc && vite build` → **exit 0** | `dist/` 744 kB JS + 19 kB CSS (chunk-size warning, §5.9) |

Negative paths exercised end-to-end: 400, 401, 403, 404, 409, 413, 422, 429,
4401, 4403 and the generic 500 — plus digest refusal, artifact path escape,
poisoned batch, crafted PCAP, and last-admin/self-lockout attempts.

## 4. Performance

### 4.1 Against the recorded baseline (`docs/acceptance-report.md` §5)

`scripts/perf.py`, hermetic (temp data dir + temp model path), this machine
(Windows, Python 3.13, scikit-learn wheel):

| Path | Baseline §5 | This pass | Δ |
|---|---|---|---|
| Edge MEC micro-detector p50 | 0.0098 ms | 0.0081 – 0.0171 ms | at/below baseline |
| Edge micro p95 (budget 10 ms) | 0.0189 ms | 0.0085 – 0.0239 ms | **always within budget** (~400× margin) |
| Main detector `score()` p50 | 0.269 ms | 0.248 – 0.558 ms (A/B mean **0.271**) | equal |
| `score()` p95 | 0.457 ms | 0.317 – 0.957 ms (A/B mean **0.415**) | equal / better |
| `explain()` p50 | 0.040 ms | 0.034 – 0.065 ms (A/B mean **0.037**) | equal / better |
| Offline scan of `suspicious.pcap` | 0.348 s / 827 pkt/s | 0.073 – 0.137 s / 2 085 – 3 950 pkt/s | **−60 % … −79 %** |
| Detection output | 288 → 13 → 5 | 288 → 13 → 5 | unchanged |

The scan delta is expected: the baseline is `spectra scan` wall-clock
(interpreter + model load + a 0.2 s completion poll in `cli.py`), while
`perf.py` times the pipeline only.

### 4.2 A/B against the pre-hardening code (causal check)

A clean `git worktree` of `2f15ebb` (A) and this tree (B), same machine, same
script, interleaved A→B pairs after a discarded warm-up — three pairs each:

| Bench | A — pre-hardening | B — this pass | Δ |
|---|---|---|---|
| Flow tracking (pkt/s) | 32 977 / 33 383 / 33 381 → **μ 33 247** | 32 457 / 32 719 / 33 298 → **μ 32 825** | −1.3 % |
| Batched persistence (rows/s) | 60 662 / 61 867 / 52 128 → **μ 58 219** | 50 088 / 51 374 / 72 291 → **μ 57 918** | −0.5 % |
| `score()` p50 (ms) | 0.2624 / 0.2713 / 0.3274 → **μ 0.287** | 0.2572 / 0.2848 / 0.2710 → **μ 0.271** | −5.6 % |
| `score()` p95 (ms) | 0.3230 / 0.3530 / 0.7149 → **μ 0.464** | 0.3086 / 0.5231 / 0.4130 → **μ 0.415** | −10.6 % |
| `explain()` p50 (ms) | 0.0339 / 0.0392 / 0.0630 → **μ 0.0454** | 0.0349 / 0.0394 / 0.0378 → **μ 0.0374** | −17.6 % |
| Offline scan (s) | 0.086 / 0.087 / 0.094 → **μ 0.089** | 0.088 / 0.094 / 0.092 → **μ 0.091** | +2.6 % |

Both versions produce identical output on every scan (288 packets → 13 flows →
5 detections). **No measurable regression from the hardening pass**: differences
sit inside run-to-run noise and the detector rows favour B.

### 4.3 New measurements (no prior baseline)

| Metric | Measured |
|---|---|
| Flow tracking | 26.2 k – 35.0 k pkt/s (A/B μ 32.8 k) |
| Batched persistence (`batch_size=256`, 40 transactions/10 k rows) | 41.9 k – 76.3 k rows/s (A/B μ 57.9 k) |
| Stage-queue hand-off (200 k items, `maxsize=4096`) | 0.96 – 1.41 µs/item |
| Event-bus fan-out (20 k events, 3 listeners, 0 errors) | 0.42 – 0.87 µs/event |
| API p50, in-process (TestClient) | `/api/status` 0.97 – 1.80 ms · `/api/stats` 1.08 – 1.96 ms · `/api/capabilities` 1.23 – 2.17 ms · `/api/health` 0.89 – 1.49 ms · `/api/history/flows?limit=100` 1.75 – 2.90 ms |
| WebSocket first message p50 | 1.40 – 2.28 ms (n = 5) |
| Offline training of `baseline.pcap` | 0.49 – 1.12 s (42 flows → 39 features) |

**Method notes.** API/WS figures are in-process: they measure route + auth +
store work, not network cost. Sub-millisecond rows move by roughly ±30 % on a
desktop depending on background load and CPU clock (runs taken while the API
server was running sit at the top of every range) — a delta inside that band
is noise, which is why §4.2 compares interleaved pairs rather than single runs.

## 5. Remaining limitations

Explicit, verified, and **not** addressed in this pass:

1. **Age-based retention is off by default.** `RetentionPolicy` fields default
   to `0` (= keep); history is bounded by newest-kept **row caps**
   (flows/events/alerts, alert cap 50 000), not by age. `audit_log` is never
   pruned — its hash chain and Merkle checkpoints need the full `seq`
   sequence, so growth depends on archive/checkpoint practice.
2. **Rate limiting covers login only.** The throttle is per-process and
   in-memory (10/60 s per *(ip, username)*, 40/60 s per ip): it resets on
   restart and is not shared across processes. Other authenticated endpoints
   rely on RBAC, bounded pagination and the 4 MiB body limit.
3. **No idle-session timeout.** Sessions expire after an absolute
   `session_ttl_minutes` (12 h). A revoked session's open WebSocket keeps
   streaming for up to `REVALIDATE_INTERVAL` (30 s) before the writer
   revalidates and closes it with 4401.
4. **TEE is SIMULATED.** The quote carries `environment: "SIMULATED"` and
   verification reports it; there is no real enclave or remote attestation.
   No payload decryption and read-only passive capture remain by design
   (privacy boundary, not a defect).
5. **`serve` ignores `SPECTRA_API_HOST`/`SPECTRA_API_PORT`.** The subcommand's
   `--host`/`--port` defaults are literals; only the CLI flags take effect —
   the config fields are not consulted.
6. **Text/JSON search predicates are not index-covered.** History/search
   filters use `LIKE` over stored JSON (`record`, `metadata`, …); SQLite cannot
   use an index for those. Cost is bounded by anchors, page limits and the row
   caps — not by an index.
7. **Legacy capture rows have no stored file.** Rows created before the
   managed-resource model (or live sessions) report `source_type: "path"` and
   are refused by `path_for` with a conflict instead of being re-imported.
8. **Live NIC capture needs Npcap** (Windows). The acceptance runner's live
   section is gated on it; without Npcap those checks are skipped, not passed.
9. **Frontend bundle:** `vite build` still warns that the single chunk is
   > 500 kB (744 kB / 211 kB gzip, recharts included). A build warning, not a
   functional defect; code-splitting was out of scope for a fix-only pass.
10. **Performance methodology:** desktop measurements (±30 % on sub-ms rows),
    in-process API timing, and a scan baseline that includes CLI startup.
    Absolute numbers will differ on other hardware; the A/B in §4.2 is the
    comparison that isolates code changes.
11. **Prompt 15 remains deferred** by the standing rules — this pass adds no
    features.

## 6. Status

| DoD item | Status |
|---|---|
| No critical known vulnerability | Closed: login throttling, storage-path leakage, crafted-PCAP multi-GiB allocation, path traversal, exception/stack leakage, WS origin + session revalidation, artifact integrity, last-admin lockout, unbounded queues/collections |
| No major functional regression | 496 tests + 156/156 acceptance (incl. live capture) + identical detection output + A/B performance parity |
| Tests pass | ✅ `496 passed` · `156/156` · `tsc && vite build` exit 0 |
| Measured performance documented | ✅ §4 (baseline, causal A/B, new metrics, method) |
| Remaining limitations documented | ✅ §5 |
