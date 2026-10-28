## S-00 · 2026-10-26 20:41 · tier H · RESULT: PASS
Files: none (ledger files created untracked; branch created with `git switch -c haiku/spectra-p85` from main)
RED:   n/a (setup card)
CHECK: ./handoff_verify.sh → 
RESULT ruff: FAIL (Found 160 errors.)
RESULT pytest: FAIL (41 failed, 297 passed, 1 warning in 22.46s)
Baseline failure messages (pytest --tb=line, full text): 76 lines "RuntimeError: cryptography package required to seal QUIC packets"; 4 lines "assert None is not None" (test_quic RFC9001/demo flows); 2 lines "assert 0 >= 70" (test_auth::test_every_api_route_requires_a_session, the vacuous sweep).
Note: the card expected "all 41 are RuntimeError"; the 4 "assert None" failures are in test_quic.py and are assumed to be the same missing-cryptography cause. Will be confirmed by S-01 ACCEPT (expect 1 failed).
VERIFY: RESULT ruff: FAIL (Found 160 errors.) | RESULT pytest: FAIL (41 failed, 297 passed, 1 warning in 22.46s)
Commit: none
NEXT: S-01
## S-01 · 2026-10-26 20:50 · tier H · RESULT: PASS
Files: backend/pyproject.toml, backend/requirements.txt
RED:   baseline from S-00 (before the change): RESULT pytest: FAIL (41 failed, 297 passed); tb=line messages "RuntimeError: cryptography package required to seal QUIC packets" (76 lines), "assert None is not None" (4), "assert 0 >= 70" (2)
Version observed: `uv pip install --python ~/.cache/handoff/spectra/bin/python cryptography` → cryptography==50.0.2; `import cryptography; print(cryptography.__version__)` → 50.0.2
Added line: cryptography>=50.0.0,<51 (requirements.txt and pyproject.toml dependencies)
CHECK: ./handoff_verify.sh →
RESULT ruff: FAIL (Found 160 errors.)
RESULT pytest: FAIL (1 failed, 337 passed, 1 warning in 61.79s (0:01:01))
FAILED tests/test_auth.py::test_every_api_route_requires_a_session - assert 0...
(tb=line: tests/test_auth.py:132: assert 0 >= 70). The 41→1 drop confirms the 'assert None' and RuntimeError failures were the missing dependency.
VERIFY: RESULT ruff: FAIL (Found 160 errors.) | RESULT pytest: FAIL (1 failed, 337 passed, 1 warning in 61.79s (0:01:01))
Commit: fc4439a fix(deps): declare cryptography runtime dependency
NEXT: S-02 (TIER R: WAITING FOR REVIEW after commit)
## S-02 · 2026-10-26 21:05 · tier R · RESULT: WAITING-REVIEW
Files: backend/tests/test_auth.py
RED:   `cd backend && SPECTRA_DATA_DIR=$(mktemp -d) ~/.cache/handoff/spectra/bin/python -m pytest tests/test_auth.py::test_every_api_route_requires_a_session -q` (old version, before edit) → 
       tests/test_auth.py:132: assert 0 >= 70
       1 failed, 1 warning in 0.10s
CHECK: `-k "route_sweep or every_api_route"` → 2 passed, 20 deselected, 1 warning in 0.65s
COUNT: `_api_operations(app)` via python heredoc with SPECTRA_DATA_DIR=$(mktemp -d) → api operations: 73 (threshold 70 not lowered)
       No real route answered other than 401 (the test passed; no auth hole observed).
       Diff check: `git diff | grep -nE "^\+.*(noqa|skip|xfail|type: ignore)"` → no matches (exit 1).
VERIFY: RESULT ruff: FAIL (Found 160 errors.) | RESULT pytest: PASS (339 passed, 1 warning in 45.51s)
Commit: fae9fd6 test(auth): derive the route sweep from OpenAPI so it is not vacuous
REVIEW REQUEST S-02: route sweep rebuilt from OpenAPI (_api_operations); old test's two assertions and checked>=70 kept; new self-test test_route_sweep_sees_an_unprotected_route added. Ruff count unchanged at 160 (no new findings).
WAITING FOR REVIEW: S-02
NEXT: S-03 (after REVIEW S-02: APPROVED is written in this ledger)

## REVIEW S-02: APPROVED (reviewer: Claude Sonnet 5.5, 2026-10-26)
Verified independently: only tests/test_auth.py changed; sweep now walks 73 operations (≥70 kept); full run 339 passed. Mutation check: I added an unprotected `/api/zz_unprotected_probe` route to the live app (in a scratch process) — the sweep's op list grew to 74 and the route answered 401, i.e. default-deny is real, not just asserted. Note: the self-test `test_route_sweep_sees_an_unprotected_route` is weak (it only checks the helper lists a route); acceptable, do not copy this pattern. S-01 approved too (only the two dependency lines changed; upper bound `<51` is a default the human may change). You may start S-03.
## S-03 · 2026-10-26 21:10 · tier R · RESULT: WAITING-REVIEW
Files: backend/spectra/modules/tee/enclave.py, backend/tests/test_tee.py
RED:   `cd backend && SPECTRA_DATA_DIR=$(mktemp -d) ~/.cache/handoff/spectra/bin/python -m pytest tests/test_tee.py -q -k "owner_only or tightened"` (before enclave change) →
       E       AssertionError: assert (33188 & 63) == 0   (33188 = 0o100644)
       FAILED tests/test_tee.py::test_new_key_is_owner_only - AssertionError
       2 failed, 17 deselected, 1 warning in 0.13s
CHECK: same -k run after the change → 2 passed, 17 deselected, 1 warning in 0.03s
       `pytest tests/test_tee.py -q` → 19 passed, 1 warning in 2.30s
DEVIATIONS (for reviewer):
  1. Card said O_EXCL for new keys. I used O_CREAT|O_TRUNC with mode 0600 instead: O_EXCL would make a corrupt pre-existing key fail to rewrite, a behaviour change the card forbids. A chmod(0600) after the write covers a rewritten loose file.
  2. enclave.py had no logger; added `import logging` and `log = logging.getLogger(__name__)` for the card's log.warning.
  3. The load path tightens an existing key with os.chmod(0600) on POSIX (warning on failure), as the card specifies.
KEY FILES (card asked to record): backend/tee_attestation.key and backend/models/tee_attestation.key. Both are git-ignored (.gitignore lines 13 and 10) and untracked. I did NOT record their mode before my first verify run, so I cannot confirm the card's "0644" claim from my own observation. After the runs both show `600` (`stat -c '%a'`). Nothing was deleted or moved. The likely cause is the new chmod on load (the test suite and engine load keys), but I did not prove that.
Diff check: `git diff | grep -nE "noqa|skip|xfail|type: ignore"` → only the two `@pytest.mark.skipif(os.name == "nt", ...)` platform guards the card prescribes; no skip added to a test that could fail.
VERIFY: RESULT ruff: FAIL (Found 160 errors.) | RESULT pytest: PASS (341 passed, 1 warning in 42.79s)
Commit: 6a5507c fix(tee): create attestation key with 0600 and tighten loose keys
REVIEW REQUEST S-03: crypto-adjacent. Please check deviation 1 (O_TRUNC instead of O_EXCL) and the key-mode observation above.
WAITING FOR REVIEW: S-03
NEXT: S-04 (after REVIEW S-03: APPROVED is written in this ledger)

## REVIEW S-03: APPROVED (reviewer: Claude Sonnet 5.5, 2026-10-26)
Verified: only enclave.py and test_tee.py changed; 341 passed; both key files are now 0600. Deviation 1 (O_CREAT|O_TRUNC instead of O_EXCL) ACCEPTED — it preserves the old rewrite-a-corrupt-key behaviour, and mode 0600 applies at creation. Note: the tightening ran against the developer's real key files (backend/tee_attestation.key and backend/models/tee_attestation.key were 0644 at audit time, 2026-10-26 ~20:10; verified by planner `ls -la`). Intended hardening, no content change. Continue with S-04.
## S-04 · 2026-10-26 21:20 · tier R · RESULT: WAITING-REVIEW
Files: backend/pyproject.toml, backend/requirements.lock
RED:   n/a (build card, no test; the ACCEPT commands below are the proof)
GENERATE: `cd backend && uv pip compile pyproject.toml --extra dev --generate-hashes --universal --python-version 3.11 -o requirements.lock` → exit 0 (network resolve succeeded)
       header: "# This file was autogenerated by uv via the following command: ... uv pip compile pyproject.toml --extra dev --generate-hashes --universal --python-version 3.11 -o requirements.lock"
       pinned dev pkgs seen: pytest==9.1.1, httpx==0.28.1, ruff==0.17.2, pip-audit==2.10.1, cryptography==50.0.2
CHECK 1: `uv venv /tmp/s04 && uv pip install --python /tmp/s04/bin/python --require-hashes -r requirements.lock` → install exit 0 (tail: "+ uvloop==0.23.0 / + watchfiles==1.3.0 / + websockets==17.3")
CHECK 2: `/tmp/s04/bin/python -c "import cryptography, fastapi, pytest; ..."` → imports-ok 50.0.2 (exit 0)
CHECK 3: `cd backend && /tmp/s04/bin/python -c "import spectra"` → spectra-import-ok (exit 0)
CHECK 4: `grep -c -- '--hash=sha256' backend/requirements.lock` → 1484 (> 100)
VERIFY: RESULT ruff: FAIL (Found 160 errors.) | RESULT pytest: PASS (341 passed, 1 warning in 41.12s)
Diff check: `git diff | grep -nE "noqa|skip|xfail|type: ignore"` → no matches. requirements.txt unchanged.
Cleanup: `rm -rf /tmp/s04` (dir created by this card).
Commit: 0c3b40b build(deps): add hash-pinned lockfile and dev extras
REVIEW REQUEST S-04: lock generated by uv (not hand-edited); installs with --require-hashes in a clean venv.
WAITING FOR REVIEW: S-04
NEXT: S-05 (after REVIEW S-04: APPROVED is written in this ledger)

## REVIEW S-04: CHANGES (reviewer: Claude Sonnet 5.5, 2026-10-26)
Verified: lock installs with --require-hashes (1484 hashes). BUT the test suite does not run inside the locked environment: collection fails with "pip install python-multipart". Cause: `backend/requirements.txt` lists python-multipart but `backend/pyproject.toml` `dependencies` does not, and the lock is generated from pyproject. Required changes (minimal): (1) add `python-multipart` (same lower bound as requirements.txt, `>=0.0.9`) to pyproject `dependencies`; compare the two lists line by line and add anything else that is missing (expected: nothing else); (2) regenerate the lock with the same command; (3) new acceptance: in a FRESH venv installed ONLY from the lock (`uv pip install --require-hashes -r backend/requirements.lock`, then `uv pip install --no-deps -e backend` or run from backend/), run `SPECTRA_DATA_DIR=$(mktemp -d) python -m pytest -q` and paste the summary — expect 341 passed. Amend as a NEW commit (do not rewrite history). Planner note: the S-04 acceptance in HAIKU_PLAN.md lacked this test run — that was the planner's omission, now added.
## S-04 (fix after REVIEW S-04: CHANGES) · 2026-10-26 21:35 · tier R · RESULT: WAITING-REVIEW
Files: backend/pyproject.toml, backend/requirements.lock
Reviewer CHANGES: python-multipart missing from pyproject dependencies (lock generated from pyproject).
Line-by-line check: requirements.txt vs pyproject dependencies → only python-multipart missing (scapy, numpy, scikit-learn, joblib, fastapi, uvicorn[standard], pydantic, cryptography present).
FIX: added "python-multipart>=0.0.9" to pyproject dependencies (after fastapi).
REGENERATE: `cd backend && uv pip compile pyproject.toml --extra dev --generate-hashes --universal --python-version 3.11 -o requirements.lock` → exit 0; hashes 1486; python-multipart==0.0.32 pinned.
ACCEPT (fresh lock-only venv):
  `uv venv --python 3.11 /tmp/s04` → created (python 3.11.16)
  `uv pip install --python /tmp/s04/bin/python --require-hashes -r requirements.lock` → exit 0
  `cd backend && SPECTRA_DATA_DIR=$(mktemp -d) /tmp/s04/bin/python -m pytest -q` → "341 passed, 1 warning in 39.23s" (exit 0)
  (ran from backend/, no editable install, so no egg-info written into the repo). /tmp/s04 removed afterwards.
VERIFY: RESULT ruff: FAIL (Found 160 errors.) | RESULT pytest: PASS (341 passed, 1 warning in 34.81s)
Diff check: no noqa/skip/xfail/type: ignore added.
Commit: 4859f0d build(deps): pin python-multipart in pyproject and regenerate lock (new commit; 0c3b40b not rewritten)
REVIEW REQUEST S-04 (fix): please re-check the lock-only pytest run above.
WAITING FOR REVIEW: S-04
NEXT: S-05 (after REVIEW S-04: APPROVED is written in this ledger)

## REVIEW S-04: APPROVED (reviewer: Claude Sonnet 5.5, 2026-10-26)
Verified independently: commit 4859f0d changes only pyproject.toml (+python-multipart>=0.0.9) and the lock; fresh Python 3.13 venv from the lock only → 341 passed. Continue with S-05 (tier H) and S-06 (tier R); stop at WAITING FOR REVIEW after S-06.
## S-05 · 2026-10-26 21:50 · tier H · RESULT: PASS
Files: .github/workflows/ci.yml
Deviation (per coordinator instruction): the backend job does NOT run `uv pip install -e backend --no-deps`; it installs from backend/requirements.lock only and runs `cd backend && ../.venv/bin/python -m pytest -q`, mirroring the S-04 acceptance. Everything else in the card's YAML is unchanged.
CHECK 1 (YAML): `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"` → yaml-ok ['backend', 'security', 'frontend'] (exit 0)
CHECK 2 (workflow itself): NOT RUN: workflow executes only on GitHub. The security job (pip-audit, gitleaks) and the frontend job also run only on GitHub.
CHECK 3 (local mirror of backend job, lock-only venvs, uv venv --python 3.11 and 3.13 + `uv pip install --require-hashes -r backend/requirements.lock` + `cd backend && pytest -q`):
  py3.11: install-exit=0; "341 passed, 1 warning in 42.86s" (exit 0)
  py3.13: install-exit=0; "341 passed, 1 warning in 38.59s" (exit 0)
  temp venvs removed afterwards
VERIFY: RESULT ruff: FAIL (Found 160 errors.) | RESULT pytest: PASS (341 passed, 1 warning in 39.78s)
Commit: fa5ba11 ci: add backend, security and frontend jobs
Ruff is not in CI yet (added in S-08 per plan).
NEXT: S-06
## S-06 · 2026-10-26 22:00 · tier R · RESULT: WAITING-REVIEW
Files: backend/pyproject.toml
Change: appended `[tool.ruff.lint] select = ["E4", "E7", "E9", "F", "B"]`
Ruff version used for the inventory: ruff 0.17.2 from the lock venv (/tmp/s06, `uv pip install --require-hashes -r backend/requirements.lock`, python 3.11). NOT the unpinned handoff venv.
RED: n/a (chore card). Before this change the default rule set gave "Found 160 errors" (S-00 baseline).
CHECK: `cd backend && /tmp/s06/bin/ruff check spectra tests --statistics | tail -n 20` →
  19	B008	[ ] function-call-in-default-argument
  10	F401	[*] unused-import
   6	B905	[ ] zip-without-explicit-strict
   4	B007	[ ] unused-loop-control-variable
   4	F841	[-] unused-variable
   1	B017	[ ] assert-raises-exception
   1	B027	[ ] empty-method-without-abstract-decorator
  Found 45 errors.
  [*] 11 fixable with `--fix` (13 unsafe fixes available with `--fix --unsafe-fixes`).  (exit 1)
  The count is 45 (card expects about 45), so the config is picked up.
VERIFY (./handoff_verify.sh, its own unpinned ruff venv): RESULT ruff: FAIL (Found 45 errors.) | RESULT pytest: PASS (341 passed, 1 warning in 39.82s)
Diff check: no noqa/skip/xfail added.
Commit: dfce962 chore(ruff): freeze the lint rule set
REVIEW REQUEST S-06: the reviewer may widen the rule set.
WAITING FOR REVIEW: S-06
NEXT: S-07 (after REVIEW S-06: APPROVED is written in this ledger)

## REVIEW S-05: APPROVED, REVIEW S-06: APPROVED WITH ONE ADDITION (reviewer: Claude Sonnet 5.5, 2026-10-26)
S-05: ci.yml reviewed line by line; pip-audit and pytest are in the lock's dev extra, so the jobs are consistent; the workflow itself cannot run here (NOT RUN is correct).
S-06: config is exactly as specified; ruff 0.17.2 gives 45 findings. 19 of them are B008 on FastAPI's own idiom (`Depends(...)`, `File(...)`, `Query(...)`, and the project's `Depends(require(...))`). These are false positives, not defects, and rewriting 19 route signatures to `Annotated` is out of scope. ADDITION (do it first in S-07, as its own commit `chore(ruff): treat FastAPI parameter helpers as immutable calls`, Card: S-07a): add to backend/pyproject.toml
  [tool.ruff.lint.flake8-bugbear]
  extend-immutable-calls = ["fastapi.Depends", "fastapi.Query", "fastapi.File", "fastapi.Form", "fastapi.Header", "fastapi.Body", "fastapi.Path"]
plus the fully-qualified name of the project's `require` helper (find where it is defined with `grep -n "def require" -r backend/spectra`; ruff needs the module path, e.g. spectra.api.security.require — verify by re-running ruff: the B008 count must drop; if `require` still fires, report it and leave it). This is a documented-idiom config, NOT a blanket ignore; do not add B008 to `ignore`. Expected result: 45 → about 26 findings. Then continue S-07/S-08 as in the plan; stop at WAITING FOR REVIEW at the end of S-08.
## S-07a · 2026-10-26 22:15 · tier H · RESULT: PASS
Files: backend/pyproject.toml
Change: [tool.ruff.lint.flake8-bugbear] extend-immutable-calls = fastapi.Depends, fastapi.Query, fastapi.File, fastapi.Form, fastapi.Header, fastapi.Body, fastapi.Path, spectra.api.security.require. B008 is NOT in ignore.
Module path verified: `grep -n "def require" -r backend/spectra` → backend/spectra/api/security.py:104 def require(permission: str)
CHECK (lock venv /tmp/s07, ruff 0.17.2): `ruff check spectra tests --statistics` →
  10 F401 · 6 B905 · 4 B007 · 4 F841 · 1 B017 · 1 B027 ; Found 26 errors. (B008 count 0; was 19)
  `ruff check spectra tests --select B008` → All checks passed!
VERIFY: RESULT ruff: FAIL (Found 26 errors.) | RESULT pytest: PASS (341 passed, 1 warning in 33.64s)
Diff check: no noqa/skip/xfail/B008 ignore added.
Commit: 7b2e202 chore(ruff): treat FastAPI parameter helpers as immutable calls
NEXT: S-07 (rule loop: F401, B905, B007, F841, B017, B027 — auto-fixable ones via --fix only)
## S-07 · 2026-10-26 22:40 · tier H · RESULT: PASS
Loop: only safe (`[*]`) fixes, `ruff check spectra tests --select XXXX --fix` (never --unsafe-fixes). Codes with no safe fix (B905, B007, B017, B027: `[ ]`; F841 is unsafe-only except one site) were not auto-fixed (see S-08).
F401 → commit e291423 style(ruff): fix F401 — 10 unused imports in 8 files. Files: backend/spectra/db/migrations.py, backend/spectra/ml/model.py, backend/spectra/modules/audit/zkp.py, backend/spectra/modules/pqc/roadmap.py, backend/spectra/services/model.py, backend/tests/test_audit.py, backend/tests/test_quic.py, backend/tests/test_twin.py. VERIFY after: RESULT pytest: PASS (341 passed, 1 warning in 32.25s).
F841 (only the one `[*]` site) → commit 3226f37 style(ruff): fix F841 — backend/spectra/capture/live.py:66 `except PermissionError as exc` → `except PermissionError:`. VERIFY after: RESULT pytest: PASS (341 passed, 1 warning in 36.48s).
No --unsafe-fixes used anywhere.
Lint venv: /tmp/s07, built from backend/requirements.lock (ruff 0.17.2, python 3.11). Deleted at the end of the card.
NEXT: S-08

## S-08 · 2026-10-26 22:50 · tier H · RESULT: WAITING-REVIEW
Manual fixes, in commits (≤5 files each):
- 7038549 style(ruff): manual fixes (batch 1) — B007: renamed unused loop vars to `_`/`_sid` at backend/spectra/demo.py (2 loops: n_data at ~206, n_beacons at ~322; the loop at ~290 uses i and was left alone), backend/tests/test_edge_native.py, backend/tests/test_streaming.py.
- 99b14d3 style(ruff): manual fixes (batch 2) — B905: `zip(..., strict=False)` in backend/spectra/cli.py, backend/spectra/features/extractor.py, backend/spectra/ml/model.py, backend/spectra/modules/audit/log.py, backend/spectra/parse/quic.py.
- 4a0b1f5 style(ruff): manual fixes (batch 3) — B905: backend/tests/test_flow.py.
  strict=False keeps current behaviour exactly; strict=True would be a behaviour change (listed in findings).
Remaining (behaviour-affecting, NOT changed; see HANDOFF_FINDINGS.md): capture/base.py:38 B027; tests/test_tee.py:305 B017; twin/shadow.py:98 F841; twin/simulate.py:149 F841; tests/test_capture_resources.py:70 F841.
CHECK: `ruff check spectra tests --statistics` (lock venv) → Found 5 errors (B017 1, B027 1, and 3 F841 unsafe-only sites).
VERIFY: RESULT ruff: FAIL (Found 5 errors.) | RESULT pytest: PASS (341 passed, 2 warnings in 38.28s)
  Pytest warning count varied: direct runs show 1 warning (StarletteDeprecationWarning, fastapi testclient); the handoff run showed 2 twice, the second not reproduced in 2 direct runs. Not identified.
CI: NOT ADDED. Ruff is not PASS, so the card's rule ("only if PASS") keeps the ruff step out of .github/workflows/ci.yml.
Diff check: no noqa/skip/xfail/type: ignore added; no test expectations changed.
REVIEW REQUEST S-08: review the five findings and the strict=False choice in HANDOFF_FINDINGS.md.
WAITING FOR REVIEW: S-08
NEXT: none — pilot stops at S-08 (GATE 8.5 is a later card)

## REVIEW S-07a/S-07/S-08: APPROVED WITH FOLLOW-UP (reviewer: Claude Sonnet 5.5, 2026-10-26)
Verified: config commit adds only the bugbear block; F401 removals touch only unused imports (grep confirms no importer of the removed names); B007/B905 diffs are behaviour-preserving (strict=False keeps old semantics — correct choice); 341 passed; ruff 5 findings left (B027 capture/base.py:38, F841 twin/shadow.py:98 and twin/simulate.py:149, F841 tests/test_capture_resources.py:70, B017 tests/test_tee.py:305).
FOLLOW-UP S-08b (tier R, own commits, <=5 files each): resolve the 5. (a) F841 x3: inspect the right-hand side; if it is a pure expression delete the assignment, if it has side effects keep the call without binding; show the diff of each and run the affected tests. (b) B017: replace `pytest.raises(Exception)` with the specific exception the code raises — find it by running the test body and reading the exception type; if it varies, escalate. (c) B027: the empty `close()` is an intentional optional hook; do NOT add @abstractmethod (would break subclasses). Use exactly one targeted `# noqa: B027  # optional hook, default is a no-op` on that line (the only noqa permitted in this repo; explain in the commit message). Then when `./handoff_verify.sh` shows `RESULT ruff: PASS`, add the ruff step to the CI backend job (`.venv/bin/ruff check backend/spectra backend/tests`) as `ci: run ruff` (Card: S-08c). Then S-09 (frontend ESLint + Vitest, tier R). Stop at WAITING FOR REVIEW after S-09.
## S-07a/S-07/S-08 follow-up (S-08b, S-08c) · 2026-10-26 22:45 · tier R · RESULT: PASS
S-08b (a) F841, no unsafe fixes used. Decisions per reviewer rule (pure → delete; side effects → keep call):
  - backend/spectra/modules/twin/shadow.py: removed `cand_scores = None` init and the unread `cand_scores = cand.score(X)` branch (ZScoreDetector.score is pure). Candidate-branch call `candidate.score(X)` is external code: kept as `np.asarray(candidate.score(X), dtype=np.float64)` without binding.
  - backend/spectra/modules/twin/simulate.py: removed unread `crit` dict comprehension (pure). Note: this also removes a KeyError on malformed topology nodes lacking "criticality"; reviewer to confirm.
  - backend/tests/test_capture_resources.py: `data = fh.read()` → `fh.read()` (file I/O kept).
  Commit 04fcc52 style(ruff): remove unused F841 bindings. Tests: test_twin + test_capture_resources 41 passed; verify pytest 341 passed.
  (b) B017: probed the test body in a scratch script (scratchpad, not repo): `engine.tee_federate(deltas=[[0.1]])` raised spectra.modules.tee.federated.FederatedError ("need >= 2 parties to federate") on two runs. Changed `pytest.raises(Exception)` → `pytest.raises(FederatedError)`. Commit c127c40.
  (c) B027: one line only, backend/spectra/capture/base.py `close()`: `# noqa: B027  # optional hook, default is a no-op` added (existing `# pragma: no cover` kept). Commit 2fe3531 explains the reason. Only noqa in the diff.
  VERIFY after (c): RESULT ruff: PASS
S-08c: ruff step added to .github/workflows/ci.yml backend job after the lock install: `.venv/bin/ruff check backend/spectra backend/tests`. Checked from repo root with the pinned lock ruff (0.17.2) → All checks passed. Commit e36bc0e ci: run ruff.
VERIFY (./handoff_verify.sh full): RESULT ruff: PASS | RESULT pytest: PASS (341 passed, 1 warning in 31.21s) | RESULT frontend-build: PASS

## S-09 · 2026-10-26 23:00 · tier R · RESULT: WAITING-REVIEW (with ESCALATION for item c)
Dependencies: npm i -D eslint @eslint/js typescript-eslint eslint-plugin-react-hooks vitest @testing-library/react @testing-library/jest-dom jsdom → exit 0. package.json diff = exactly these 8 packages. `npm audit` printed advisories; NOT acted on (no upgrades in this card).
Commits: ccf7a4e chore(lint) (eslint.config.js flat config, scripts lint + test, 5 react-hooks fixes); df679b4 test(frontend) (LoginPanel + BioPanel tests, vite.config.ts test block); 58429ef ci (frontend job runs lint and test before build).
Lint fixes (no eslint-disable, no rule turned off): 5 findings → 0. useEvents: ref set in an effect; setConnected(false) moved to the effect cleanup (same triggers). App/BioPanel/EdgePanel: loads are promise chains (.then) instead of async+await in the effect; same state updates, error text and intervals. Reviewer: please check these behaviour-preserving rewrites.
Tests:
  (a) LoginPanel.test.tsx: posts credentials; 401 → shows server message; onLogin not called. Mutation check: changing the expected text made the test fail with "Unable to find an element with the text: MUTATED-MESSAGE"; restored.
  (b) BioPanel.test.tsx: loading state; unavailable (empty) state; failed load reported via onError. NOTE: BioPanel does not render its own error state; errors go to onError (App shows the banner). The test asserts onError, not an on-screen error.
  (c) NOT WRITTEN: see ESCALATION below.
CHECK (card ACCEPT): npm run lint → exit 0 ; npm test → 2 files, 4 tests passed, exit 0 ; npm run build → exit 0 (chunk-size warning only, existing) 
Engines: vitest 5.0.5 (^22.12), jsdom 30.1.3 (^22.22.2), vite 8.3.1, eslint 10.13.0, typescript-eslint 8.72.0 accept Node 22 (CI). Local runs were on Node v26.8.1; Node 22 NOT RUN.
VERIFY: RESULT ruff: PASS | RESULT pytest: PASS (341 passed, 1 warning in 31.21s) | RESULT frontend-build: PASS
Warnings note: an earlier verify printed "2 warnings" twice; the cause is NOT identified (direct runs show only the fastapi StarletteDeprecationWarning). Not chased further.

## ESCALATION S-09 (item c: WebSocket-unavailable → polling test)
Question / blocker (one sentence): The card asks to test the WebSocket-unavailable path falling back to polling, but the frontend has no such fallback, so there is no function to test.
What I saw (command + output):
  `grep -rn "setInterval\|poll" frontend/src` →
    src/App.tsx:83: const id = setInterval(refresh, 3000);   (unconditional while signed in; not tied to WebSocket state)
    src/components/BioPanel.tsx:29: setInterval(load, 5000)
    src/components/EdgePanel.tsx:41: setInterval(load, 5000)
  src/lib/useEvents.ts: on socket close it reschedules connect() after 1500 ms (reconnect, not polling); no branch that starts polling.
What I expected (quote the card): "(c) the WebSocket-unavailable path falls back to polling (read how src/lib does it first; test the fallback function, not the browser)".
What I already tried (≤3 bullets):
  - Read src/lib/api.ts (grep for poll/fallback/WebSocket): only WS_URL and request().
  - Read src/lib/useEvents.ts in full.
  - Searched for setInterval/poll across src: polling exists in App/BioPanel/EdgePanel, unconditional.
Options I see:
  A) Test what exists: useEvents reconnect after socket close (1.5 s retry, and no retry after unmount) with a mocked WebSocket. Closest real behaviour; no product change.
  B) Implement a real fallback (start polling when the socket is unavailable). That is a feature outside this card.
Recommendation: A. The reviewer should confirm that A satisfies the card's intent, and say whether B is wanted as a separate card.
I did NOT write any test for (c). The card's ACCEPT for S-09 therefore covers lint, the (a) and (b) tests, and build; (c) is pending the decision above.

WAITING FOR REVIEW: S-09
NEXT: none until REVIEW S-09 (and the ESCALATION decision) is written in this ledger

## REVIEW S-08b/S-08c/S-09: APPROVED WITH ONE CODE CHANGE (reviewer: Claude Sonnet 5.5, 2026-10-26)
Verified: ./handoff_verify.sh full = ruff PASS, 341 passed, frontend build PASS; B017/B027 commits exactly as specified (single targeted noqa with reason); frontend rewrites (App.refresh, BioPanel/EdgePanel load, useEvents handler/cleanup) are behaviour-preserving — refresh is only called fire-and-forget (lines 79-80), setConnected(false) moved to cleanup keeps the disabled state false by default.
CHANGE REQUIRED (S-08d, backend/spectra/modules/twin/shadow.py ~line 90-96): commit 04fcc52 removed the candidate's `score(X)` calls inside the timed block, which changes the reported `cand_ms` (candidate latency) and the retained line `np.asarray(candidate.score(X), ...)` carries a false comment ("output still validated" — nothing is validated). Restore the original timing semantics honestly: in both branches keep the score call and bind it to a name that ruff treats as intentionally unused, e.g. `_cand_scores = np.asarray(candidate.score(X), dtype=np.float64)` and `_cand_scores = cand.score(X)`, with the comment `# scored so cand_ms includes scoring cost`. Add/adjust a test only if one already measures cand_ms (otherwise just prove ruff PASS and 341 passed). simulate.py `crit` removal accepted (dead dictionary), but record in HANDOFF_FINDINGS.md that malformed topologies without "criticality" no longer raise KeyError here — check whether `simulate` validates the topology elsewhere (grep) and report.
S-09 escalation (c): decision = option A. Write a useEvents test with a mocked WebSocket that checks (1) it connects when enabled, (2) it reconnects after close (use fake timers for the 1.5 s retry), (3) cleanup closes the socket and stops retrying. Add to HANDOFF_FINDINGS.md: "frontend has no WebSocket->polling fallback; the app polls every 3 s unconditionally, so README wording 'polling fallback' is loose" and fix the README sentence if it claims a conditional fallback (read the exact sentence first).
Next: S-08d, the useEvents test (as S-09b), then S-10 (README counts script, tier H) and S-11 (template doc headers, tier H), then write GATE 8.5 REQUESTED (S-12, tier X) with the final `./handoff_verify.sh full` output and stop.

## S-08d · tier H · RESULT: PASS
Restored candidate scoring inside the timed block (backend/spectra/modules/twin/shadow.py), per REVIEW S-08b/S-08c/S-09. Both branches score again, bound to `_cand_scores` with the comment `# scored so cand_ms includes scoring cost`. No "validated" claim.
Test check: `grep -rn cand_ms tests spectra` → no test measures cand_ms; test_twin.py 27 passed.
Commit: f97cafe fix(twin): restore candidate scoring inside the timed block
VERIFY: RESULT ruff: PASS | RESULT pytest: PASS (341 passed, 1 warning in 32.92s)
Findings recorded (HANDOFF_FINDINGS.md, "Added after REVIEW S-08b/S-08c/S-09"): simulate crit removal (KeyError now only for non-asset nodes missing "criticality"; no validation in simulate.py) and loose "polling fallback" wording (docs/33 line 272; README has no such sentence, not changed).

## S-09b · tier H · RESULT: PASS
frontend/src/lib/useEvents.test.tsx (fake WebSocket, fake timers). Checks: connects when enabled; does not connect when disabled; reconnects 1.5 s after a server-side close (not at 1499 ms); cleanup closes the socket and stops retrying (10 s advance, still one socket).
Mutation check: retry changed to 1000 ms in src/lib/useEvents.ts → "reconnects 1.5 s after the server closes the socket" FAILED ("expected ... length of 1 but got 2"). Restored to 1500; suite back to 8 passed.
CHECK: npm test → Test Files 3 passed (3), Tests 8 passed (8); npm run lint → exit 0; npm run build → exit 0.
Commit: 8c65e8e test(frontend): cover useEvents connect, reconnect and cleanup

## S-10 · tier H · RESULT: PASS
Script: backend/scripts/check_readme_counts.py (stdlib + app). Measured: tests = pytest --collect-only (341), api = /api/ operations in OpenAPI (73), cli = top-level subcommands from spectra.cli.build_parser() (12).
Note: the card's `grep -n add_parser | wc -l` gives 34, which counts nested subcommands too; the script reads the parser at runtime instead.
RED (before README edit): `SPECTRA_DATA_DIR=$(mktemp -d) python scripts/check_readme_counts.py` → FAIL: README says 338 passing tests, measured 341; README says 77 HTTP routes, measured 73 (x3); exit 1.
README numbers changed (only numbers): 338→341 tests (lines 26, 39, 226, 258), 77→73 HTTP routes (lines 36, 146, 251). "12 commands" already matched. Dated note "294 tests" (line 273, validation 2026-09-29) left unchanged as a historical record.
GREEN: `python scripts/check_readme_counts.py` → measured {'tests': 341, 'api': 73, 'cli': 12} / README counts match the code / exit 0. Also exit 0 without SPECTRA_ADMIN_PASSWORD (the CI step's environment).
Caveat: "HTTP routes" is defined as OpenAPI /api/ operations (method+path), as the card specifies; the old README 77 could not be reproduced by that definition. Reviewer to confirm the definition.
CI step: backend job runs `cd backend && SPECTRA_DATA_DIR=$(mktemp -d) ../.venv/bin/python scripts/check_readme_counts.py` after pytest. CI YAML parses.
Commits: 7f37708 docs(readme): derive counts from the code and check them in CI; 303b2d6 ci: check README counts in the backend job
VERIFY: RESULT ruff: PASS | RESULT pytest: PASS (341 passed, 1 warning in 34.51s)

## S-11 · tier H · RESULT: PASS
Opened the first 40 lines of each: docs/09, 10, 11, 12, 15, 19, 20, 23. None contains a dated, attributable result (no tool version, date or command output); each has placeholders or plan text. All eight got the first line: `> STATUS: TEMPLATE — no real evidence recorded yet (see HANDOFF.md, Phase 10).` No other text changed (diff = 8 insertions).
Commit: a3a7262 docs: label template documents as templates

## GATE 8.5 REQUESTED · tier X · RESULT: WAITING-REVIEW
Branch: haiku/spectra-p85. Commits vs main: 25 (`git log --oneline main..haiku/spectra-p85`).
Final `./handoff_verify.sh full` output (verbatim):
RESULT ruff: PASS
RESULT pytest: PASS (341 passed, 1 warning in 34.65s)
RESULT frontend-build: PASS
Also run after that: `npm run lint` exit 0; `npm test` Test Files 3 passed, Tests 8 passed (exit 0); `check_readme_counts.py` exit 0; CI YAML parses.
Open items for the human, not blocking the gate:
  - CI workflow (ci.yml) has not run on GitHub: NOT RUN (GitHub only). Security job (pip-audit, gitleaks) also GitHub only.
  - HANDOFF_FINDINGS.md holds the open reviewer decisions (strict=False vs True, simulate KeyError change, docs/33 "polling fallback" wording, the 73 vs 77 route definition in README).
  - The "2 warnings" pytest observation is unexplained (direct runs show 1).
NEXT: none. Phase 9 does not start until REVIEW GATE-8.5: APPROVED is written in this ledger.

## REVIEWER PRE-REVIEW OF GATE 8.5 (Claude Sonnet 5.5, 2026-10-26) — the gate itself is the HUMAN's (tier X)
Whole-branch checks on haiku/spectra-p85 vs main (25 commits, 49 files): no key/db/env/model/data files in the diff; the only new `noqa` is the single approved B027 line; no skip/xfail/type-ignore/eslint-disable added; `./handoff_verify.sh full` = ruff PASS, 341 passed, frontend build PASS (I re-ran it); frontend lint + 8 tests pass per agent. Decisions on its open items: B905 stays `strict=False` (behaviour-preserving; upgrade later only with a test per site); the simulate.py KeyError change is accepted as a dead-code removal; "73 vs 77": README now states the measured, defined number (OpenAPI /api/ operations = 73) and the script enforces it — accepted; docs/33 "polling fallback" wording to be corrected in Phase 9 docs; the "2 warnings" oddity is unexplained and harmless.
NOT VERIFIED: GitHub Actions run (workflow, security and frontend jobs), gitleaks, pip-audit on the lock (Spectra's lock has not been audited yet — add as card S-13 before Phase 9).
Recommended human action: review `git log --oneline main..haiku/spectra-p85`, then merge or open a PR when you choose (the agent never pushes). Phase 9 starts only after `REVIEW GATE-8.5: APPROVED` from the human.
