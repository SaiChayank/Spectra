# Handoff: where the project stands (written 2026-11-08)

Read first, in order: `CLAUDE.md`, `HANDOFF.md`, `docs/project-rules.md`, then `docs/35_threat_engine_plan.md` (the plan the owner approved on
2026-11-08) and `docs/evaluation-report.md` §10-17 (everything measured so far). Rules that matter most: metadata only (no payload bytes
anywhere), no fabricated evidence, run the FULL pytest suite before any push, never push to `main`, tag, or release unless the owner says so
that turn, point `SPECTRA_DATA_DIR` at a temp dir for ad-hoc work.

## 1. State of `main`

* Phases 0-11 and Phase B / Gate B evidence are done, as far as an agent can do them. CI on `main` was green on the Dockerfile fix
  (zlib1g upgrade). 879 backend tests at the time of writing (check `docs/testing.md`).
* Product verdict (honest): a solid, metadata-only platform; **the detector is weak** (docs/evaluation-report.md §14) and, on the one real
  C2 family we have, **real RITA beats Spectra's beacon score: AUC 0.99 vs 0.85, recall 0.9 vs 0.0 at a 1 % pair-FPR budget** (§17).
  Closing that gap is the first engineering goal.
* Phase E0 of docs/35 (benchmark backbone) is mostly done: `backend/scripts/spectra_bench.py` + frozen `ci/prereg/e0.json` reproduce the CTU
  and Gate B numbers exactly (§15 end); beacon jitter sweep with hard negatives (§15); leave-family-out with a TLS/port ablation (§16);
  real RITA vs Spectra on CIC-2018 Bot pairs (§17).

## 2. What is NOT done (E0 remainder, then the plan)

1. **Lab C2 corpus** (owner approved Sliver, Mythic and Havoc on 2026-11-08; **nothing downloaded or run yet**). Rules: official upstream
   release only, verify checksums/signatures, run only inside a Docker network with `internal: true` (no internet egress), no host ports,
   record framework version, interval, jitter, transport per run, hash every pcap. Then run Zeek -> RITA and Spectra on those pcaps.
   This is also the only way to run RITA on a jitter sweep.
2. Cover HIKARI, CIC-2018 and the Suricata/Zeek baselines in the runner (they need external IDS outputs).
3. E1 (richer metadata), E2 (detectors; E2.1 beaconing first), E3, E4 ... see docs/35 §4-8.
4. The old open items: Phase 11 (real upgrade rehearsal, 503 on DB lock/disk full, `/api/health` writability probe, upload expiry,
   Schemathesis findings), release phase (docs site, signing, packaging), the nightly benchmark's first CI run.

## 3. Work that exists only on the owner's machine until committed

* Two session worktrees under `.claude/worktrees/`:
  * `claude/nostalgic-moore-fd6f1f`: scapy -> in-tree pcap reader (ADR-011). No commits; edits uncommitted in `pyproject.toml`,
    `capture/{base,live,pcap_file,sanitize}.py`. Unverified.
  * `claude/focused-volhard-ffb223`: host-pair beaconing detector (`docs/plan-beaconing-detector.md`). One commit (the evaluation
    protocol), uncommitted `config.py`, `modules/corr/beacon.py`, `services/detection.py`, new `tests/test_beacon.py`. Unverified.
  Commit and push each branch from its worktree before anything else; do not merge either into `main` without the owner's say-so, and run the
  full suite on the branch first. The beacon protocol fixes the metrics before the first run: do not tune on the test split.
* **Benchmark data, not in git (11 GB): `~/Projects/Spectra_bench_data`.** Re-fetchable: sources, licences and SHA-256 hashes are in
  `docs/datasets.md`; `backend/scripts/fetch_datasets.py` for CTU; CIC-2018 came from range requests (slowest to redo, copy it if possible).
  Zeek logs (`zeek/out`, `zeek/cic-out`), Suricata outputs (`suricata/`) and `tools/rita` (compose file, config with feeds off, `.env`) are
  rebuildable from the helper scripts there (`run_zeek.sh`, `run_zeek_cic.sh`, `run_suricata*.sh`). Benchmark scripts take the root as an
  argument.

## 4. How to run what exists

```bash
cd backend && python -m venv .venv && .venv/bin/pip install -c requirements.lock -e '.[dev]'   # see docs/local-setup.md
.venv/bin/python -m pytest -q                                   # ~7.5 min, must pass before any push
.venv/bin/ruff check .
.venv/bin/python scripts/spectra_bench.py --prereg ../ci/prereg/e0.json --bench-data ~/Projects/Spectra_bench_data --out ../docs/evidence/<date>/bench-run
.venv/bin/python scripts/bench_beacon_sweep.py --data ~/Projects/Spectra_bench_data/datasets --out <json>   # ~6 min
.venv/bin/python scripts/bench_rita_cic.py --root ~/Projects/Spectra_bench_data --out <json>                 # needs the RITA stack up:
( cd ~/Projects/Spectra_bench_data/tools/rita && docker compose up -d clickhouse )
```
Docker images used: `zeek/zeek:7.0.5`, `jasonish/suricata:7.0.8`, `ghcr.io/activecm/rita:v5.1.2` (GPL-3.0, external benchmark tool only,
never shipped or linked), `clickhouse/clickhouse-server:24.1.6`. The prereg was extended after its first run (a `lofo` step was added), so the
2026-11-08 manifest hash differs from the current file; say so if you cite it. Lesson recorded in §17: always check how a competing tool keys its
output (RITA's SNI beacons have a blank destination IP) before reporting that it missed something.

## 5. Owner-only items (an agent must not do these)

Making the repo public (after a gitleaks scan); picking the package name, the trademark search and the PyPI project; security sign-offs
(9F, 9G, TOTP, login back-off, metrics-token principal, ADRs 005-011); the own-network 24-72 h benign capture (`docs/human-benchmark-tasks.md`
task 12, then `bench_own_network.py`); the live-capture sizing run (`sudo scripts/bench_perf.sh`, task 13); recruiting release-candidate
testers; the docs domain; a SIEM webhook (only if authorised); licence sign-off for every new dataset. No credentials, tokens or key files
go into the repo or into chat.

## 6. Known pitfalls

* Memory/tmpfs pressure on the dev machine (11 GB RAM, other containers) can cause a spurious SQLite "disk I/O error" in a full run; free
  temp files and rerun.
* The README/docs test counts are checked by CI: update them whenever tests are added.
* Importing `spectra.api.app` creates an admin in `SPECTRA_DATA_DIR`: use a temp dir.
* CTU-Normal 2017 pcaps carry 1970-based timestamps (RITA/Zeek logs show 1970); the 2011 botnets carry real dates.
* The CTU leave-family-out result is confounded by capture era (2011 vs 2017) and is not evidence of detection (§16).
