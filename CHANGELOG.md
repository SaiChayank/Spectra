# Changelog

All notable changes to Spectra are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- scapy (GPL-2.0-only) is no longer a core dependency (ADR-011): pcap, pcapng and gzip are read by an in-tree `struct` reader and packets are decoded by an in-tree dissector (`spectra.capture.packet`). scapy remains only as the optional `live` extra (live NIC capture) and a dev/test dependency. Interface listing uses `socket.if_nameindex()` and returns names only (no Windows friendly names). The compose `capture` service builds its own image with the `live` extra.

### Added
- Operations (Phase 11): validated Prometheus exposition with latency histograms and an optional metrics-only token (**breaking:** counters renamed to `*_total`); a wheel that serves the dashboard same-origin and keeps data in a per-user directory; `spectra backup create|verify|restore` with an executed restore drill (demo scale); `docs/runbook.md`; digest-pinned non-root Docker image, `compose.yaml`, trivy in CI.
- Time-windowed correlation edges: graph edges carry first/last contact
  time, and paths, reachability and cascade accept `window_s` (Phase 9A).
- Report-only adversarial-retraining harness, `POST /api/model/harden`, with
  an opt-in scheduler (`SPECTRA_HARDEN_INTERVAL_H`, default off). It never
  promotes a model. A recorded experiment found that retraining does not
  reduce evasion; see `HANDOFF_FINDINGS.md` (Phase 9B).
- Opt-in synthetic benign augmentation at train time: `spectra train
  --augment N` and `augment` on `POST /api/model/train`, labelled synthetic
  everywhere. It has been validated on synthetic held-out traffic only
  (Phase 9C).
- Per-host-pair beaconing: flow-start cadence per (source, SNI-or-IP) pair feeds the bio `beacon_cadence` danger signal and a `regularity` field on graph edges; `SPECTRA_PAIR_WINDOW_FLOWS` (default 32). Not yet measured on real traffic (Phase 9D).
- Rolling PSI reference: `GET /api/model/drift` now also reports `psi_vs_train`, `psi_vs_recent` and `alert_level` (worse of the two); drift alerts fire on either. It re-baselines after legitimate shifts; it does not detect slow drift sooner than the training PSI (Phase 9E, see `HANDOFF_FINDINGS.md`).
- Audit signing-key epochs: `POST /api/audit/rotate-key` (ADMIN), migration v12 `audit_key_epochs`, a swappable `AuditKeyProvider`, epoch-aware checkpoint/certificate verification (Phase 9F; awaiting human security review).
- Federated aggregation: opt-in Shamir t-of-n over GF(2^127-1) with share commitments and shareholder/party dropout tolerance (`threshold`, `dropped_parties`, `dropped_shareholders` on `POST /api/tee/federate`; `spectra tee federate --threshold`). Default stays additive k-of-k (Phase 9G).
- Twin/graph staleness: `GET /api/twin/topology` and `GET /api/graph` report `hydrated_at`, `flow_lag` and `stale`; the Network page shows a freshness badge (Phase 9H). JA4S/JA4L were not built - JA4+ is not Apache-2.0-compatible (see `HANDOFF_FINDINGS.md`).
- Exit Gate 9: traceability matrix re-run (FR-2.2 closed, FR-4.1 scheduled mode with qualifiers); acceptance runner gained a `phase9` group and was run against a live server (`docs/acceptance-report-2026-11-06.md`).
- Phase 10 security evidence: custom Semgrep payload-access rule + CI `sast` job, licence policy check, npm-audit gates, metadata-only runtime probe, SAST/SCA/DAST reports with raw evidence, refreshed threat model, ADRs 005-009 (proposed). Found: uploaded captures are stored verbatim (documented).
- Login throttle now escalates: repeated failure episodes double the block (60 s up to 900 s), strikes decay, a success clears them; per-source, non-enumerating, bounded (Phase 10 §6, `test_login_backoff.py`). TOTP is not built - see `HANDOFF_FINDINGS.md`.
- Model evaluation report and model card (`docs/evaluation-report.md`, `docs/model-card.md`) from a reproducible synthetic evaluation (`scripts/eval_synthetic.py`, bootstrap intervals, 2 baselines, evasion rates, cross-sector table). Synthetic only; real-data runs not done.
- Optional TOTP second factor (`/api/auth/totp/{setup,enable,disable}`, `totp_code` on login, admin/CLI reset, secrets AES-GCM-encrypted under `totp.key`), awaiting security review (Phase 10, ADR-010).
- Deployment profiles: `SPECTRA_PROFILE=hardened` turns on proposed retention defaults (flows 30 d, detections 90 d, captures 14 d, events 30 d; default `local` unchanged); numbers need data-owner approval (`docs/retention.md`).
- `scripts/eval_real_pcap.py` and the first public-capture run (CTU-13 scenario 1): parser handled 21,254 real flows; the synthetic-trained detector flagged everything, benign control included, so the run is uninformative about detection (`docs/evaluation-report.md` §9).
- Prometheus: exposition validated with the official parser; new series (cumulative inference/db latency histograms, drift PSI and level, bio verdict counts, audit head, build info); optional metrics-only bearer token `SPECTRA_METRICS_TOKEN`; example scrape config and alert rules (`docs/monitoring.md`, `deploy/prometheus/`). **Breaking:** seven counters were renamed to end in `_total`.
- Ship plan for the public software release (`docs/34_ship_plan.md`).
- `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`, issue/PR
  templates and Dependabot configuration.

### Changed
- **JA4 now follows the published FoxIO spec** (`t13d1516h2_8daaf6152771_e5627efa2ab1` for the spec's worked example). Previously the value was JA4-style but not interoperable: decimal unsorted values, wrong extension count and ALPN characters, one merged hash. QUIC hellos now start with `q`; server hellos get no JA4; a GREASE-first `supported_versions` no longer yields a bogus negotiated version. Flows stored before this change keep their old JA4 value and will not match JA4 reference lists.
- Project rules and guardrails restored as `docs/project-rules.md`. The
  former `docs/16`/`docs/17` were removed in an earlier cleanup while still
  referenced as binding.

### Fixed
- A truncated pcap/pcapng is no longer silently analysed as if complete (scapy 2.8 treats a short read as end-of-file); it now raises `CaptureError` (HTTP 400). CI on Python 3.13 was red because of this and two tests that demanded bit-identical floats across CPUs; the matrix no longer fails fast.
- Dataset import no longer stores a second `<dataset>--<dataset>--<name>` copy of a file the fetch script just downloaded (it doubled disk use: 1.4 GB for the 696 MB CTU-13 flow file).
- Capture retention now deletes the stored upload file together with the row; previously the verbatim PCAP stayed on disk until the next restart.
- Ruff findings in merged Phase 7 code; react-hooks lint errors in the
  frontend.

### Fixed (Phase 11)
- A truncated capture file is now reported as an error instead of being read as a shorter, complete capture.

## [1.0.0] - 2026-09-29

Internal release (tag `v1.0.0`): live NIC capture accepted. Full history is in
the git log and `docs/readiness-report.md`.
