# Changelog

All notable changes to Spectra are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
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
- Ship plan for the public software release (`docs/34_ship_plan.md`).
- `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`, issue/PR
  templates and Dependabot configuration.

### Changed
- **JA4 now follows the published FoxIO spec** (`t13d1516h2_8daaf6152771_e5627efa2ab1` for the spec's worked example). Previously the value was JA4-style but not interoperable: decimal unsorted values, wrong extension count and ALPN characters, one merged hash. QUIC hellos now start with `q`; server hellos get no JA4; a GREASE-first `supported_versions` no longer yields a bogus negotiated version. Flows stored before this change keep their old JA4 value and will not match JA4 reference lists.
- Project rules and guardrails restored as `docs/project-rules.md`. The
  former `docs/16`/`docs/17` were removed in an earlier cleanup while still
  referenced as binding.

### Fixed
- Ruff findings in merged Phase 7 code; react-hooks lint errors in the
  frontend.

## [1.0.0] - 2026-09-29

Internal release (tag `v1.0.0`): live NIC capture accepted. Full history is in
the git log and `docs/readiness-report.md`.
