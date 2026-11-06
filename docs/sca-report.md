# Spectra — Software Composition Analysis (SCA) report

**Date:** 2026-11-06 · **Commit:** `24221c9` · **Evidence:** `docs/evidence/2026-11-06/` — `pip-audit.json`, `npm-audit-before-fix.json`, `npm-audit.json`, `npm-audit-production.txt`, `licenses.json`. Engineering evidence, not a sign-off.

## 1. Vulnerabilities

| Scope | Tool / command | Result |
|---|---|---|
| Python, hash-locked (`backend/requirements.lock`) | pip-audit 2.10.1 `-r backend/requirements.lock --disable-pip --no-deps` | **65 packages audited, 0 known vulnerabilities** |
| Frontend, before | `npm audit --json` (npm 11.19.0 / node 26.8.1) | 12: **2 high** (`vite` 8.3.0–8.3.2 via `launch-editor`, dev server; `source-map-js` event-loop DoS, build time), 10 moderate |
| Frontend, after `npm audit fix` (lockfile-only, non-breaking) | `npm audit --json` | **0 high, 0 critical**, 10 moderate |
| Frontend, production tree only | `npm audit --omit=dev` | **0 vulnerabilities** (3 runtime packages: react, react-dom, recharts) |

The 10 remaining moderates are one `minimatch` ReDoS (GHSA-g3hv-75wg-m249) reached through ESLint and typescript-eslint. They are **dev-only** (linting the repo's own files; nothing ships), and the offered "fix" is a breaking ESLint downgrade (`--force`), so they are left open and listed here. After the fix: frontend `eslint` exit 0, `tsc` clean, 11 vitest tests pass, `vite build` ok.

CI now gates `npm audit --omit=dev` and `npm audit --audit-level=high`; pip-audit was already gating.

## 2. Pins and updates

Python dependencies are hash-pinned (`requirements.lock`, installed with `--require-hashes`); a throwaway venv built from it for this run installed cleanly on Python 3.13. The frontend uses `package-lock.json`. Dependabot (pip, npm, GitHub Actions; weekly) was added in the housekeeping step. `ruff` and `uvx`-run tools are not pinned in the lock; the CI `sast` job pins Semgrep 1.184.0 and Bandit 1.9.4.

## 3. Licences

`backend/scripts/check_licenses.py` checks every locked Python package (read from the installed environment, honouring platform markers such as `colorama ; sys_platform == 'win32'`) and every `package-lock.json` entry against `security/license-policy.json`; production npm dependencies must pass, dev-only ones are reported. **357 packages: 355 allowed, 1 dev-only note, 1 pending decision, 0 failures.**

* **OPEN OWNER DECISION — `scapy` 2.8.0, GPL-2.0-only.** A hard runtime dependency imported in six modules, while Spectra's own `LICENSE` is Apache-2.0. Recorded as a *pending* exception (`owner` and `expires` blank — tooling cannot approve it). Options: relicense GPL-compatibly, replace scapy with a permissive pcap reader, or legal advice. The release plan's Docker image and offline bundle would redistribute scapy, which is where this bites.
* `caniuse-lite` 1.0.30001819 — CC-BY-4.0 (browser-support *data*, build tool only, not shipped).
* BlueOak-1.0.0 (`lru-cache`, `minimatch`, dev-only) was added to the allowlist: a permissive, OSI-approved licence.
* JA4+ (FoxIO License 1.1) is not a dependency and is deliberately not implemented — see `HANDOFF_FINDINGS.md` "9H findings".

## 4. Not covered

OSV-Scanner / Trivy / Syft (SBOM, image scan): no binaries or images here, and no container image exists yet (Phase 11). Transitive licence text beyond the declared metadata field was not read. Vulnerability databases are point-in-time: re-run before release.
