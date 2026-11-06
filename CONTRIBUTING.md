# Contributing to Spectra

Thanks for helping. Read `docs/project-rules.md` first. Its rules are
non-negotiable, the first being that **no code path may decrypt, log or
persist packet payload**.

## Setup

See `docs/local-setup.md`. In short (each line runs from the repo root):

```bash
cd backend && uv venv .venv && uv pip install --require-hashes -r requirements.lock
cd frontend && npm ci
```

Importing `spectra.api.app` bootstraps an admin account in
`SPECTRA_DATA_DIR`. Point that variable at a temporary directory for ad-hoc
work and tests.

## Before you open a PR

Run what CI runs (each line from the repo root):

```bash
uvx ruff check backend/spectra backend/tests
cd backend && .venv/bin/python -m pytest -q
cd backend && SPECTRA_DATA_DIR=$(mktemp -d) .venv/bin/python scripts/check_readme_counts.py
cd frontend && npm run lint && npm test && npm run build
```

- **Tests first.** New behaviour comes with a test. Never weaken or delete an
  existing test to make a change pass.
- **Metadata-only.** If you touch `capture/`, `parse/`, `features/` or an
  API response, add a test proving no payload bytes reach storage, logs,
  features or responses.
- **New API route:** it must appear in OpenAPI and carry an explicit
  permission, with allow/deny tests for each role (ADMIN, ANALYST, VIEWER).
- **Schema change:** add a numbered migration in `spectra/db/migrations.py`
  with an upgrade test. Nothing else may `CREATE` or `ALTER`.
- **Honest numbers.** Do not put benchmark, accuracy or security-scan
  results in docs unless they come from a real, dated, reproducible run.
- **Crypto, auth or TEE code** needs a human security review before merge.

## Commits and PRs

- Use Conventional Commits (`feat(corr): …`, `fix(auth): …`, `docs: …`). The
  changelog is built from them.
- One logical change per PR. Update `CHANGELOG.md` under **Unreleased**.
- Changing counts (tests, routes, CLI commands) means updating `README.md`;
  CI checks this.

## Reporting bugs

Open an issue with the template. Security problems go through `SECURITY.md`,
not public issues.

## License

By contributing you agree that your contributions are licensed under the
Apache License 2.0 (see `LICENSE`).
