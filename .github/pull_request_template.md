## What and why

<!-- One logical change. Link the issue or plan section (e.g. docs/34 §B). -->

## Checklist

- [ ] Tests added or updated first; no existing test weakened
- [ ] `ruff`, `pytest`, README count check and frontend lint/test/build pass locally
- [ ] Metadata-only: if this touches capture/parse/features/API responses, a test proves no payload bytes leak
- [ ] New API routes carry a permission and have per-role allow/deny tests
- [ ] Schema changes are a numbered migration with an upgrade test
- [ ] Any numbers in docs come from a real, dated run (command + output)
- [ ] `CHANGELOG.md` updated under **Unreleased**
- [ ] Crypto/auth/TEE change: human security review requested
