# Spectra

**Before doing anything, read `HANDOFF.md` in this directory in full** (Part A audit, Part B work order, Part C rules R1–R41), then `docs/16_project_rules_file.md` and `docs/17_guardrails_context.md`. The functional roadmap is `docs/33_implementation_plan.md` Part II; `HANDOFF.md` adds the mandatory Phase 8.5 that must land first.

Non-negotiables:
- Metadata-only, always: no code path may decrypt, log or persist payload bytes. Add a test for it whenever you touch capture/parse/features/API responses.
- Never fabricate security evidence: SAST/DAST/SCA/validation docs only from real, dated, reproducible runs. Sign-offs and approvals are the human's.
- Importing `spectra.api.app` bootstraps an admin in `SPECTRA_DATA_DIR` — always point it at a temp dir for ad-hoc work.
- Keep `HANDOFF_PROGRESS.md` and `HANDOFF_FINDINGS.md`; no "done" without a command and real output; never weaken tests; never read/print secrets or key files.
- No destructive commands, no `git push`, no tags/releases unless the human says so this turn.

If you are a **Claude Haiku** agent: your work queue is `HAIKU_PLAN.md` (read it fully, then follow it card by card). `HANDOFF.md` is the long-form audit/rules reference.
