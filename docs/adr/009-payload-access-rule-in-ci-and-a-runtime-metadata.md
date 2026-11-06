# ADR-009: Payload-access rule in CI and a runtime metadata-only probe

**Status:** Proposed (2026-11-06) — written by the implementing agent; **accepting it is the owner's call.**

## Context
The project's first non-negotiable is that no code path decrypts, logs or persists payload. Until now only review enforced it.

## Decision
Add a scapy-specific Semgrep rule that fails CI for payload reads outside `parse/` (with annotated must-flag/must-not-flag fixtures), and a pytest probe that plants a marker in payload, crawls every GET route, the in-memory buffers and every file in the data directory, and pins the single place the marker may exist.

## Consequences
Two independent layers (static and runtime) with a mutation-checked probe. The probe found that uploaded captures are stored verbatim — now documented and pinned. The rule is syntactic and misses payload copied through other variables.

## Alternatives considered
Review only — status quo; taint analysis — not available in the free Semgrep rules used here.
