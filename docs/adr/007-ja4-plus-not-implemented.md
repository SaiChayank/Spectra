# ADR-007: JA4+ (JA4S, JA4L, ...) is not implemented; base JA4 follows the spec

**Status:** Proposed (2026-11-06) — written by the implementing agent; **accepting it is the owner's call.**

## Context
FoxIO publishes base JA4 under BSD-3-Clause but JA4+ under FoxIO License 1.1: patent-pending, non-commercial copyright licence, no sublicensing, support/hosting counted as commercial. Spectra is released under Apache-2.0. Separately, the repo's own `ja4()` was JA4-style but not spec-compliant.

## Decision
Implement no JA4+ method. Rewrite `ja4()` to FoxIO's published JA4 for ClientHellos only (QUIC marked `q`), verified against the spec's worked example. Server hellos get no JA4.

## Consequences
Licence-clean Apache-2.0 release; JA4-keyed intel lists now match published values. Flows stored before the fix keep old values. If JA4S/JA4L are wanted, ship them as a separate optional plugin under FoxIO's terms or obtain an OEM licence — an owner decision.

## Alternatives considered
Clean-room JA4+ — does not remove the patent-pending exposure; vendoring FoxIO code into the Apache tree — misstates its licence.
