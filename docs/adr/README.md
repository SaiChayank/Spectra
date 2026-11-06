# Architecture decision records

ADR-001..004 lived in the planning documents removed in commit `09638ce` (ADR-002, the software-TEE analogue, is described in `docs/00_reconciliation_note.md` and `docs/limitations.md` §4). Records from 005 onward are kept here. All are **Proposed** until the owner accepts them; the implementing agent does not mark any of them accepted.

| ADR | Decision |
|---|---|
| 005 | Audit signing keys have epochs bound to chain positions |
| 006 | Shamir t-of-n federation is opt-in; hash commitments, not VSS |
| 007 | JA4+ is not implemented; base JA4 follows the spec |
| 008 | Drift alerts fire on the worse of the training and recent PSI |
| 009 | Payload-access rule in CI and a runtime metadata-only probe |
