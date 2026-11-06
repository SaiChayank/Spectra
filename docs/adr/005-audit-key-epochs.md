# ADR-005: Audit signing keys have epochs bound to chain positions

**Status:** Proposed (2026-11-06) — written by the implementing agent; **accepting it is the owner's call.**

## Context
The audit log's hash chain is unkeyed; a signing key signs checkpoints and certificates. A single never-rotated key means one theft lets an attacker forge checkpoints over any range.

## Decision
Add `audit_key_epochs` (migration v12) and `AuditKeyProvider` (`public_key`, `sign`, `rotate`). Rotation chains an `audit.key_rotated` entry whose seq is the new epoch's `start_seq`. A checkpoint names its epoch inside the signed message and is valid only if that epoch's key signed it and its covered range ends inside the epoch's window. Startup registers an out-of-band key change as a new epoch with a chain entry. The old secret is overwritten.

## Consequences
A stolen current key cannot forge old-range checkpoints; a rotated-out key cannot sign new ones; pre-9F checkpoints verify as epoch 1. Does not protect against a key stolen before its rotation (for its own range), nor against history rewrites by someone who can recompute the whole chain. KMS/HSM becomes one class. The Schnorr/secp256k1 code is unchanged and still unreviewed.

## Alternatives considered
Keyed chain (HMAC per entry) — larger change, needs the key to read; external timestamping/anchoring — right long-term answer, needs infrastructure; one key forever — rejected.
