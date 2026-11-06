# ADR-010: Optional TOTP second factor with an off-database encryption key

**Status:** Proposed (2026-11-07) — written by the implementing agent; **accepting it is the owner's call, and the code needs your security review before merge.**

## Context
Phase 10 item 6 asked for an optional second factor "stored as scrypt'd secret". A TOTP shared secret must be readable by the server to compute codes, so a one-way hash cannot work. Spectra has no external identity infrastructure by design.

## Decision
RFC 6238 TOTP (HMAC-SHA1, 30 s, 6 digits, ±1 step) in the stdlib plus `cryptography`. Secrets are AES-256-GCM encrypted (account id as AAD) under a 32-byte key in `totp.key` (mode 0600, outside the database), created on first use and never regenerated if lost. Enrolment needs the password; login takes the code in the same request and returns the generic 401 for any missing/wrong code (no oracle) while feeding the login throttle; the last accepted step is stored with an atomic compare-and-set (no replay). Eight single-use recovery codes are kept as SHA-256 hashes. Recovery from a lost device or key: admin `DELETE /api/users/{id}/totp` or `spectra auth totp-reset`. Opt-in per account; migration v13.

## Consequences
Database theft alone does not reveal secrets; database plus key file does, so the key file must be backed up and protected with the database. Losing the key file locks TOTP users out until a reset. No enrolment UI yet (API only), no enforcement, no WebAuthn. The behind-a-proxy throttle-sharing limit also applies to code guessing.

## Alternatives considered
Key in an environment variable — simpler to rotate but leaks into process listings and container configs; derive the key from the admin password — breaks on password change and offers no protection once the admin session exists; store the secret plain — a stolen database would defeat the factor; WebAuthn/passkeys — stronger but needs a browser UI and ceremony code beyond this phase; make the factor mandatory for ADMIN — would lock out the single-host admin on key loss.
