# ADR-006: Shamir t-of-n federation is opt-in; hash commitments, not VSS

**Status:** Proposed (2026-11-06) — written by the implementing agent; **accepting it is the owner's call.**

## Context
Federated aggregation was additive k-of-k: any dropout kills the round, and a tampered share is undetectable. Plan item 9G asks for k-of-n with share verification.

## Decision
Keep additive k-of-k as the default (byte-identical behaviour). `threshold=t` selects Shamir over GF(2^127-1) with SHA-256 commitments (secret nonce, domain-separated) per party share and per aggregate share, a polynomial-consistency check on surplus shares, and explicit errors below `t` responders or 2 surviving parties. Field arithmetic is checked against sympy-generated vectors and the published Wikipedia example.

## Consequences
Dropout tolerance and tamper rejection with no new dependencies. A malicious dealer who commits to consistent but wrong shares is caught only when surplus shares exist. Randomness is seeded, so the capability must stay `SIMULATED`.

## Alternatives considered
Feldman VSS — publishes g^secret, which for small quantized updates is brute-forceable and would leak every party's delta; Pedersen VSS — correct and hiding but needs the unreviewed curve code and is slow in pure Python (the documented upgrade); library Shamir — none found that is integer-additive over a prime field.
