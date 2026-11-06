# ADR-008: Drift alerts fire on the worse of the training and recent PSI

**Status:** Proposed (2026-11-06) — written by the implementing agent; **accepting it is the owner's call.**

## Context
Plan item 9E proposed alerting on a rolling 'recent' PSI so slow drift is caught. A simulation at equal false-alarm rates showed a recent reference trips later than (or never, vs.) the training baseline on a slow shift, because it absorbs the drift.

## Decision
Report `psi_vs_train`, `psi_vs_recent` and `alert_level` = the worse of the two; alert and feed the immune layer on `alert_level`. The recent reference is a bounded, sampled history compared with the current window over bins merged 4:1.

## Consequences
No slow-drift detection is lost; the recent comparison re-baselines after legitimate shifts and flags abrupt change. The plan's Done-when ('recent trips first') is not met and is not claimed. The 40-bin training PSI keeps a noise floor of roughly 0.04–0.18 at a few hundred rows (pre-existing).

## Alternatives considered
Alert on recent only — would regress slow-drift detection; replace the training PSI — loses the stable reference.
