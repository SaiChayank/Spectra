# HANDOFF_FINDINGS (S-08 remaining ruff items, for reviewer decision)

Ruff 0.17.2 from the lock venv, rules E4,E7,E9,F,B. After S-08: `Found 5 errors.` Not fixed by Haiku because each change alters behaviour or removes code, which the card says to list rather than guess.

1. backend/spectra/capture/base.py:38 B027 `CaptureSource.close` is an empty non-abstract method in an ABC. Fix options: add `@abstractmethod` (changes instantiation: every subclass that does not override `close` becomes uninstantiable), or keep as a no-op and suppress (not allowed). Reviewer decides.
2. backend/tests/test_tee.py:305 B017 `pytest.raises(Exception)` around `engine.tee_federate(deltas=[[0.1]])` (one party). Narrowing needs the concrete exception class (the module imports FederatedError and TeeError; which one is raised was not checked). Narrowing the test changes what it proves. Reviewer decides.
3. backend/spectra/modules/twin/shadow.py:98 F841 `cand_scores = cand.score(X)` is unused. Removing the line removes a call; ruff only offers this as an unsafe fix. Reviewer decides.
4. backend/spectra/modules/twin/simulate.py:149 F841 `crit = {...}` is an unused dict comprehension. Pure, but removal is ruff's unsafe-only fix; reviewer decides.
5. backend/tests/test_capture_resources.py:70 F841 `data = fh.read()` is unused. Removing it drops a file read inside a test; reviewer decides.

Also for the reviewer (not an error, a choice made in S-08):
- B905 was resolved with explicit `strict=False` at 6 sites (cli.py:410, features/extractor.py:130, ml/model.py:157, modules/audit/log.py:408, parse/quic.py:202, tests/test_flow.py:45). This keeps today's behaviour exactly. `strict=True` would raise on length mismatch, which is a behaviour change; reviewer may upgrade where lengths are guaranteed equal.
- B007 resolved by renaming unused loop variables to `_` or `_sid` (demo.py x2, tests/test_edge_native.py, tests/test_streaming.py).
- Ruff is NOT PASS, so the ruff step was not added to CI (card S-08 rule).

## Added after REVIEW S-08b/S-08c/S-09
- backend/spectra/modules/twin/simulate.py (crit removal, commit 04fcc52): before, the dict comprehension read `criticality` for EVERY node, so a topology node without it raised KeyError. After, only nodes that reach the other accessors still raise. Those are `resolve_initial` (line ~61, asset nodes only) and `_resolved_controls` (line ~87, asset nodes only) and `simulate` (line ~186, asset nodes only). So a non-asset node missing `criticality` no longer raises. No validation of the topology exists in simulate.py (grep finds none). Reviewer: decide whether to add validation, which is outside this card.
- Frontend polling wording: the frontend has no WebSocket-to-polling fallback. App.tsx polls every 3 s unconditionally while signed in (setInterval refresh, 3000); BioPanel and EdgePanel poll every 5 s. The planning doc docs/33_implementation_plan.md line 272 says "3 s polling fallback", which is loose. README.md contains no such sentence (checked), so README was not changed. docs/33 is outside this card's files; left untouched.
