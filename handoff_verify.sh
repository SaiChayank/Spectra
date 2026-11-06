#!/usr/bin/env bash
# One-command truth for the Spectra handoff. Usage: ./handoff_verify.sh [fast|full]
#   fast (default): install deps from requirements.txt, ruff, pytest (hermetic temp data dir)
#   full: fast + frontend `npm ci && npm run build`
# The venv lives outside the repo (override with HANDOFF_ENV). Prints a RESULT line per check.
set -uo pipefail
TMPD="$(mktemp -d)"; trap 'rm -rf "$TMPD"' EXIT
ROOT="$(cd "$(dirname "$0")" && pwd)"
ENVDIR="${HANDOFF_ENV:-$HOME/.cache/handoff/spectra}"
MODE="${1:-fast}"
[ -x "$ENVDIR/bin/python" ] || uv venv --python 3.13 "$ENVDIR" >/dev/null 2>&1 || { echo "RESULT env: FAIL (uv venv)"; exit 2; }
uv pip install --python "$ENVDIR/bin/python" -q -r "$ROOT/backend/requirements.txt" pytest httpx ruff >/dev/null 2>&1 || { echo "RESULT install: FAIL"; exit 2; }
rc=0
cd "$ROOT/backend"
if "$ENVDIR/bin/ruff" check spectra tests >$TMPD/handoff_spectra_ruff.txt 2>&1; then echo "RESULT ruff: PASS"; else echo "RESULT ruff: FAIL ($(grep -E "^Found" $TMPD/handoff_spectra_ruff.txt | tail -n 1))"; rc=1; fi
export SPECTRA_DATA_DIR="$(mktemp -d)"
"$ENVDIR/bin/python" -m pytest -q -p no:cacheprovider 2>&1 | tail -n 15 > $TMPD/handoff_spectra_pytest.txt
summary="$(tail -n 1 $TMPD/handoff_spectra_pytest.txt)"
if echo "$summary" | grep -q "failed\|error"; then echo "RESULT pytest: FAIL ($summary)"; grep FAILED $TMPD/handoff_spectra_pytest.txt | head -n 5; rc=1; else echo "RESULT pytest: PASS ($summary)"; fi
rm -rf "$SPECTRA_DATA_DIR"
if [ "$MODE" = "full" ]; then
  cd "$ROOT/frontend" && npm ci >/dev/null 2>&1 && npm run build >$TMPD/handoff_spectra_fe.txt 2>&1 && echo "RESULT frontend-build: PASS" || { echo "RESULT frontend-build: FAIL"; rc=1; }
fi
exit $rc
