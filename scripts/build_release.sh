#!/usr/bin/env bash
# Build the release wheel with the compiled dashboard inside it.
#
#   scripts/build_release.sh            # -> backend/dist/spectra-<version>-py3-none-any.whl
#
# Needs node/npm and either `uv` or `python -m build`. The dashboard is built from
# frontend/package-lock.json (npm ci) and copied into backend/spectra/webui/, which is
# git-ignored and declared as package data, so the wheel serves it with `spectra serve`.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "== dashboard"
(cd "$ROOT/frontend" && npm ci --no-audit --no-fund && npm run build)

echo "== stage"
rm -rf "$ROOT/backend/spectra/webui" "$ROOT/backend/build" "$ROOT/backend/dist" "$ROOT"/backend/*.egg-info
cp -r "$ROOT/frontend/dist" "$ROOT/backend/spectra/webui"

echo "== wheel"
cd "$ROOT/backend"
if command -v uv >/dev/null 2>&1; then
  uv build --wheel --out-dir dist
else
  python -m build --wheel --outdir dist
fi
python "$ROOT/scripts/check_wheel.py" dist/*.whl
