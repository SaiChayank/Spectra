#!/usr/bin/env bash
# usage: run_diff.sh FILE   (cap 2,000,000 packets per file; both readers)
set -u
f="$1"; here="$(cd "$(dirname "$0")" && pwd)"; b="$(basename "$f")"
SPECTRA_DATA_DIR="$(mktemp -d)" PYTHONPATH=backend /home/saikrishna/Projects/Spectra/backend/.venv/bin/python backend/scripts/diff_reader_vs_scapy.py diff "$f" --cap 2000000 > "$here/diff/$b.json" 2> "$here/diff/$b.err"
