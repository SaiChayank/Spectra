"""THIRD_PARTY_NOTICES.md must match the lockfiles (scripts/gen_third_party_notices.py --check).

Runs only when its inputs exist: frontend/node_modules (npm ci) and an environment matching
backend/requirements.lock with the `live` extra (the generator exits 2 when it does not).
CI runs the same check in the `package` job against the built wheel.
"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(ROOT, "scripts", "gen_third_party_notices.py")


def test_notices_file_is_current():
    if not os.path.isdir(os.path.join(ROOT, "frontend", "node_modules")):
        pytest.skip("frontend/node_modules missing (run npm ci)")
    r = subprocess.run([sys.executable, SCRIPT, "--check"], capture_output=True, text=True, check=False)
    if r.returncode == 2:
        pytest.skip("environment does not match the lockfiles: " + r.stderr.strip()[-300:])
    assert r.returncode == 0, r.stderr or r.stdout
