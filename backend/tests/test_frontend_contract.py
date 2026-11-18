"""Drift guard: the committed frontend contract must match what the app serves now."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "export_frontend_contract.py"


@pytest.mark.skipif(not SCRIPT.exists() or not (ROOT / "frontend" / "contract").exists(),
                    reason="not a source checkout (scripts/ or frontend/contract missing)")
def test_frontend_contract_is_current():
    res = subprocess.run([sys.executable, str(SCRIPT), "--check"], capture_output=True, text=True,
                         cwd=ROOT, timeout=600)
    assert res.returncode == 0, res.stdout[-2000:] + res.stderr[-1000:]
