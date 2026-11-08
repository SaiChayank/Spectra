"""spectra_bench.py: manifest hashes outputs, records failure, stops on it."""
import json
import subprocess
import sys
from pathlib import Path

RUNNER = Path(__file__).resolve().parent.parent / "scripts" / "spectra_bench.py"


def _run(tmp_path, steps):
    (tmp_path / "ok.py").write_text("import sys,json;json.dump({'x':1},open(sys.argv[1],'w'))")
    (tmp_path / "bad.py").write_text("raise SystemExit(3)")
    pre = tmp_path / "p.json"
    pre.write_text(json.dumps({"steps": steps}))
    out = tmp_path / "out"
    r = subprocess.run([sys.executable, str(RUNNER), "--prereg", str(pre), "--bench-data", "-", "--out", str(out)],
                       capture_output=True, text=True)
    return r.returncode, json.loads((out / "manifest.json").read_text())


def test_success_and_failure_recorded(tmp_path, monkeypatch):
    # scripts resolve relative to backend/, so point at absolute temp scripts
    ok = {"id": "a", "script": str(tmp_path / "ok.py"), "args": ["{out}/a.json"], "out": "a.json"}
    bad = {"id": "b", "script": str(tmp_path / "bad.py"), "args": [], "out": "b.json"}
    never = {"id": "c", "script": str(tmp_path / "ok.py"), "args": ["{out}/c.json"], "out": "c.json"}
    rc, m = _run(tmp_path, [ok, bad, never])
    assert rc == 1
    assert [s["id"] for s in m["steps"]] == ["a", "b"]  # stopped at the failure
    assert m["steps"][0]["ok"] and len(m["steps"][0]["sha256"]) == 64
    assert not m["steps"][1]["ok"] and m["steps"][1]["sha256"] is None
