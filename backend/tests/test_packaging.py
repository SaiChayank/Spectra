"""Release-packaging invariants (no build needed): versions, license copy, wheel checker."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import zipfile

import spectra

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
ROOT = os.path.dirname(BACKEND)


def _load_checker():
    spec = importlib.util.spec_from_file_location(
        "check_wheel", os.path.join(ROOT, "scripts", "check_wheel.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_python_and_frontend_versions_agree():
    pyproject = open(os.path.join(BACKEND, "pyproject.toml"), encoding="utf-8").read()
    py_version = re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
    with open(os.path.join(ROOT, "frontend", "package.json"), encoding="utf-8") as fh:
        js_version = json.load(fh)["version"]
    assert py_version == spectra.__version__ == js_version


def test_the_packaged_license_is_the_repository_license():
    a = open(os.path.join(ROOT, "LICENSE"), "rb").read()
    b = open(os.path.join(BACKEND, "LICENSE"), "rb").read()
    assert a == b, "backend/LICENSE drifted from LICENSE (copy it: cp LICENSE backend/LICENSE)"
    assert b"Apache License" in a


def _wheel(tmp_path, extra=(), drop=()):
    files = {
        "spectra/__init__.py": f'__version__ = "{spectra.__version__}"\n',
        "spectra/cli.py": "", "spectra/api/app.py": "", "spectra/api/webui.py": "",
        "spectra/webui/index.html": "<html></html>",
        "spectra/webui/assets/index-abc.js": "x",
        f"spectra-{spectra.__version__}.dist-info/METADATA":
            f"Name: spectra\nVersion: {spectra.__version__}\nLicense-Expression: Apache-2.0\n",
        f"spectra-{spectra.__version__}.dist-info/entry_points.txt":
            "[console_scripts]\nspectra = spectra.cli:main\n",
        f"spectra-{spectra.__version__}.dist-info/licenses/LICENSE": "Apache License",
    }
    for name in drop:
        files.pop(name)
    for name in extra:
        files[name] = "secret"
    path = tmp_path / "w.whl"
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return str(path)


def test_wheel_checker_accepts_a_good_wheel_and_rejects_bad_ones(tmp_path, capsys):
    chk = _load_checker()
    assert chk.main(_wheel(tmp_path)) == 0
    for planted in ("spectra/audit_signing.key", "spectra/data/spectra.db", "spectra/admin_bootstrap.txt",
                    "spectra/cap.pcap", "spectra/.env", "tests/test_x.py", "spectra/models/m.joblib",
                    "spectra/webui/node_modules/x.js"):
        assert chk.main(_wheel(tmp_path, extra=[planted])) == 1, planted
    assert "forbidden file in wheel" in capsys.readouterr().out
    assert chk.main(_wheel(tmp_path, drop=["spectra/webui/index.html"])) == 1      # dashboard missing
    assert chk.main(_wheel(tmp_path, drop=[f"spectra-{spectra.__version__}.dist-info/licenses/LICENSE"])) == 1
