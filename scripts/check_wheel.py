#!/usr/bin/env python
"""Inspect a built wheel: it must carry the dashboard and must not carry anything private.

    python scripts/check_wheel.py backend/dist/spectra-1.0.0-py3-none-any.whl

Exit 1 on any problem. Checks: the compiled dashboard and the entry point are present; the
version matches spectra.__version__; no key material, databases, captures, env files, tests
or node_modules slipped in.
"""
from __future__ import annotations

import fnmatch
import re
import sys
import zipfile

REQUIRED = ["spectra/webui/index.html", "spectra/cli.py", "spectra/api/app.py",
            "spectra/api/webui.py"]
FORBIDDEN = ["*.key", "*admin_bootstrap*", "*.db", "*.db-wal", "*.db-shm", "*.sqlite*",
             "*.pcap", "*.pcapng", "*.joblib", ".env", ".env.*", "*/.env", "*/tests/*",
             "tests/*", "*node_modules*", "*.pyc", "*__pycache__*", "*.pem", "*/.git/*"]


def main(path: str) -> int:
    problems: list[str] = []
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        info = {n: zf.getinfo(n).file_size for n in names}
        meta = next((n for n in names if n.endswith(".dist-info/METADATA")), None)
        text = zf.read(meta).decode() if meta else ""
        entry = next((n for n in names if n.endswith("entry_points.txt")), None)
        entry_text = zf.read(entry).decode() if entry else ""
        pkg_init = zf.read("spectra/__init__.py").decode() if "spectra/__init__.py" in names else ""
    for need in REQUIRED:
        if need not in names:
            problems.append(f"missing {need}")
    if not any(n.startswith("spectra/webui/assets/") and n.endswith(".js") for n in names):
        problems.append("no compiled JavaScript under spectra/webui/assets/")
    for n in names:
        for pat in FORBIDDEN:
            if fnmatch.fnmatch(n, pat) or fnmatch.fnmatch(n.rsplit("/", 1)[-1], pat):
                problems.append(f"forbidden file in wheel: {n} (matches {pat})")
                break
    if not any(n.endswith(".dist-info/licenses/LICENSE") for n in names):
        problems.append("the Apache-2.0 LICENSE text is not in the wheel")
    if "spectra = spectra.cli:main" not in entry_text:
        problems.append("console script `spectra` is not declared")
    ver = re.search(r"^Version: (.+)$", text, re.M)
    code_ver = re.search(r'__version__ = "([^"]+)"', pkg_init)
    if not ver or not code_ver or ver.group(1) != code_ver.group(1):
        problems.append(f"version mismatch: wheel {ver and ver.group(1)} vs package {code_ver and code_ver.group(1)}")
    lic = re.search(r"^License(?:-Expression)?: (.+)$", text, re.M)
    total = sum(info.values())
    print(f"{path}\n  {len(names)} files, {total / 1e6:.2f} MB uncompressed, version "
          f"{ver and ver.group(1)}, license {lic and lic.group(1)}")
    print(f"  dashboard files: {sum(n.startswith('spectra/webui/') for n in names)}")
    for p in problems:
        print("  PROBLEM:", p)
    print("  OK" if not problems else f"  {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]) if len(sys.argv) == 2 else print(__doc__) or 2)
