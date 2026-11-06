#!/usr/bin/env python
"""Dependency licence check against security/license-policy.json.

    python scripts/check_licenses.py [--json OUT] [--frontend]

Python packages are the ones in ``requirements.lock``, read from the
*running interpreter's* environment (install the lockfile first, as CI does).
``--frontend`` also checks ``frontend/package-lock.json`` (production
dependencies must pass; dev-only ones are reported, not enforced).

Exit 1 = a package has a licence that is neither allowed nor covered by an
exception.  An exception with ``status: pending`` is an OPEN owner decision:
it is printed loudly and listed, but does not fail the run - only the owner
can turn it into ``approved`` (or remove the dependency).
"""
from __future__ import annotations

import argparse
import importlib.metadata as md
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
POLICY = os.path.join(ROOT, "security", "license-policy.json")
LOCK = os.path.join(ROOT, "backend", "requirements.lock")
NPM_LOCK = os.path.join(ROOT, "frontend", "package-lock.json")

#: trove classifier tail -> SPDX-ish name
CLASSIFIERS = {
    "MIT License": "MIT",
    "BSD License": "BSD",
    "Apache Software License": "Apache-2.0",
    "Python Software Foundation License": "PSF-2.0",
    "ISC License (ISCL)": "ISC",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "The Unlicense (Unlicense)": "Unlicense",
    "Public Domain": "Unlicense",
}
ALIASES = {"MIT License": "MIT", "BSD License": "BSD", "Apache 2.0": "Apache-2.0",
           "Apache License 2.0": "Apache-2.0", "Apache-2": "Apache-2.0"}


def load_policy(path: str = POLICY) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def allowed_expression(expr: str, allowed: set[str]) -> bool:
    """SPDX-style ``A AND B`` / ``A OR B`` (no parentheses): every AND part
    must be allowed, any OR alternative may satisfy it."""
    expr = ALIASES.get(expr.strip(), expr.strip())
    if not expr:
        return False
    for alt in re.split(r"\s+OR\s+", expr):
        parts = [ALIASES.get(p.strip(), p.strip()) for p in re.split(r"\s+AND\s+", alt)]
        if parts and all(p in allowed for p in parts):
            return True
    return False


def python_license(name: str) -> str:
    meta = md.metadata(name)
    expr = (meta.get("License-Expression") or "").strip()
    if expr:
        return expr
    cls = [CLASSIFIERS.get(c.split("::")[-1].strip(), c.split("::")[-1].strip())
           for c in (meta.get_all("Classifier") or []) if c.startswith("License ::")
           and "OSI Approved" in c or c.startswith("License :: Public Domain")]
    cls = [c for c in cls if c != "OSI Approved"]
    if cls:
        return " AND ".join(dict.fromkeys(cls))
    lic = (meta.get("License") or "").strip()
    first = lic.splitlines()[0] if lic else ""
    return first if lic and len(lic) <= 60 and "\n" not in lic else "UNKNOWN"


def marker_applies(marker: str) -> bool:
    """Does an environment marker (``sys_platform == 'win32'``) hold here?"""
    try:
        from packaging.markers import Marker
        return bool(Marker(marker.strip().rstrip("\\").strip()).evaluate())
    except Exception:  # noqa: BLE001 - no packaging / odd marker: be strict, check it
        return True


def locked_python_packages(lock: str = LOCK) -> list[str]:
    """Names pinned in the lockfile that apply to this platform."""
    names = []
    with open(lock, encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r"^([A-Za-z0-9_.\-]+)==[^;\s\\]+\s*(?:;\s*(.+))?", line)
            if m and (not m.group(2) or marker_applies(m.group(2))):
                names.append(m.group(1))
    return names


def judge(name: str, lic: str, policy: dict) -> tuple[str, str]:
    """-> (status, note) with status in ok | approved | pending | FAIL."""
    allowed = set(policy["allowed"])
    if allowed_expression(lic, allowed):
        return "ok", ""
    for ex in policy.get("exceptions", []):
        if ex["package"].lower() == name.lower():
            if ex.get("status") == "approved":
                return "approved", f"owner={ex.get('owner')} expires={ex.get('expires')}"
            return "pending", ex.get("reason", "")
    return "FAIL", "licence is not on the allowlist and has no exception"


def check_python(policy: dict) -> list[dict]:
    rows = []
    for name in locked_python_packages():
        try:
            lic = python_license(name)
            ver = md.version(name)
        except md.PackageNotFoundError:
            rows.append({"ecosystem": "python", "package": name, "version": "",
                         "license": "NOT-INSTALLED", "status": "FAIL",
                         "note": "install the lockfile first"})
            continue
        status, note = judge(name, lic, policy)
        rows.append({"ecosystem": "python", "package": name, "version": ver,
                     "license": lic, "status": status, "note": note})
    return rows


def check_npm(policy: dict) -> list[dict]:
    with open(NPM_LOCK, encoding="utf-8") as fh:
        pkgs = json.load(fh).get("packages", {})
    rows = []
    for path, info in sorted(pkgs.items()):
        if not path:
            continue
        name = path.split("node_modules/")[-1]
        lic = info.get("license") or "UNKNOWN"
        if isinstance(lic, dict):
            lic = lic.get("type", "UNKNOWN")
        status, note = judge(name, str(lic), policy)
        dev = bool(info.get("dev"))
        if status == "FAIL" and dev:
            status, note = "dev-only", "not shipped; " + note
        rows.append({"ecosystem": "npm", "package": name, "version": info.get("version", ""),
                     "license": str(lic), "status": status, "note": note, "dev": dev})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", help="write the full result table here")
    ap.add_argument("--frontend", action="store_true")
    args = ap.parse_args()
    policy = load_policy()
    rows = check_python(policy) + (check_npm(policy) if args.frontend else [])
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    for r in rows:
        if r["status"] != "ok":
            print(f"  [{r['status'].upper():8}] {r['ecosystem']:6} {r['package']} {r['version']}  "
                  f"({r['license']})  {r['note']}")
    print(f"{len(rows)} packages checked: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    if counts.get("pending"):
        print("OPEN OWNER DECISION: a pending licence exception exists (see security/license-policy.json)")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"policy": os.path.relpath(POLICY, ROOT), "counts": counts, "rows": rows},
                      fh, indent=2)
    return 1 if counts.get("FAIL") else 0


if __name__ == "__main__":
    sys.exit(main())
