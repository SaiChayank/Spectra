#!/usr/bin/env python
"""Regenerate (or --check) THIRD_PARTY_NOTICES.md at the repo root.

    python scripts/gen_third_party_notices.py            # write the file
    python scripts/gen_third_party_notices.py --check    # exit 1 if the committed file is stale

Inputs, all local (no network):
  * Python: the *running interpreter's* environment. The core closure is walked from the
    core ``dependencies`` in backend/pyproject.toml through installed ``Requires-Dist``
    metadata (not the ``dev`` extra); the ``live`` extra is walked separately. Markers are
    evaluated for a FIXED target (CPython 3.13 on Linux, like the container image) so the
    output does not depend on the interpreter that runs this. Install the wheel with the
    lock constraints into a throwaway venv first (see docs/release-policy.md, and CI).
    Licence/NOTICE texts are the files in each ``*.dist-info``.
  * npm: frontend/package-lock.json (production closure from package.json ``dependencies``)
    with texts read from ``--node-modules`` (default frontend/node_modules).
Licence text is copied verbatim (line endings normalised to LF) and never typed or fetched.
"""
from __future__ import annotations

import argparse
import importlib.metadata as md
import importlib.util
import json
import os
import re
import sys
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "THIRD_PARTY_NOTICES.md")
PYPROJECT = os.path.join(ROOT, "backend", "pyproject.toml")
LOCK = os.path.join(ROOT, "backend", "requirements.lock")
NPM_LOCK = os.path.join(ROOT, "frontend", "package-lock.json")
NPM_PKG = os.path.join(ROOT, "frontend", "package.json")
DOCKERFILE = os.path.join(ROOT, "Dockerfile")

_spec = importlib.util.spec_from_file_location(
    "check_licenses", os.path.join(ROOT, "backend", "scripts", "check_licenses.py"))
cl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cl)

#: marker environment the closure is resolved for (the container image: Python 3.13, Linux)
TARGET_ENV = {
    "python_version": "3.13", "python_full_version": "3.13.0", "implementation_name": "cpython",
    "platform_python_implementation": "CPython", "sys_platform": "linux",
    "platform_system": "Linux", "os_name": "posix", "platform_machine": "x86_64",
}
LICENSE_FILE = re.compile(r"(licen[sc]e|copying|notice|copyright)", re.IGNORECASE)


def die(msg: str):
    """Input problem (environment does not match the lockfiles): exit 2, distinct from "stale" (1)."""
    print("gen_third_party_notices: " + msg, file=sys.stderr)
    sys.exit(2)


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def read_text(path: str) -> str:
    with open(path, "rb") as fh:
        t = fh.read().decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
    return t if t.endswith("\n") else t + "\n"


# ---------------------------------------------------------------- python
def py_walk(roots: list[str], skip: set[str]) -> dict[str, md.Distribution]:
    from packaging.requirements import Requirement
    seen: dict[str, set[str]] = {}
    out: dict[str, md.Distribution] = {}
    todo = [(Requirement(r), "") for r in roots]
    while todo:
        req, _ = todo.pop()
        key = norm(req.name)
        if key in skip:
            continue
        extras = set(req.extras)
        if key in seen and extras <= seen[key]:
            continue
        seen.setdefault(key, set()).update(extras)
        try:
            dist = md.distribution(req.name)
        except md.PackageNotFoundError:
            die(f"{req.name} is not installed in this environment; install the "
                             "wheel (with the live extra) with the lock constraints first")
        out[key] = dist
        for line in dist.requires or []:
            sub = Requirement(line)
            if sub.marker is None or any(
                    sub.marker.evaluate({**TARGET_ENV, "extra": e}) for e in ({""} | seen[key])):
                todo.append((sub, ""))
    return out


def py_url(meta) -> str:
    urls = {u.split(",", 1)[0].strip().lower(): u.split(",", 1)[1].strip()
            for u in meta.get_all("Project-URL") or [] if "," in u}
    for k in ("homepage", "source", "source code", "repository", "home"):
        if k in urls:
            return urls[k]
    return meta.get("Home-page") or next(iter(urls.values()), "") or \
        f"https://pypi.org/project/{meta['Name']}/"


#: metadata gives only the bare classifier "BSD"; the shipped text has the three BSD clauses (checked by reading it)
LICENCE_OVERRIDE = {"cloudpickle": "BSD-3-Clause", "scipy": "BSD-3-Clause"}


def py_licence(dist: md.Distribution) -> str:
    return LICENCE_OVERRIDE.get(norm(dist.metadata["Name"])) or cl.python_license(dist.metadata["Name"])


def py_texts(dist: md.Distribution) -> list[tuple[str, str]]:
    files = []
    for f in dist.files or []:
        parts = f.parts
        if not parts[0].endswith(".dist-info") or f.suffix in (".py", ".pyc"):
            continue
        rel = "/".join(parts[1:])
        if rel in ("METADATA", "RECORD", "WHEEL", "INSTALLER", "REQUESTED", "entry_points.txt",
                   "top_level.txt", "direct_url.json") or not LICENSE_FILE.search(parts[-1]):
            continue
        files.append((rel.removeprefix("licenses/"), read_text(str(dist.locate_file(f)))))
    return sorted(files)


def py_section(roots, skip, lock_pins) -> tuple[list[dict], dict[str, md.Distribution]]:
    dists = py_walk(roots, skip)
    rows = []
    for key in sorted(dists):
        d = dists[key]
        if key in lock_pins and lock_pins[key] != d.version:
            die(f"{key}: installed {d.version} != requirements.lock {lock_pins[key]}")
        rows.append({"name": d.metadata["Name"], "version": d.version, "license": py_licence(d),
                     "url": py_url(d.metadata), "texts": py_texts(d)})
    return rows, dists


def lock_pins() -> dict[str, str]:
    pins = {}
    with open(LOCK, encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r"^([A-Za-z0-9_.\-]+)==([^;\s\\]+)", line)
            if m:
                pins[norm(m.group(1))] = m.group(2)
    return pins


# ---------------------------------------------------------------- npm
def npm_rows(modules: str) -> list[dict]:
    with open(NPM_LOCK, encoding="utf-8") as fh:
        pk = json.load(fh)["packages"]
    todo = [("", n) for n in pk[""].get("dependencies", {})]
    chosen: set[str] = set()
    while todo:
        base, name = todo.pop()
        p = base
        while True:                                   # node resolution: nearest node_modules
            cand = (p + "/" if p else "") + "node_modules/" + name
            if cand in pk:
                break
            if not p:
                cand = None
                break
            p = p.rsplit("/node_modules/", 1)[0] if "/node_modules/" in p else ""
        if cand is None or cand in chosen:
            continue                                  # unresolved optional/peer: not installed
        chosen.add(cand)
        info = pk[cand]
        for k in ("dependencies", "optionalDependencies", "peerDependencies"):
            todo += [(cand, n) for n in info.get(k, {})]
    rows = []
    for path in sorted(chosen, key=lambda p: (p.rsplit("node_modules/", 1)[1], p)):
        info = pk[path]
        name = path.rsplit("node_modules/", 1)[1]
        d = os.path.join(modules, path.removeprefix("node_modules/"))
        meta, texts = {}, []
        if os.path.isfile(os.path.join(d, "package.json")):
            with open(os.path.join(d, "package.json"), encoding="utf-8") as fh:
                meta = json.load(fh)
            if meta.get("version") != info.get("version"):
                die(f"{name}: node_modules has {meta.get('version')}, lock has {info.get('version')}")
            texts = sorted((f, read_text(os.path.join(d, f))) for f in os.listdir(d)
                           if LICENSE_FILE.search(f) and os.path.isfile(os.path.join(d, f)))
            if not texts:                              # e.g. victory-vendor: vendored d3 licences in subfolders
                for dp, dn, fn in os.walk(d):
                    dn[:] = sorted(x for x in dn if x != "node_modules")
                    rel = os.path.relpath(dp, d)
                    if rel.count(os.sep) < 3:
                        texts += [(os.path.normpath(os.path.join(rel, f)), read_text(os.path.join(dp, f)))
                                  for f in sorted(fn) if LICENSE_FILE.match(f)]
                texts.sort()
        else:
            die(f"{name} is not in {modules}; run `npm ci` in frontend/ first")
        repo = meta.get("repository")
        repo = repo.get("url", "") if isinstance(repo, dict) else (repo or "")
        repo = re.sub(r"^git\+", "", repo)
        repo = re.sub(r"^git://", "https://", repo)
        repo = re.sub(r"\.git$", "", repo)
        if re.match(r"^[\w.-]+/[\w.-]+$", repo):
            repo = "https://github.com/" + repo
        lic = info.get("license") or "UNKNOWN"
        rows.append({"name": name, "version": info["version"], "license": str(lic),
                     "url": meta.get("homepage") or repo or f"https://www.npmjs.com/package/{name}",
                     "texts": texts})
    return rows


# ---------------------------------------------------------------- render
def fence(text: str) -> str:
    n = max([3] + [len(m) + 1 for m in re.findall(r"`+", text)])
    return "`" * n


def entry(r: dict) -> list[str]:
    out = [f"### {r['name']} {r['version']}", "",
           f"- SPDX licence: `{r['license']}`", f"- Upstream: {r['url']}", ""]
    if not r["texts"]:
        out += ["**This package ships no licence file; none is reproduced here.**", ""]
    for fname, text in r["texts"]:
        f = fence(text)
        out += [f"Licence/notice file `{fname}`:", "", f + "text", text.rstrip("\n"), f, ""]
    return out


def table(rows: list[dict]) -> list[str]:
    out = ["| Package | Version | SPDX licence |", "|---|---|---|"]
    out += [f"| {r['name']} | {r['version']} | {r['license']} |" for r in rows]
    return out + [""]


def render(modules: str) -> str:
    with open(PYPROJECT, "rb") as fh:
        cfg = tomllib.load(fh)["project"]
    pins = lock_pins()
    core, core_d = py_section(cfg["dependencies"], {"spectra"}, pins)
    live, _ = py_section(cfg["optional-dependencies"]["live"], set(core_d) | {"spectra"}, pins)
    npm = npm_rows(modules)
    with open(DOCKERFILE, encoding="utf-8") as fh:
        base = re.search(r"^FROM (\S+)", fh.read(), re.MULTILINE).group(1)
    attn = [f"{r['name']} {r['version']} ({s}): no licence file shipped"
            for s, rows in (("Python core", core), ("npm bundled", npm), ("live extra", live))
            for r in rows if not r["texts"]]
    attn += [f"{r['name']} {r['version']} ({s}): licence is `{r['license']}`, not a usable SPDX identifier"
             for s, rows in (("Python core", core), ("npm bundled", npm), ("live extra", live))
             for r in rows if r["license"] in ("UNKNOWN", "", "BSD")]
    L = ["# Third-party notices", "",
         "Spectra is Apache-2.0 (see `LICENSE`). It includes or depends on the third-party software below.",
         "This file is generated by `scripts/gen_third_party_notices.py` from the installed distribution",
         "metadata and the `node_modules` package directories; licence and NOTICE texts are copied verbatim",
         "(line endings normalised to LF). Do not edit it by hand: run `python scripts/gen_third_party_notices.py`.",
         "Versions are the ones pinned in `backend/requirements.lock` and `frontend/package-lock.json`.", "",
         "Scope:", "",
         ("1. **Python core**: the runtime closure of a plain `pip install spectra` (not the `dev` extra), "
          "resolved for CPython 3.13 on Linux."),
         ("2. **Frontend bundle**: the npm production dependencies of the dashboard and their transitive "
          "dependencies (a superset of what Vite tree-shakes into the bundle; build tools and test runners are excluded)."),
         "3. **Optional `live` extra**: not installed by default (section below).",
         "4. **Container image**: see the last section.", "", "## Needs attention", ""]
    L += [f"- {a}" for a in attn] or ["None: every listed package ships a licence file."]
    L += ["", f"## 1. Python core dependencies ({len(core)})", ""] + table(core)
    for r in core:
        L += entry(r)
    L += [f"## 2. Frontend bundle, npm production dependencies ({len(npm)})", ""] + table(npm)
    for r in npm:
        L += entry(r)
    L += [f"## 3. Optional `live` extra ({len(live)}): NOT installed by default", "",
          "`pip install spectra[live]` adds the packages below for live NIC capture. They are optional and are",
          "not part of the default wheel install, the default container image or the offline pcap path.",
          "**scapy is GPL-2.0-only**: whoever installs the extra takes it under its own licence (see",
          "`docs/release-policy.md`). Spectra's Apache-2.0 distribution does not bundle it.", ""] + table(live)
    for r in live:
        L += entry(r)
    L += ["## 4. Container image", "",
          f"The image is built `FROM {base}` (pinned by digest in the `Dockerfile`) and installs the Spectra wheel",
          "with the Python core dependencies above (the `capture` variant also installs the `live` extra).",
          "The base image's Debian packages carry their own licences, in `/usr/share/doc/<package>/copyright`",
          "inside the image; they are not listed here.", ""]
    return "\n".join(L).rstrip("\n") + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="exit 1 if THIRD_PARTY_NOTICES.md is stale")
    ap.add_argument("--node-modules", default=os.path.join(ROOT, "frontend", "node_modules"))
    args = ap.parse_args()
    text = render(args.node_modules)
    if args.check:
        cur = ""
        if os.path.exists(OUT):
            with open(OUT, encoding="utf-8") as fh:
                cur = fh.read()
        if cur != text:
            print("THIRD_PARTY_NOTICES.md is stale: run python scripts/gen_third_party_notices.py", file=sys.stderr)
            return 1
        print("THIRD_PARTY_NOTICES.md is current")
        return 0
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print(f"wrote {OUT} ({len(text)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
