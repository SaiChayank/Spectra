"""Check that README.md states the counts measured from the code.

Measured values:
  tests     pytest --collect-only (number of collected tests)
  api       /api/ operations in the OpenAPI document (method + path pairs)
  cli       top-level subcommands of spectra.cli.build_parser()

Exits 1 with a message if README disagrees with any measured value.
Run with SPECTRA_DATA_DIR set to a temporary directory: importing the app
bootstraps an admin account there.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
README = BACKEND.parent / "README.md"
sys.path.insert(0, str(BACKEND))

HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")

# (label, README pattern with one capture group, measured key)
CHECKS = [
    ("passing tests", r"(\d+)\s+passing tests", "tests"),
    ("HTTP routes", r"(\d+)\s+HTTP routes", "api"),
    ("commands", r"(\d+)\s+(?:CLI\s+)?commands", "cli"),
]


def measure_tests() -> int:
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"],
        cwd=BACKEND, capture_output=True, text=True, check=True,
    ).stdout
    last = out.strip().splitlines()[-1]
    match = re.search(r"(\d+) tests? collected", last)
    if not match:
        raise SystemExit(f"could not read the test count from: {last!r}")
    return int(match.group(1))


def measure_api_operations() -> int:
    from spectra.api.app import app

    count = 0
    for path, item in app.openapi()["paths"].items():
        if path.startswith("/api/"):
            count += sum(1 for method in item if method.upper() in HTTP_METHODS)
    return count


def measure_cli_commands() -> int:
    from spectra.cli import build_parser

    for action in build_parser()._actions:  # argparse has no public accessor
        if isinstance(action, argparse._SubParsersAction):
            return len(action.choices)
    raise SystemExit("no subcommands found in spectra.cli.build_parser()")


def main() -> int:
    measured = {
        "tests": measure_tests(),
        "api": measure_api_operations(),
        "cli": measure_cli_commands(),
    }
    print("measured:", measured)
    text = README.read_text(encoding="utf-8")
    problems = []
    for label, pattern, key in CHECKS:
        found = [int(value) for value in re.findall(pattern, text)]
        if not found:
            problems.append(f"README has no '{label}' count (pattern {pattern!r})")
        for value in found:
            if value != measured[key]:
                problems.append(f"README says {value} {label}, measured {measured[key]}")
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1
    print("README counts match the code")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
