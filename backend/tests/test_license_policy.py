"""The licence checker's decisions (security/license-policy.json)."""

from __future__ import annotations

import importlib.util
import json
import os
import re

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "scripts", "check_licenses.py")
spec = importlib.util.spec_from_file_location("check_licenses", SCRIPT)
cl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cl)

POLICY = cl.load_policy()
ALLOWED = set(POLICY["allowed"])


@pytest.mark.parametrize("expr,ok", [
    ("MIT", True), ("MIT License", True), ("BSD-3-Clause", True),
    ("Apache-2.0 OR BSD-3-Clause", True),          # any alternative is enough
    ("BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0", True),
    ("MIT AND GPL-2.0-only", False),               # every AND part must be allowed
    ("GPL-2.0-only", False), ("GPL-3.0-only OR GPL-2.0-only", False),
    ("AGPL-3.0-only", False), ("UNKNOWN", False), ("", False),
])
def test_expression_evaluation(expr, ok):
    assert cl.allowed_expression(expr, ALLOWED) is ok


def test_copyleft_without_an_exception_fails():
    status, _ = cl.judge("somelib", "GPL-3.0-only", POLICY)
    assert status == "FAIL"


def test_scapy_is_an_optional_extra_only_and_tooling_does_not_approve_it():
    status, note = cl.judge("scapy", "GPL-2.0-only", POLICY)
    assert status == "optional-extra" and "live" in note          # visible, not silently allowed
    ex = next(e for e in POLICY["exceptions"] if e["package"] == "scapy")
    assert ex["status"] == "optional-extra" and ex["owner"] == ""   # tooling never approves


def test_no_copyleft_exception_package_is_a_core_dependency():
    import tomllib

    with open(os.path.join(os.path.dirname(HERE), "pyproject.toml"), "rb") as fh:
        proj = tomllib.load(fh)["project"]
    core = {re.split(r"[<>=!\[; ]", d, maxsplit=1)[0].lower() for d in proj["dependencies"]}
    excepted = {e["package"].lower() for e in POLICY["exceptions"]}
    assert not core & excepted, core & excepted
    assert any(d.startswith("scapy") for d in proj["optional-dependencies"]["live"])


def test_only_an_owner_approved_exception_turns_green():
    policy = json.loads(json.dumps(POLICY))
    next(e for e in policy["exceptions"] if e["package"] == "scapy").update(
        status="approved", owner="the owner", expires="2027-01-01")
    status, note = cl.judge("scapy", "GPL-2.0-only", policy)
    assert status == "approved" and "the owner" in note


def test_a_pending_exception_is_still_an_open_decision():
    policy = json.loads(json.dumps(POLICY))
    next(e for e in policy["exceptions"] if e["package"] == "scapy").update(status="pending")
    assert cl.judge("scapy", "GPL-2.0-only", policy)[0] == "pending"


def test_platform_marker_dependencies_are_skipped_when_they_do_not_apply():
    assert cl.marker_applies("sys_platform == 'win32'") is (os.name == "nt")
    assert cl.marker_applies("python_version >= '3.0'") is True
