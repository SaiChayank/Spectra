"""Deployment profiles: ``local`` (default, unchanged) and ``hardened`` (Phase 10 §7).

The numbers in HARDENED_RETENTION_DAYS were approved as proposed by the project
owner on 2026-11-07 (docs/retention.md) - these tests pin the mechanism, so a
later change to the numbers is a deliberate edit of that constant and its docs.
"""

from __future__ import annotations

import pytest

from spectra.config import HARDENED_RETENTION_DAYS, PROFILES, Config
from spectra.db import RetentionPolicy

FIELDS = tuple(HARDENED_RETENTION_DAYS)


def test_local_profile_is_the_default_and_changes_nothing(monkeypatch):
    monkeypatch.delenv("SPECTRA_PROFILE", raising=False)
    cfg = Config.from_env()
    assert cfg.profile == "local"
    assert all(getattr(cfg, f) == 0.0 for f in FIELDS)          # retention off, as before
    assert not RetentionPolicy.from_config(cfg).enabled() or RetentionPolicy.from_config(cfg).stale_session_hours > 0


def test_hardened_profile_turns_retention_on_with_the_proposed_defaults(monkeypatch):
    monkeypatch.setenv("SPECTRA_PROFILE", "hardened")
    cfg = Config.from_env()
    assert cfg.profile == "hardened"
    for field, days in HARDENED_RETENTION_DAYS.items():
        assert getattr(cfg, field) == days > 0
    # flagged rows are evidence: kept longer than ordinary flows; uploads (which may hold payload) shortest
    assert cfg.detection_retention_days > cfg.flow_retention_days > cfg.capture_retention_days
    pol = RetentionPolicy.from_config(cfg)
    assert pol.enabled() and pol.capture_retention_days == cfg.capture_retention_days


def test_explicit_settings_win_over_the_profile(monkeypatch):
    monkeypatch.setenv("SPECTRA_PROFILE", "hardened")
    monkeypatch.setenv("SPECTRA_FLOW_RETENTION_DAYS", "7")
    monkeypatch.setenv("SPECTRA_EVENT_RETENTION_DAYS", "0")      # an operator who really wants it off
    cfg = Config.from_env()
    assert cfg.flow_retention_days == 7.0
    assert cfg.event_retention_days == 0.0
    assert cfg.detection_retention_days == HARDENED_RETENTION_DAYS["detection_retention_days"]
    assert Config(profile="hardened", flow_retention_days=3.0).flow_retention_days == 3.0


def test_unknown_profile_fails_loudly(monkeypatch):
    monkeypatch.setenv("SPECTRA_PROFILE", "paranoid")
    with pytest.raises(ValueError, match="paranoid"):
        Config.from_env()
    assert set(PROFILES) == {"local", "hardened"}


def test_audit_log_is_never_part_of_a_profile():
    assert not any("audit" in f for f in HARDENED_RETENTION_DAYS)
