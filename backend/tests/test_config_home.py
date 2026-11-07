"""Where Spectra keeps its data when it is installed rather than run from a checkout."""

from __future__ import annotations

from pathlib import Path

import pytest

from spectra.config import Config, default_home


def test_a_source_checkout_keeps_data_and_models_beside_the_code(tmp_path):
    backend = tmp_path / "backend"
    backend.mkdir()
    (backend / "pyproject.toml").write_text("[project]\nname='spectra'\n")
    assert default_home(backend, {}, "linux") == backend


@pytest.mark.parametrize("platform,environ,expected", [
    ("linux", {}, "/home/u/.local/share/spectra"),
    ("linux", {"XDG_DATA_HOME": "/srv/xdg"}, "/srv/xdg/spectra"),
    ("linux", {"XDG_DATA_HOME": ""}, "/home/u/.local/share/spectra"),        # empty = unset
    ("darwin", {}, "/home/u/Library/Application Support/spectra"),
    ("win32", {"LOCALAPPDATA": "C:/Users/u/AppData/Local"}, "C:/Users/u/AppData/Local/spectra"),
    ("win32", {}, "/home/u/AppData/Local/spectra"),
])
def test_an_installed_copy_uses_the_per_user_data_directory(tmp_path, platform, environ, expected):
    site_packages = tmp_path / "venv" / "lib" / "python3.13" / "site-packages"
    site_packages.mkdir(parents=True)                     # no pyproject.toml here: installed
    got = default_home(site_packages, environ, platform, home=Path("/home/u"))
    assert Path(got) == Path(expected)
    assert "site-packages" not in str(got)


def test_the_installed_defaults_never_point_into_site_packages(tmp_path, monkeypatch):
    import spectra.config as cfgmod
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    monkeypatch.setattr(cfgmod, "BACKEND_DIR", site_packages)
    monkeypatch.setattr(cfgmod, "_HOME", cfgmod.default_home(site_packages, {"XDG_DATA_HOME": str(tmp_path / "xdg")}, "linux"))
    monkeypatch.delenv("SPECTRA_DATA_DIR", raising=False)
    monkeypatch.delenv("SPECTRA_MODEL_PATH", raising=False)
    monkeypatch.delenv("SPECTRA_DB_PATH", raising=False)
    cfg = Config()
    for path in (cfg.data_dir, cfg.model_path, cfg.db_path, cfg.capture_store_dir):
        assert str(site_packages) not in path, path
        assert str(tmp_path / "xdg" / "spectra") in path, path


def test_explicit_environment_paths_still_win(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECTRA_DATA_DIR", str(tmp_path / "d"))
    monkeypatch.setenv("SPECTRA_MODEL_PATH", str(tmp_path / "m" / "x.joblib"))
    cfg = Config()
    assert cfg.data_dir == str(tmp_path / "d") and cfg.model_path == str(tmp_path / "m" / "x.joblib")
