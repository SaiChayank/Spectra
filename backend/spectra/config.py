"""Central configuration for Spectra.

All values can be overridden with environment variables (SPECTRA_* prefix),
so the API, CLI, and tests share one source of truth.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field, fields
from pathlib import Path

# backend/ directory (the package lives at backend/spectra)
BACKEND_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = BACKEND_DIR / "data"


def _env(name: str, default: str) -> str:
    return os.environ.get(f"SPECTRA_{name}", default)


@dataclass
class Config:
    # paths
    data_dir: str = field(default_factory=lambda: _env("DATA_DIR", str(DEFAULT_DATA_DIR)))
    db_path: str = ""              # resolved in __post_init__
    model_path: str = ""           # resolved in __post_init__

    # capture / flow tracking
    idle_timeout: float = 30.0     # seconds before an idle flow is finalized
    bucket_seconds: int = 5        # timeline resolution
    flow_buffer: int = 5000        # in-memory flow ring buffer
    detection_buffer: int = 2000   # in-memory detection ring buffer
    timeline_buckets: int = 120

    # persistence
    persist: bool = True
    max_history_rows: int = 200_000   # oldest rows are pruned beyond this

    # detection model
    contamination: float = 0.02    # expected anomaly fraction when training

    # service
    api_host: str = "127.0.0.1"
    api_port: int = 8787
    cors_origins: list[str] = field(default_factory=lambda: [
        o.strip()
        for o in _env("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
        if o.strip()
    ])
    log_level: str = field(default_factory=lambda: _env("LOG_LEVEL", "INFO"))

    def __post_init__(self) -> None:
        if not self.db_path:
            self.db_path = _env("DB_PATH", os.path.join(self.data_dir, "spectra.db"))
        if not self.model_path:
            self.model_path = _env(
                "MODEL_PATH", str(BACKEND_DIR / "models" / "spectra_model.joblib")
            )
        self.data_dir = os.environ.get("SPECTRA_DATA_DIR", self.data_dir)

    @classmethod
    def from_env(cls) -> "Config":
        """Build a config, coercing numeric env overrides."""
        cfg = cls()
        for f in fields(cls):
            raw = os.environ.get(f"SPECTRA_{f.name.upper()}")
            if raw is None:
                continue
            if f.type in ("float", float):
                setattr(cfg, f.name, float(raw))
            elif f.type in ("int", int):
                setattr(cfg, f.name, int(raw))
            elif f.type in ("bool", bool):
                setattr(cfg, f.name, raw.lower() in ("1", "true", "yes", "on"))
            else:
                setattr(cfg, f.name, raw)
        return cfg

    def ensure_dirs(self) -> None:
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.model_path)), exist_ok=True)


def setup_logging(level: str | None = None) -> None:
    """Configure process-wide logging once."""
    resolved = (level or Config().log_level).upper()
    logging.basicConfig(
        level=getattr(logging, resolved, logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )


_config: Config | None = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = Config.from_env()
        _config.ensure_dirs()
    return _config


def set_config(cfg: Config) -> Config:
    """Override the process-wide config (tests, CLI flags)."""
    global _config
    cfg.ensure_dirs()
    _config = cfg
    return cfg
