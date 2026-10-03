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

    # managed capture storage (spectra/capture/storage.py): imported PCAPs are
    # validated and stored here under generated names - a client filename is
    # metadata only and never becomes a filesystem path.
    capture_store_dir: str = ""    # resolved in __post_init__ (data/captures)
    capture_max_bytes: int = 256 * 1024 * 1024  # per-import size cap

    # streaming runtime: bounded in-process stages.  Overload never blocks
    # packet acquisition - a full queue sheds internal work under an explicit
    # policy and the loss is counted (status["pipeline"] + /api/metrics).
    packet_queue_size: int = 4096    # capture -> flow processing
    flow_queue_size: int = 1024      # completed flows -> inference
    publish_queue_size: int = 1024   # scored flows -> persistence/events
    max_active_flows: int = 5000     # flow-table cap (LRU force-completion)
    flow_max_packets: int = 512      # packet metadata retained per flow
    flow_max_lifetime: float = 900.0 # seconds one flow may remain open
    shutdown_timeout: float = 10.0   # seconds stop() waits for the stages

    # persistence (SQLite, see spectra.db)
    persist: bool = True
    max_history_rows: int = 200_000   # flow row cap (oldest rows pruned)
    db_batch_size: int = 256          # flow/event rows staged per commit
    db_flush_interval: float = 1.0    # seconds before a partial batch commits
    event_max_rows: int = 50_000      # system-event feed stays bounded

    # retention: age policies, off (0) by default so existing history is kept;
    # growth stays bounded by the row caps above even when every age is 0.
    flow_retention_days: float = 0.0      # non-flagged flow rows
    detection_retention_days: float = 0.0 # flagged rows (investigation evidence)
    capture_retention_days: float = 0.0   # finished capture sessions
    event_retention_days: float = 0.0     # system event feed
    stale_session_hours: float = 24.0     # open sessions this old = crashed
    # audit_log is deliberately not configurable here: its hash chain is never
    # pruned automatically (see spectra.db.retention).

    # detection model
    contamination: float = 0.02    # expected anomaly fraction when training

    # analyst alerts (spectra.services.threat_alerts): sightings of the same
    # behaviour (threat type + endpoint pair) within this flow-time window
    # group into one alert (occurrences++); a longer gap starts a new one.
    alert_group_seconds: float = 600.0

    # incident correlation (spectra.incident_correlation): alerts whose
    # sighting intervals are at most this many seconds apart may share an
    # incident; together with shared anchors this is what keeps grouping
    # conservative instead of time-wide.
    incident_window_seconds: float = 1800.0

    # investigation reads (spectra.services.investigation): bounds that keep
    # every bundle/search response finite no matter how large the tables
    # grow - a bundle pages ``investigation_flow_limit`` related flows and
    # aggregates over the newest ``investigation_evidence_rows`` of them,
    # while /api/search returns at most ``search_section_limit`` rows per
    # entity section.
    investigation_flow_limit: int = 100
    investigation_evidence_rows: int = 500
    search_section_limit: int = 10

    # authentication (spectra.services.auth): local accounts only - one admin
    # is bootstrapped when the users table is empty (env password or a
    # mode-restricted file), sessions are absolute-TTL rows keyed by token
    # hash, so both survive restarts and are invalidated by password changes.
    session_ttl_minutes: float = 720.0   # absolute session lifetime (12 h)
    admin_username: str = "admin"        # bootstrap account (first run only)
    session_cookie_secure: bool = False   # set True only behind TLS

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
        if not self.capture_store_dir:
            self.capture_store_dir = _env(
                "CAPTURE_STORE_DIR", os.path.join(self.data_dir, "captures"))

    @classmethod
    def from_env(cls) -> "Config":
        """Build a config, coercing numeric/boolean/list env overrides.

        Annotations are strings (PEP 563), so the type checks compare
        against both the string and the type object; list-valued fields
        (``cors_origins``) are comma-split so ``SPECTRA_CORS_ORIGINS`` can
        never hand CORSMiddleware a bare string (which would make origin
        matching iterate characters instead of origins).
        """
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
            elif f.type in ("list[str]", list[str]):
                setattr(cfg, f.name,
                        [v.strip() for v in raw.split(",") if v.strip()])
            else:
                setattr(cfg, f.name, raw)
        return cfg

    def ensure_dirs(self) -> None:
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.capture_store_dir, exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.model_path)), exist_ok=True)


def setup_logging(level: str | None = None) -> None:
    """Configure process-wide logging once.

    Structured JSON lines with the request id and credential redaction -
    see :mod:`spectra.observability`. Idempotent (formatters are swapped,
    handlers never stacked).
    """
    resolved = (level or Config().log_level).upper()
    from .observability import configure_logging

    configure_logging(getattr(logging, resolved, logging.INFO))


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
