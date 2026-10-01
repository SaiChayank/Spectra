"""Structured logging: JSON lines, request correlation, secret redaction.

Every ``spectra.*`` log record is emitted as one JSON object per line::

    {"ts": "2026-10-02T09:15:04Z", "level": "INFO", "logger": "spectra.api",
     "msg": "http request", "request_id": "9f2c...", "event": "http_request",
     "method": "GET", "path": "/api/status", "status": 200,
     "duration_ms": 3.1}

* **request_id** - the current HTTP request's id (set by
  ``spectra.api.middleware.RequestIdMiddleware`` through :data:`REQUEST_ID`;
  ``-`` outside a request). Operators can join a response header
  (``X-Request-ID``) to the server-side records for the same request.
* **redaction** - defense in depth for the standing "never log secrets"
  rule: messages and structured extras are scrubbed for credential-shaped
  keys (``password``, ``token``, ``secret``, ``private_key``, ``session``
  ...) and ``key=value`` / ``key: value`` patterns before they reach a
  handler. The application code never passes these values in the first
  place; the scrubber exists so a future ``log.info("%s", user_input)``
  cannot silently leak one.

Stdlib-only on purpose: ``spectra.config.setup_logging`` imports this on
every CLI command, including ones that never touch FastAPI.
"""

from __future__ import annotations

import json
import logging
import re
from contextvars import ContextVar

#: Correlation id for the request currently being served (None otherwise).
REQUEST_ID: ContextVar[str | None] = ContextVar("spectra_request_id",
                                                default=None)


def current_request_id() -> str | None:
    """The request id bound to this context, if any."""
    return REQUEST_ID.get()


class RequestIdFilter(logging.Filter):
    """Stamps every record with the current request id (handler-side, so it
    is resolved when the line is actually emitted, not when the record was
    created)."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = current_request_id() or "-"
        return True


#: Key names whose values must never reach a log line.
_SENSITIVE_KEY = re.compile(
    r"(?i)(password|passwd|secret|token|credential|private[_-]?key"
    r"|api[_-]?key|session[_-]?id|authorization)")

#: ``password=hunter2`` / ``token: abc`` inside a message or string value.
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|token|credential|private[_-]?key"
    r"|api[_-]?key|session[_-]?id|authorization)\b(\s*[=:]\s*)\S+")

#: Standard LogRecord attributes - everything else in ``record.__dict__``
#: was attached via ``extra=`` and becomes a structured JSON field.
_STANDARD_ATTRS = frozenset({
    "args", "asctime", "created", "exc_info", "exc_text", "filename",
    "funcName", "levelname", "levelno", "lineno", "module", "msecs",
    "message", "msg", "name", "pathname", "process", "processName",
    "relativeCreated", "stack_info", "thread", "threadName", "taskName",
    "request_id",
})


def redact(text: str) -> str:
    """Mask credential-shaped ``key=value`` assignments in ``text``."""
    return _SENSITIVE_ASSIGNMENT.sub(r"\1\2***", text)


def _scrub(key: str, value: object) -> object:
    """Redact one structured extra: sensitive keys are masked outright,
    string values are pattern-scrubbed, containers are walked one level."""
    if _SENSITIVE_KEY.search(key):
        return "***"
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: _scrub(str(k), v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub(key, v) for v in value]
    return value


class StructuredFormatter(logging.Formatter):
    """One JSON object per record with request id, extras and traceback."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S") + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": redact(record.getMessage()),
        }
        request_id = getattr(record, "request_id", None) \
            or current_request_id()
        if request_id:
            payload["request_id"] = request_id
        for key, value in record.__dict__.items():
            if key in _STANDARD_ATTRS or key.startswith("_"):
                continue
            payload[key] = _scrub(key, value)
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(level: str | int | None = None) -> None:
    """Install the structured formatter + request-id filter on the root
    handlers (called once per process from ``spectra.config.setup_logging``).

    Idempotent: a second call only swaps formatters, so tests and reloads
    cannot stack handlers or filters.
    """
    if isinstance(level, str):
        resolved = getattr(logging, level.upper(), logging.INFO)
    elif isinstance(level, int):
        resolved = level
    else:
        resolved = logging.INFO
    root = logging.getLogger()
    root.setLevel(resolved)
    if not root.handlers:
        logging.basicConfig(level=resolved, format="%(message)s")
    formatter = StructuredFormatter()
    for handler in root.handlers:
        handler.setFormatter(formatter)
        if not any(isinstance(f, RequestIdFilter) for f in handler.filters):
            handler.addFilter(RequestIdFilter())
