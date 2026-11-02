"""Spectra persistence layer (data access only).

Layering: ``Store`` (facade in :mod:`spectra.store`) -> these repositories ->
:class:`Database`. Services and modules never build SQL themselves; migrations
are the only place schema changes happen.

Public surface:

* :class:`Database` / :class:`StoreError` - connection + transactions
* :func:`migrate` / :class:`Migration` - versioned schema migrations
* repositories: :class:`FlowRepository`, :class:`CaptureRepository`,
  :class:`ModelRunRepository`, :class:`ModelRegistryRepository`,
  :class:`AuditRepository`, :class:`EventRepository`,
  :class:`UserRepository`, :class:`SessionRepository`,
  :class:`IncidentRepository`, :class:`AlertRepository`
* :class:`WriteBuffer` - batched flow/event commits
* :class:`RetentionPolicy` / :func:`apply_retention` - bounded retention
"""

from __future__ import annotations

from .batch import WriteBuffer
from .connection import Database, StoreError
from .migrations import (
    MIGRATIONS,
    Migration,
    applied_migrations,
    migrate,
    schema_version,
)
from .repositories import (
    ALERT_JSON_FIELDS,
    AlertRepository,
    AuditRepository,
    CaptureRepository,
    EventRepository,
    FlowRepository,
    IncidentRepository,
    ModelRegistryRepository,
    ModelRunRepository,
    SessionRepository,
    UserRepository,
    row_to_flow,
)
from .retention import RetentionPolicy, apply_retention

__all__ = [
    "ALERT_JSON_FIELDS",
    "AlertRepository",
    "AuditRepository",
    "CaptureRepository",
    "Database",
    "EventRepository",
    "FlowRepository",
    "IncidentRepository",
    "MIGRATIONS",
    "Migration",
    "ModelRegistryRepository",
    "ModelRunRepository",
    "RetentionPolicy",
    "SessionRepository",
    "StoreError",
    "UserRepository",
    "WriteBuffer",
    "applied_migrations",
    "apply_retention",
    "migrate",
    "row_to_flow",
    "schema_version",
]
