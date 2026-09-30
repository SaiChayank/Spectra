"""Spectra persistence layer (data access only).

Layering: ``Store`` (facade in :mod:`spectra.store`) -> these repositories ->
:class:`Database`. Services and modules never build SQL themselves; migrations
are the only place schema changes happen.

Public surface:

* :class:`Database` / :class:`StoreError` - connection + transactions
* :func:`migrate` / :class:`Migration` - versioned schema migrations
* repositories: :class:`FlowRepository`, :class:`CaptureRepository`,
  :class:`ModelRunRepository`, :class:`AuditRepository`, :class:`EventRepository`,
  :class:`UserRepository`, :class:`SessionRepository`, :class:`IncidentRepository`
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
    AuditRepository,
    CaptureRepository,
    EventRepository,
    FlowRepository,
    IncidentRepository,
    ModelRunRepository,
    SessionRepository,
    UserRepository,
    row_to_flow,
)
from .retention import RetentionPolicy, apply_retention

__all__ = [
    "AuditRepository",
    "CaptureRepository",
    "Database",
    "EventRepository",
    "FlowRepository",
    "IncidentRepository",
    "MIGRATIONS",
    "Migration",
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
