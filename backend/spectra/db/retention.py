"""Bounded retention: age policies for prunable tables + stale sessions.

Policies are **off by default** (``0`` = keep): nothing here destroys existing
history unless the operator opts in with ``SPECTRA_*`` configuration. Growth is
still bounded without them - the flow row cap lives in
:class:`~spectra.db.repositories.FlowRepository` and the event row cap in
:class:`~spectra.db.repositories.EventRepository`.

Audit data follows *separate integrity rules*: ``audit_log`` is deliberately
absent from every policy below. Its hash chain and Merkle checkpoints require
the full ``seq`` sequence, so pruning entries would make ``audit verify`` fail
by construction; audit growth is bounded by archive/checkpoint practice, not by
deletion. :func:`apply_retention` therefore never touches it (tested).

Stale sessions: a row with ``stopped_at IS NULL`` whose ``started_at`` is older
than ``stale_session_hours`` is a capture a crashed process never finalised; it
is closed with an explanatory ``error`` (and ``status = 'FAILED'``) so history
stops showing it as running. Rows still ``UPLOADED`` are exempt: an import
waiting to be processed is a resource, not an open session, and only the
delete API (or ``capture_retention_days`` for finished rows) removes it. The
sweep runs when a Store opens (before any capture of this process exists) and
after each capture finishes.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .connection import Database

DAY = 86_400.0
_STALE_ERROR = "stale session: process exited before the capture was finalised"


@dataclass
class RetentionPolicy:
    """Age-based retention; ``0`` disables the corresponding policy."""

    flow_retention_days: float = 0.0      # non-flagged flow rows
    detection_retention_days: float = 0.0  # flagged rows (evidence - usually longer)
    capture_retention_days: float = 0.0    # finished capture sessions
    event_retention_days: float = 0.0      # system event feed
    stale_session_hours: float = 24.0      # open sessions older than this = crashed

    @classmethod
    def from_config(cls, config) -> "RetentionPolicy":
        """Build from a :class:`spectra.config.Config` (duck-typed for tests)."""
        return cls(
            flow_retention_days=float(getattr(config, "flow_retention_days", 0.0)),
            detection_retention_days=float(
                getattr(config, "detection_retention_days", 0.0)),
            capture_retention_days=float(
                getattr(config, "capture_retention_days", 0.0)),
            event_retention_days=float(getattr(config, "event_retention_days", 0.0)),
            stale_session_hours=float(getattr(config, "stale_session_hours", 24.0)),
        )

    def enabled(self) -> bool:
        return any((self.flow_retention_days > 0,
                    self.detection_retention_days > 0,
                    self.capture_retention_days > 0,
                    self.event_retention_days > 0,
                    self.stale_session_hours > 0))


def apply_retention(db: Database, policy: RetentionPolicy,
                    now: float | None = None) -> dict:
    """Run every enabled policy in one transaction; returns per-policy counts.

    Order matters: stale sessions are closed first (so their rows become
    eligible for capture retention later), then sessions, then flow rows
    (flagged and non-flagged age independently), then events.
    """
    now = time.time() if now is None else now
    counts = {"stale_sessions": 0, "captures": 0, "detections": 0,
              "flows": 0, "events": 0}
    if not policy.enabled():
        return counts

    stale_cutoff = (now - policy.stale_session_hours * 3600.0
                    if policy.stale_session_hours > 0 else None)
    capture_cutoff = (now - policy.capture_retention_days * DAY
                      if policy.capture_retention_days > 0 else None)
    flow_cutoff = (now - policy.flow_retention_days * DAY
                   if policy.flow_retention_days > 0 else None)
    detection_cutoff = (now - policy.detection_retention_days * DAY
                        if policy.detection_retention_days > 0 else None)
    event_cutoff = (now - policy.event_retention_days * DAY
                    if policy.event_retention_days > 0 else None)

    with db.transaction():
        if stale_cutoff is not None:
            counts["stale_sessions"] = db.execute(
                """UPDATE captures
                   SET stopped_at = ?, error = COALESCE(error, ?),
                       status = 'FAILED'
                   WHERE stopped_at IS NULL AND started_at < ?
                     AND status <> 'UPLOADED'""",
                (now, _STALE_ERROR, stale_cutoff),
            ).rowcount
        if capture_cutoff is not None:
            # Only finished sessions: an open one is live (or just swept);
            # unprocessed uploads are managed by the delete API.
            counts["captures"] = db.execute(
                """DELETE FROM captures
                   WHERE started_at < ? AND stopped_at IS NOT NULL""",
                (capture_cutoff,),
            ).rowcount
        if detection_cutoff is not None:
            counts["detections"] = db.execute(
                "DELETE FROM flows WHERE anomaly = 1 AND ts < ?",
                (detection_cutoff,),
            ).rowcount
        if flow_cutoff is not None:
            counts["flows"] = db.execute(
                "DELETE FROM flows WHERE anomaly = 0 AND ts < ?",
                (flow_cutoff,),
            ).rowcount
        if event_cutoff is not None:
            counts["events"] = db.execute(
                "DELETE FROM events WHERE ts < ?", (event_cutoff,),
            ).rowcount
    return counts
