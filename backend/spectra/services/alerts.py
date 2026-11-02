"""Alert service: evasion watch, drift alert bookkeeping, scored window.

This is a deliberate *leaf* of the service graph: it depends only on the
event bus, the audit trail and the failure tracker, so any other service
(hot path, model service) can notify it without creating a dependency cycle.
"""

from __future__ import annotations

import logging
from collections import deque

import numpy as np

from ..config import Config
from ..modules.adv import ScoreWindow
from ..domain import SystemEvent
from .audit import AuditService
from .events import EventBus
from .resilience import FailureTracker

log = logging.getLogger("spectra.engine")


class AlertService:
    """Module 3 alert state: near-threshold score watch + drift episodes.

    Owns the recent-scored-feature window shared with the hot path (the
    composition root hands the same deque to detection/model services so the
    historical ``_recent_feats`` rebinding keeps working in one place).
    """

    def __init__(self, config: Config, events: EventBus, audit: AuditService,
                 failures: FailureTracker, contamination: float,
                 recent_feats: deque) -> None:
        self.config = config
        self.events = events
        self.audit = audit
        self.failures = failures
        self.recent_feats = recent_feats
        self.score_watch = ScoreWindow(contamination=contamination)
        self.drift_level: str | None = None
        self.drift_alerted = False
        self._contamination = contamination

    # -- session lifecycle ----------------------------------------------------

    def reset_session(self, contamination: float | None = None) -> None:
        """Fresh evasion watch per capture; the drift level persists."""
        if contamination is not None:
            self._contamination = contamination
        self.recent_feats.clear()
        self.drift_alerted = False
        self.score_watch = ScoreWindow(contamination=self._contamination)

    def update_contamination(self, contamination: float) -> None:
        """Repoint the evasion watch at an activated model's contamination.

        Score distributions are percentiles, so the history stays valid -
        only the percentile boundary (and the stored value behind reset)
        moves with the model.  Called by the model-activation hook.
        """
        self._contamination = float(contamination)
        self.score_watch.contamination = float(contamination)

    @property
    def evasion_active(self) -> bool:
        return bool(self.score_watch.alerted)

    # -- hot-path hook --------------------------------------------------------

    def on_scored(self, feats: np.ndarray, score: float) -> None:
        """Record a scored flow; alert once per evasion episode.

        The score-window watch is optional telemetry, not core: a failure
        here degrades to "no alert" instead of stopping inference.
        """
        self.recent_feats.append(feats)
        alert = self.failures.guard(
            "adversarial_watch", lambda: self.score_watch.add(score),
            default=None,
        )
        if alert is not None:
            log.warning("possible detector evasion: %s", alert)
            self.events.emit(SystemEvent(type="evasion", data=alert))
            self.audit.append("alert", {"alert_type": "evasion", **alert})

    def evasion_report(self) -> dict:
        """Threshold-hugging analysis of the recent score stream."""
        return self.score_watch.report()

    # -- drift bookkeeping ----------------------------------------------------

    def note_drift(self, report: dict) -> None:
        """Track the drift level and alert once per drift episode.

        Called by the model service after each PSI computation; the level is
        re-read by the immune layer as a danger axis.
        """
        if not report.get("available"):
            return
        self.drift_level = report.get("level")
        drifted = report.get("level") in ("moderate", "significant")
        if drifted and not self.drift_alerted:
            self.drift_alerted = True
            self.events.emit(SystemEvent(type="drift", data=report))
            self.audit.append("alert", {
                "alert_type": "drift",
                "psi": report.get("psi"),
                "level": report.get("level"),
                "n": report.get("n"),
            })
        elif not drifted:
            self.drift_alerted = False

    def set_drift_level(self, level: str | None) -> None:
        """Cache a freshly computed drift level (best-effort refresh)."""
        self.drift_level = level
