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


#: 9E rolling reference: keep every REF_SAMPLE_EVERY-th scored flow, newest
#: REF_MAX of them (so ~REF_MAX * REF_SAMPLE_EVERY flows of history, bounded
#: memory); report only once REF_MIN_ROWS reference rows exist.
REF_SAMPLE_EVERY = 4
REF_MAX = 4000
REF_MIN_ROWS = 300


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
        self.ref_feats: deque = deque(maxlen=REF_MAX)
        self._scored = 0
        self.score_watch = ScoreWindow(contamination=contamination)
        self.drift_level: str | None = None
        #: last computed drift numbers (None until a drift check ran); read by the
        #: metrics scrape so a scrape never recomputes drift or raises an alert
        self.last_drift: dict | None = None
        self.drift_alerted = False
        self._contamination = contamination

    # -- session lifecycle ----------------------------------------------------

    def reset_session(self, contamination: float | None = None) -> None:
        """Fresh evasion watch per capture; the drift level persists."""
        if contamination is not None:
            self._contamination = contamination
        self.recent_feats.clear()
        self.ref_feats.clear()
        self._scored = 0
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
        self._scored += 1
        if self._scored % REF_SAMPLE_EVERY == 0:
            self.ref_feats.append(feats)
        alert = self.failures.guard(
            "adversarial_watch", lambda: self.score_watch.add(score),
            default=None,
        )
        if alert is not None:
            log.warning("possible detector evasion: %s", alert)
            self.events.emit(SystemEvent(type="evasion", data=alert))
            self.audit.append("alert", {"alert_type": "evasion", **alert})

    def reference_matrix(self) -> np.ndarray | None:
        """Sampled history older than the current window, or None while warming up."""
        # the newest ceil(window / EVERY) samples are the window's own flows
        own = -(-len(self.recent_feats) // REF_SAMPLE_EVERY)
        rows = list(self.ref_feats)[:len(self.ref_feats) - own]
        if len(rows) < REF_MIN_ROWS:
            return None
        return np.vstack([np.asarray(r, dtype=np.float64) for r in rows])

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
        level = report.get("alert_level", report.get("level"))
        self.cache_drift(report)
        self.drift_level = level
        drifted = level in ("moderate", "significant")
        if drifted and not self.drift_alerted:
            self.drift_alerted = True
            self.events.emit(SystemEvent(type="drift", data=report))
            self.audit.append("alert", {
                "alert_type": "drift",
                "psi": report.get("psi"),
                "level": level,
                "n": report.get("n"),
            })
        elif not drifted:
            self.drift_alerted = False

    def cache_drift(self, report: dict) -> None:
        """Remember the numbers of the newest drift report (for metrics)."""
        recent = report.get("psi_vs_recent") or {}
        self.last_drift = {
            "psi_train": report.get("psi_vs_train", {}).get("psi", report.get("psi")),
            "psi_recent": recent.get("psi") if recent.get("available") else None,
            "level": report.get("alert_level", report.get("level")),
            "n": report.get("n"),
        }

    def set_drift_level(self, level: str | None) -> None:
        """Cache a freshly computed drift level (best-effort refresh)."""
        self.drift_level = level
