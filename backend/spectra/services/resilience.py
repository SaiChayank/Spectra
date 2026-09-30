"""Optional-module failure isolation shared by every service boundary.

Counts and structurally logs failures of advanced (optional) modules so a
failing module degrades its own output instead of stopping packet capture or
core inference.  Never raises.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Callable

log = logging.getLogger("spectra.engine")


class FailureTracker:
    """Counts optional-module failures and mirrors them into ``status``.

    One tracker instance lives per engine and is injected into every service,
    so ``status["failures"]`` keeps its historical flat shape.
    """

    def __init__(self, status: dict) -> None:
        self._failures: Counter = Counter()
        self._status = status
        status["failures"] = dict(self._failures)

    @property
    def counts(self) -> dict:
        return dict(self._failures)

    def record(self, component: str, exc: BaseException) -> None:
        """Count and structurally log an optional-module failure.

        Never raises. Called from every module boundary in the hot path.
        Log lines are grep-able key=value structured records with full
        tracebacks.
        """
        self._failures[component] += 1
        self._status["failures"] = dict(self._failures)
        log.error(
            "optional module failed: component=%s error_type=%s error=%s failures=%d",
            component, type(exc).__name__, exc, self._failures[component],
            exc_info=True,
        )

    def guard(self, component: str, fn: Callable, default=None):
        """Run an optional-module callable; failures become ``default``."""
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - module isolation is the contract
            self.record(component, exc)
            return default
