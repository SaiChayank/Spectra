"""Adversarial-retraining harness (Phase 9B): report only, never promotes.

One run:

  1. take the incumbent's flagged flows as the attack set,
  2. attack each with ``modules.adv.evasion.attack`` and keep the perturbed
     vectors,
  3. fit a *scratch* candidate on the baseline plus those vectors
     (``TrainingService.augmented_fit``),
  4. measure incumbent and candidate on the same attack set and the same
     baseline, shadow-compare them (``modules.twin.shadow.run_shadow``),
  5. return a recommendation from :func:`decide` and audit-chain the run
     (``model.harden`` + ``model.shadow``).

The session detector and the registry are never touched: promotion is the
existing explicit register -> validate -> activate path.  The recommendation
is conservative on purpose - a recorded experiment (HANDOFF_FINDINGS.md, 9B)
found that augmenting an Isolation Forest with evaded vectors does *not*
reduce evasion, so ``promote`` is only ever true when this run measures a
real, same-set gain.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Callable

import numpy as np

from ..features.extractor import flows_to_matrix
from ..modules.adv.evasion import attack
from ..modules.twin.shadow import run_shadow
from ..tools import collect_flows
from .audit import AuditService
from .model import ModelService
from .training import TrainingService

log = logging.getLogger("spectra.engine")

#: smallest attack set worth a verdict; below this a "gain" is noise.
MIN_ATTACK_ROWS = 5
#: after-attack detection must beat the incumbent by at least this much.
MIN_ROBUSTNESS_GAIN = 0.05
#: tolerated rise in the candidate's false-flag rate on the baseline.
MAX_FALSE_FLAG_RISE = 0.01


def decide(incumbent: dict, candidate: dict) -> tuple[bool, str]:
    """Gate: ``(promote, reason)``; blocks on any regression, never promotes."""
    blockers = []
    gain = candidate["detect_after"] - incumbent["detect_after"]
    if gain < MIN_ROBUSTNESS_GAIN:
        blockers.append(
            f"no robustness gain: {candidate['detect_after']:.1%} of the attack "
            f"set still detected after attack vs {incumbent['detect_after']:.1%} "
            f"for the incumbent (need +{MIN_ROBUSTNESS_GAIN:.0%})")
    if candidate["detect_before"] < incumbent["detect_before"]:
        blockers.append(
            f"candidate detects fewer attack-set flows before any attack "
            f"({candidate['detect_before']:.1%} vs {incumbent['detect_before']:.1%})")
    if candidate["false_flag_rate"] > incumbent["false_flag_rate"] + MAX_FALSE_FLAG_RISE:
        blockers.append(
            f"false-flag rate rose on the baseline "
            f"({candidate['false_flag_rate']:.1%} vs {incumbent['false_flag_rate']:.1%})")
    if blockers:
        return False, "; ".join(blockers)
    return True, ("candidate is more robust at no false-flag cost on this run; "
                  "promotion is a separate explicit step (register, validate, activate)")


def _measure(detector, attack_set: np.ndarray, baseline: np.ndarray,
             max_features: int, max_rounds: int) -> dict:
    """Detection of the attack set before/after attacking it, plus baseline FPs."""
    flagged = np.asarray(detector.predict(attack_set)).astype(bool)
    after = 0
    for row, was_flagged in zip(attack_set, flagged, strict=True):
        if not was_flagged:
            continue            # already evades; stays undetected
        out = attack(detector, row, max_features=max_features, max_rounds=max_rounds)
        if not out["evaded"]:
            after += 1
    n = len(attack_set)
    return {
        "detect_before": round(float(flagged.mean()), 4),
        "detect_after": round(after / n, 4),
        "false_flag_rate": round(float(np.mean(detector.predict(baseline))), 4),
    }


class HardenScheduler:
    """Daemon thread calling ``run`` every ``interval_s``; failures are logged."""

    def __init__(self, run: Callable[[], object], interval_s: float) -> None:
        self._run = run
        self._interval = float(interval_s)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="harden-scheduler",
                                        daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self._run()
            except Exception:  # noqa: BLE001 - a bad run must not end the schedule
                log.exception("scheduled harden run failed")


class HardenService:
    def __init__(self, config, model: ModelService, training: TrainingService,
                 audit: AuditService) -> None:
        self.config = config
        self._model = model
        self._training = training
        self._audit = audit

    def harden(self, pcap: str | None = None, *, contamination: float | None = None,
               max_features: int = 12, max_rounds: int = 6,
               max_attack_rows: int = 50, actor: str = "spectra") -> dict:
        """One report-only run on a capture's flows, or the live window."""
        with self._model.analysis_slot():
            incumbent = self._model.detector
            if not incumbent.is_trained:
                return {"available": False, "reason": "model not trained"}
            if pcap:
                flows = collect_flows(pcap, idle_timeout=self._model.idle_timeout)
                X = flows_to_matrix(flows) if flows else np.empty((0, 0))
                source = os.path.basename(str(pcap))
            else:
                if not self._model.recent_feats:
                    return {"available": False, "reason": "no scored flows yet"}
                X = np.vstack([np.asarray(f, dtype=np.float64)
                               for f in self._model.recent_feats])
                source = "live window"
            if len(X) < 10:
                return {"available": False,
                        "reason": f"need >= 10 flows, got {len(X)}"}

            attack_set = X[np.asarray(incumbent.predict(X)).astype(bool)][:max_attack_rows]
            base = {"available": True, "promoted": False, "source": source,
                    "n_flows": int(len(X)), "n_attack": int(len(attack_set))}
            if len(attack_set) < MIN_ATTACK_ROWS:
                result = {**base, "promote": False,
                          "reason": (f"attack set too small ({len(attack_set)} flagged "
                                     f"flows, need {MIN_ATTACK_ROWS})"),
                          "incumbent": None, "candidate": None, "shadow": None}
                self._record(result, actor, contamination)
                return result

            attacked = np.array([
                attack(incumbent, r, max_features=max_features,
                       max_rounds=max_rounds)["perturbed"] for r in attack_set])
            candidate = self._training.augmented_fit(
                X, attacked, contamination=contamination)
            inc_m = _measure(incumbent, attack_set, X, max_features, max_rounds)
            cand_m = _measure(candidate, attack_set, X, max_features, max_rounds)
            promote, reason = decide(inc_m, cand_m)
            shadow = run_shadow(incumbent, X, candidate=candidate,
                                feature_names=incumbent.feature_names)
            result = {**base, "promote": promote, "reason": reason,
                      "incumbent": inc_m, "candidate": cand_m, "shadow": shadow}
            self._record(result, actor, contamination)
            return result

    def _record(self, result: dict, actor: str, contamination: float | None) -> None:
        """Audit-chain the run (never raises: AuditService.append is guarded)."""
        self._audit.append("model.harden", {
            "source": result["source"], "n_flows": result["n_flows"],
            "n_attack": result["n_attack"], "promote": result["promote"],
            "reason": result["reason"], "incumbent": result["incumbent"],
            "candidate": result["candidate"], "contamination": contamination,
        }, actor=actor)
        shadow = result["shadow"]
        if shadow and shadow.get("available"):
            self._audit.append("model.shadow", {
                "source": result["source"], "window": shadow["window"],
                "verdict": shadow["verdict"],
                "reference_flags": shadow["comparison"]["reference_flags"],
                "candidate_flags": shadow["comparison"].get("candidate_flags"),
                "candidate_agreement": shadow["comparison"].get("candidate_agreement"),
            }, actor=actor)

    def start_scheduler(self) -> HardenScheduler | None:
        """Start the periodic run on the live window, or None when disabled."""
        hours = float(getattr(self.config, "harden_interval_h", 0.0) or 0.0)
        if hours <= 0:
            return None

        def run() -> None:
            res = self.harden(actor="spectra-scheduler")
            log.info("scheduled harden run: promote=%s reason=%s",
                     res.get("promote"), res.get("reason"))

        sched = HardenScheduler(run, interval_s=hours * 3600)
        sched.start()
        return sched
