"""Model service: detector artifact lifecycle, analysis and TEE operations.

Owns the :class:`SpectraDetector` instance (loaded once at construction by
the composition root) and everything that reads it outside the hot path:
model info/version, PSI drift analysis, evasion robustness, shadow-mode
comparison and the Module 2 confidential-computing facade.
"""

from __future__ import annotations

import logging
import os
from collections import deque

import numpy as np

from ..config import Config
from ..domain import ModelVersion
from ..ml.model import SpectraDetector
from ..modules.adv import attack_batch
from ..modules.tee import TeeEnclave, TeeError, federated_round, public_report
from ..modules.twin import run_shadow
from ..features.extractor import flows_to_matrix
from ..tools import collect_flows
from .alerts import AlertService
from .audit import AuditService
from .events import EventBus
from .resilience import FailureTracker

log = logging.getLogger("spectra.engine")


class ModelService:
    def __init__(self, config: Config, model_path: str, idle_timeout: float,
                 detector: SpectraDetector, alerts: AlertService,
                 events: EventBus, audit: AuditService,
                 failures: FailureTracker, recent_feats: deque) -> None:
        self.config = config
        self.model_path = model_path
        self.idle_timeout = idle_timeout
        self.detector = detector
        self.recent_feats = recent_feats
        self._alerts = alerts
        self._events = events
        self._audit = audit
        self._failures = failures

        # Module 2: TEE attestation over the model artifact
        try:
            self.tee = TeeEnclave(model_path)
        except Exception as exc:  # noqa: BLE001 - attestation must not block
            log.warning("tee disabled: %s", exc)
            self.tee = None  # type: ignore[assignment]

    # -- identity -------------------------------------------------------------

    @property
    def is_trained(self) -> bool:
        return self.detector.is_trained

    @property
    def contamination(self) -> float:
        return getattr(self.detector, "contamination", 0.02)

    def info(self) -> dict:
        return self.detector.info()

    def version(self) -> ModelVersion:
        """Immutable identity snapshot of the loaded model artifact."""
        return ModelVersion.from_info(self.model_path, self.detector.info())

    def psi(self, X: np.ndarray) -> dict:
        return self.detector.psi(X)

    # -- Module 3: adversarial resilience ------------------------------------

    def drift_report(self) -> dict:
        """PSI of recent scored flows against the training baseline."""
        if not self.detector.is_trained:
            return {"available": False, "reason": "model not trained"}
        if not self.recent_feats:
            return {"available": False, "reason": "no scored flows yet"}
        X = np.vstack([np.asarray(f, dtype=np.float64) for f in self.recent_feats])
        report = self.detector.psi(X)
        report["window"] = len(self.recent_feats)
        self._alerts.note_drift(report)
        return report

    def refresh_drift_level(self) -> None:
        """Recompute the cached drift level feeding the immune danger axis."""
        try:
            X = np.vstack([np.asarray(f, dtype=np.float64)
                           for f in self.recent_feats])
            report = self.detector.psi(X)
            if report.get("available"):
                self._alerts.set_drift_level(report.get("level"))
        except Exception:  # noqa: BLE001 - drift cache is best effort
            pass

    def robustness(self, pcap: str | None = None, max_features: int = 12,
                   max_rounds: int = 6) -> dict:
        """Run evasion attacks against detected flows (PCAP or recent window)."""
        if not self.detector.is_trained:
            return {"available": False, "reason": "model not trained"}
        if pcap:
            flows = collect_flows(pcap, idle_timeout=self.idle_timeout)
            X = flows_to_matrix(flows) if flows else np.empty((0, 0))
            source = pcap
        else:
            if not self.recent_feats:
                return {"available": False, "reason": "no scored flows yet"}
            X = np.vstack([np.asarray(f, dtype=np.float64)
                           for f in self.recent_feats])
            source = "live window"
        if len(X) == 0:
            return {"available": False, "reason": "no flows to evaluate"}
        result = attack_batch(self.detector, X, max_features=max_features,
                              max_rounds=max_rounds)
        result["available"] = True
        result["source"] = source
        return result

    # -- Module 4: shadow mode -------------------------------------------------

    def shadow(self, pcap: str | None = None, contamination: float = 0.05,
               threshold: float = 3.5, retrain: bool = True) -> dict:
        """Module 4 shadow mode: quantify lift over a legacy z-score rule."""
        if not self.detector.is_trained:
            return {"available": False, "reason": "model not trained"}
        if pcap:
            flows = collect_flows(pcap, idle_timeout=self.idle_timeout)
            X = flows_to_matrix(flows) if flows else np.empty((0, 0))
            source = pcap
        else:
            if not self.recent_feats:
                return {"available": False, "reason": "no scored flows yet"}
            X = np.vstack([np.asarray(f, dtype=np.float64)
                           for f in self.recent_feats])
            source = "live window"
        if len(X) == 0:
            return {"available": False, "reason": "no flows to evaluate"}
        candidate = None
        if retrain:
            candidate = SpectraDetector(contamination=contamination,
                                        random_state=42)
            candidate.fit(X)
        result = run_shadow(self.detector, X, candidate=candidate,
                            feature_names=self.detector.feature_names,
                            threshold=threshold)
        result["source"] = source
        return result

    # -- Module 2: confidential computing -------------------------------------

    def tee_attest(self, nonce: str | None = None) -> dict:
        if self.tee is None:
            raise TeeError("attestation unavailable in this process")
        return self.tee.quote(nonce)

    def tee_verify(self, quote: dict, measurement: str | None = None,
                   max_age: float = 600.0, nonce: str | None = None) -> dict:
        if self.tee is None:
            raise TeeError("attestation unavailable in this process")
        return self.tee.verify(quote, measurement=measurement,
                               max_age=max_age, nonce=nonce)

    def tee_infer(self, features) -> dict:
        """Sealed inference: features in, score + signed receipt out."""
        if self.tee is None:
            raise TeeError("attestation unavailable in this process")
        return self.tee.infer(self.detector, features)

    def tee_federate(self, deltas=None, shareholders: int = 3,
                     seed: int = 7) -> dict:
        """Secure aggregation: explicit deltas or the live window's means."""
        if deltas is None:
            window = list(self.recent_feats)
            if len(window) < 4:
                raise TeeError("no live window to federate - pass deltas")
            parties = 3
            step = max(1, len(window) // parties)
            groups = [window[i * step:(i + 1) * step]
                      for i in range(parties)]
            groups = [g for g in groups if g]
            deltas = [np.mean([np.asarray(f, dtype=np.float64)
                               for f in g], axis=0).tolist()
                      for g in groups]
        return public_report(
            federated_round(deltas, shareholders=shareholders, seed=seed)
        )

    def remeasure_tee(self) -> None:
        """Re-attest the freshly retrained artifact (best effort)."""
        if self.tee is None:
            return
        try:
            # Module 2: attest the freshly retrained artifact
            self.tee.remeasure()
        except Exception:  # noqa: BLE001
            pass
