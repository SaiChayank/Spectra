"""Training service: fit detector + sidecars on a benign baseline PCAP."""

from __future__ import annotations

import hashlib
import logging
import os

from ..capture import CaptureError
from ..config import Config
from ..features.extractor import flows_to_matrix
from ..store import Store
from ..tools import collect_flows
from .audit import AuditService
from .capture import CaptureService
from .detection import DetectionService
from .events import EventBus
from .model import ModelService

log = logging.getLogger("spectra.engine")


class TrainingService:
    def __init__(self, config: Config, idle_timeout: float,
                 store: Store | None, model: ModelService,
                 detection: DetectionService, capture: CaptureService,
                 audit: AuditService, events: EventBus, status: dict) -> None:
        self.config = config
        self.idle_timeout = idle_timeout
        self.store = store
        self._model = model
        self._detection = detection
        self._capture = capture
        self._audit = audit
        self._events = events
        self.status = status

    def train_from_pcap(self, path: str, contamination: float | None = None) -> dict:
        """Train the detector on the benign baseline contained in a PCAP."""
        if self._capture.running:
            raise CaptureError("stop the active capture before training")
        if contamination is None:
            contamination = self.config.contamination
        flows = collect_flows(path, idle_timeout=self.idle_timeout,
                              bucket=self.config.bucket_seconds)
        if len(flows) < 10:
            raise ValueError(
                f"{path} yielded only {len(flows)} complete flows; need >= 10"
            )
        X = flows_to_matrix(flows)
        detector = self._model.detector
        detector.contamination = contamination
        info = detector.fit(X)
        detector.save(self._model.model_path)

        # Modules 6 + 8: fit the bio layer and the edge micro-detector on the
        # same benign baseline, persisting both sidecars next to the model
        try:
            info["bio"] = self._detection.bio.fit(X)
            self._detection.bio.save(self._detection.bio_path)
        except Exception as exc:  # noqa: BLE001 - bio is an add-on layer
            log.warning("bio fit failed: %s", exc)
            info["bio"] = {"error": str(exc)}
        try:
            info["edge"] = self._detection.edge.fit(X)
            self._detection.edge.save(self._detection.edge_path)
        except Exception as exc:  # noqa: BLE001
            log.warning("edge fit failed: %s", exc)
            info["edge"] = {"error": str(exc)}
        # Module 2: attest the freshly retrained artifact (best effort)
        self._model.remeasure_tee()

        self.status["model_trained"] = True
        info.update({"model_path": self._model.model_path, "pcap": path})
        if self.store is not None:
            try:
                self.store.add_model_run(path, info["n_train"], contamination, info)
            except Exception:  # noqa: BLE001
                log.exception("recording model run failed")
        digest = None
        try:
            if os.path.isfile(self._model.model_path):
                h = hashlib.sha256()
                with open(self._model.model_path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
                digest = h.hexdigest()
        except OSError:  # pragma: no cover - digest is best effort
            digest = None
        self._audit.append("model.train", {
            "pcap": path,
            "n_train": info["n_train"],
            "contamination": contamination,
            "model_path": self._model.model_path,
            "model_sha256": digest,
            "n_features": info.get("n_features"),
        })
        self._events.emit({"type": "model", "data": detector.info()})
        return info
