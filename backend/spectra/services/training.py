"""Training service: fit detector + sidecars on a benign baseline PCAP."""

from __future__ import annotations

import hashlib
import logging
import os

from ..capture import CaptureError
from ..config import Config
from ..features.extractor import flows_to_matrix
from ..ml.model import SpectraDetector
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
                 audit: AuditService, events: EventBus, status: dict,
                 registry=None) -> None:
        self.config = config
        self.idle_timeout = idle_timeout
        self.store = store
        self._model = model
        self._detection = detection
        self._capture = capture
        self._audit = audit
        self._events = events
        self.status = status
        #: ModelRegistryService - bound by the engine (None = legacy train).
        self.registry = registry

    def train_from_pcap(self, path: str, contamination: float | None = None,
                        *, activate: bool = True,
                        actor: str | None = None) -> dict:
        """Train the detector on the benign baseline contained in a PCAP.

        Persistence on (Prompt 14): the baseline fits a **scratch** detector
        that is saved as an immutable registry artifact and registered as a
        CANDIDATE; with ``activate=True`` (the default, so training keeps its
        product contract) the audited chain register -> validate -> activate
        runs and the *session* detector swaps only at the end of it.  With
        ``activate=False`` the session detector is untouched - the caller gets
        a candidate to inspect (validate/compare) and activate later.

        Persistence off: legacy behaviour - fit the live session detector and
        write ``model_path`` (the lifecycle is a persistence feature).

        Single-flight (``ModelService.analysis_slot``): a concurrent train,
        robustness or shadow run is refused with ``AnalysisBusy`` instead of
        two fits racing the same detector/registry.
        """
        if self._capture.running:
            raise CaptureError("stop the active capture before training")
        with self._model.analysis_slot():
            return self._train_locked(path, contamination,
                                      activate=activate, actor=actor)

    def _train_locked(self, path: str, contamination: float | None,
                      *, activate: bool, actor: str | None) -> dict:
        """Body of :meth:`train_from_pcap` (runs with the slot held)."""
        if contamination is None:
            contamination = self.config.contamination
        flows = collect_flows(path, idle_timeout=self.idle_timeout,
                              bucket=self.config.bucket_seconds)
        if len(flows) < 10:
            raise ValueError(
                f"{os.path.basename(str(path))} yielded only {len(flows)} "
                "complete flows; need >= 10"
            )
        X = flows_to_matrix(flows)

        registry = self.registry if (self.registry is not None
                                     and self.registry.enabled) else None
        registry_info: dict | None = None
        registry_row: dict | None = None

        if registry is None:
            # Legacy: the session detector *is* the new model.
            detector = self._model.detector
            detector.contamination = contamination
            info = detector.fit(X)
            detector.save(self._model.model_path)
        else:
            scratch = SpectraDetector()
            scratch.contamination = contamination
            info = scratch.fit(X)
            row = registry.register(scratch, source=path, metrics=info,
                                    actor=actor)
            registry_row = row
            registry_info = {"model_id": row["model_id"],
                             "status": row["status"], "activated": False}
            if activate:
                row = registry.validate(row["model_id"], actor=actor)
                registry_info["status"] = row["status"]
                if row["status"] != "VALIDATED":
                    # Fresh fits always pass the gate; if one ever does not
                    # the session stays on its current model.
                    registry_info["error"] = row.get("error")
                    log.warning("trained model failed validation: %s",
                                row.get("error"))
                else:
                    row = registry.activate(row["model_id"], actor=actor)
                    registry_row = row
                    registry_info["status"] = row["status"]
                    registry_info["activated"] = bool(row.get("applied", True))

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
        # Module 2: attest the deployed artifact (best effort).  Activation
        # already re-measured after its copy; this keeps the legacy and
        # candidate-only paths attesting what is actually deployed.
        self._model.remeasure_tee()

        # Truthful in every path: reflects the *session* detector, which only
        # activation swaps (the registry hook sets it too - same value).
        self.status["model_trained"] = self._model.detector.is_trained
        info.update({"model_path": self._model.model_path, "pcap": path})
        if registry_info is not None:
            info["registry"] = registry_info
        if self.store is not None:
            try:
                self.store.add_model_run(path, info["n_train"], contamination, info)
            except Exception:  # noqa: BLE001
                log.exception("recording model run failed")
        if registry_row is not None:
            digest = registry_row["artifact_sha256"]
        else:
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
        payload = {
            "pcap": path,
            "n_train": info["n_train"],
            "contamination": contamination,
            "model_path": self._model.model_path,
            "model_sha256": digest,
            "n_features": info.get("n_features"),
        }
        if registry_info is not None:
            payload.update({"model_id": registry_info["model_id"],
                            "registry_status": registry_info["status"],
                            "activated": registry_info["activated"]})
        self._audit.append("model.train", payload)
        # Announce only a model *change* on the legacy path; the registry
        # path announces from its activation hook (candidate-only training
        # leaves the session model untouched, so there is nothing to emit).
        if registry is None:
            self._events.emit({"type": "model",
                               "data": self._model.detector.info()})
        return info
