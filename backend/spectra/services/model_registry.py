"""Model registry service (Prompt 14): artifact lifecycle + trust.

State machine (validated here; the single-ACTIVE index in the schema is the
database half of the invariant):

    CANDIDATE -> VALIDATED -> ACTIVE -> RETIRED (superseded)
    CANDIDATE -> FAILED     (validation gate)
    RETIRED   -> ACTIVE     (re-activate / rollback)

Trust rules - only locally generated or verified artifacts load:

* artifacts live in ``<data_dir>/model_artifacts/<model_id>.joblib``, one
  immutable file per registration (never overwritten);
* every load re-runs path containment + sha256 match + ``SpectraDetector.load``
  (which rejects a version or feature-schema mismatch);
* the session detector changes **only** through :meth:`activate`: the engine
  injects an ``on_activate`` hook that swaps the live detector, syncs the
  deployed copy, re-measures TEE, repoints the evasion watch, emits the
  ``model`` event and (via this service) writes the hash-chained audit entry
  ``model.activate`` / ``model.rollback``.

The service never imports another service.  The engine binds ``audit`` and
``on_activate`` right after construction, and ``store`` is a plain attribute
so the engine's store-rebinding seam reaches it like every other store-backed
service.  With no store (``persist=False``) the registry reports itself
disabled: reads answer ``enabled: false`` and writes raise
:class:`RegistryUnavailable` (409) - the lifecycle is a persistence feature.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
import uuid
from datetime import datetime
from functools import wraps

from ..config import Config
from ..features.extractor import FEATURE_NAMES, feature_schema_digest
from ..ml.model import SpectraDetector

log = logging.getLogger("spectra.engine")

#: Minimum training rows an artifact must carry to pass validation.
MIN_TRAIN_ROWS = 10


class RegistryError(Exception):
    """Domain error for registry operations (routers map status_code)."""

    status_code = 400


class RegistryNotFound(RegistryError):
    status_code = 404


class RegistryConflict(RegistryError):
    status_code = 409


class RegistryUnavailable(RegistryError):
    status_code = 409


def _epoch(value) -> float | None:
    """Stored ``trained_at``: epoch float, ISO string from detector.info()."""
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except ValueError:
        return None


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class ModelRegistryService:
    """Registry lifecycle over ``model_registry`` rows + artifact files."""

    def __init__(self, config: Config, store=None, *, failures=None) -> None:
        self.config = config
        self.store = store
        self.failures = failures
        #: AuditService - bound by the engine (a registry never imports one).
        self.audit = None
        #: ``fn(detector, row, action)`` - engine hook for session side effects.
        self.on_activate = None
        self.artifacts_dir = os.path.join(config.data_dir, "model_artifacts")
        #: Serializes every row transition (register/validate/activate/...).
        #: Reentrant because ``rollback`` re-enters ``activate`` and the
        #: engine's ``on_activate`` hook may call back into the registry;
        #: without it two concurrent transitions could observe the same
        #: CANDIDATE and race past the status gate.
        self.lock = threading.RLock()

    # -- capability -----------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return self.store is not None

    def _require_store(self):
        if self.store is None:
            raise RegistryUnavailable(
                "persistence is disabled - the model registry needs the "
                "local store")
        return self.store

    def _append_audit(self, kind: str, payload: dict, actor: str | None) -> None:
        if self.audit is None:
            return
        try:
            self.audit.append(kind, payload, actor=actor)
        except Exception:  # noqa: BLE001 - auditing must never block ops
            log.exception("registry audit append failed (%s)", kind)

    def _record_failure(self, component: str, exc: Exception) -> None:
        if self.failures is None:
            return
        try:
            self.failures.record(component, exc)
        except Exception:  # noqa: BLE001 - telemetry is best effort
            pass

    @staticmethod
    def _serialized(method):
        """Run a registry transition under the service's reentrant lock.

        Applied to every status-changing entry point so a check-then-write
        (``status == CANDIDATE`` -> ``VALIDATED``) cannot interleave with a
        concurrent transition.  ``RLock`` keeps nested calls (``rollback``
        -> ``activate``, ``adopt`` -> ``register``) on the same thread safe.
        """

        @wraps(method)
        def wrapper(self, *args, **kwargs):
            with self.lock:
                return method(self, *args, **kwargs)

        return wrapper

    # -- artifact trust -------------------------------------------------------

    def artifact_path(self, row: dict) -> str:
        """Containment-checked absolute path of a registry artifact."""
        base = os.path.realpath(self.artifacts_dir)
        candidate = os.path.realpath(os.path.join(base, str(row["artifact"])))
        if os.path.dirname(candidate) != base:
            raise RegistryError(
                f"registry artifact escapes the artifact directory: "
                f"{row['artifact']}")
        return candidate

    def trust_load(self, row: dict) -> SpectraDetector:
        """Path containment + sha256 match + schema-checked load."""
        path = self.artifact_path(row)
        if not os.path.isfile(path):
            raise RegistryError(
                f"artifact missing for {row['model_id']}: {row['artifact']}")
        digest = sha256_file(path)
        if digest != row["artifact_sha256"]:
            raise RegistryError(
                f"artifact sha256 mismatch for {row['model_id']} "
                f"(recorded {str(row['artifact_sha256'])[:12]}..., "
                f"file {digest[:12]}...)")
        return SpectraDetector.load(path)  # raises on version/schema mismatch

    # -- reads ----------------------------------------------------------------

    def count(self) -> int:
        return 0 if self.store is None else self.store.model_registry_count()

    def active(self) -> dict | None:
        return None if self.store is None else self.store.model_registry_active()

    def active_detector(self) -> tuple[SpectraDetector, dict] | None:
        """(detector, row) of the ACTIVE model, trust-checked.

        ``None`` when persistence is off, there is no active model, or its
        artifact fails the trust checks - the caller degrades to an untrained
        session, **never** to a different artifact (a registry row exists ->
        the registry is authoritative).
        """
        row = self.active()
        if row is None:
            return None
        try:
            return self.trust_load(row), row
        except Exception as exc:  # noqa: BLE001 - degrade, never crash startup
            log.warning("active model artifact failed trust checks: %s", exc)
            self._record_failure("model_registry", exc)
            return None

    def get(self, model_id: str) -> dict:
        self._require_store()
        row = self.store.model_registry_get(str(model_id))
        if row is None:
            raise RegistryNotFound(f"unknown model: {model_id}")
        return row

    def list(self, limit: int = 100, offset: int = 0) -> dict:
        if self.store is None:
            return {"enabled": False, "count": 0, "offset": offset,
                    "active": None, "items": []}
        page = self.store.model_registry_list(limit, offset=offset)
        return {"enabled": True, "count": page["count"],
                "offset": page["offset"],
                "active": self.store.model_registry_active(),
                "items": page["items"]}

    def compare(self, model_id_a: str, model_id_b: str) -> dict:
        a, b = self.get(model_id_a), self.get(model_id_b)

        def numeric(key: str) -> dict:
            va, vb = a.get(key), b.get(key)
            if not isinstance(va, (int, float)) or not isinstance(vb, (int, float)) \
                    or isinstance(va, bool) or isinstance(vb, bool):
                return {"a": va, "b": vb, "delta": None}
            delta = float(vb) - float(va)
            return {"a": va, "b": vb,
                    "delta": round(delta, 6) if delta % 1 else int(delta)}

        return {
            "a": a,
            "b": b,
            "diff": {
                "same_artifact": a["artifact_sha256"] == b["artifact_sha256"],
                "same_feature_schema":
                    a.get("feature_schema") == b.get("feature_schema"),
                "threshold": numeric("threshold"),
                "n_train": numeric("n_train"),
                "contamination": numeric("contamination"),
                "activated_count": numeric("activated_count"),
                "status": {"a": a["status"], "b": b["status"]},
                "model_version": {"a": a.get("model_version"),
                                  "b": b.get("model_version")},
                "trained_at": {"a": a.get("trained_at"),
                               "b": b.get("trained_at")},
            },
        }

    # -- lifecycle ------------------------------------------------------------

    @_serialized
    def register(self, detector: SpectraDetector, *, source: str,
                 metrics: dict | None = None,
                 actor: str | None = None) -> dict:
        """Persist a trained detector as a new CANDIDATE + immutable artifact."""
        store = self._require_store()
        os.makedirs(self.artifacts_dir, exist_ok=True)
        model_id = f"mdl_{uuid.uuid4().hex[:12]}"
        relative = f"{model_id}.joblib"
        path = os.path.join(self.artifacts_dir, relative)
        detector.save(path)
        info = detector.info()
        row = store.model_registry_add({
            "model_id": model_id,
            "created_at": time.time(),
            "source": source,
            "artifact": relative,
            "artifact_sha256": sha256_file(path),
            "status": "CANDIDATE",
            "trained_at": _epoch(info.get("trained_at")),
            "n_train": int(info.get("n_train") or 0),
            "contamination": float(info.get("contamination") or 0.0),
            "n_features": int(info.get("n_features") or 0),
            "feature_schema": feature_schema_digest(
                list(info.get("feature_names") or [])),
            "model_version": str(info.get("version") or ""),
            "threshold": info.get("threshold"),
            "metrics": metrics or {},
        })
        self._append_audit("model.register", {
            "model_id": model_id,
            "artifact_sha256": row["artifact_sha256"],
            "source": source,
            "n_train": row["n_train"],
            "contamination": row["contamination"],
        }, actor)
        return row

    @_serialized
    def validate(self, model_id: str, *, actor: str | None = None) -> dict:
        """Validation gate: CANDIDATE -> VALIDATED, or -> FAILED with reasons."""
        store = self._require_store()
        row = self.get(model_id)
        if row["status"] != "CANDIDATE":
            raise RegistryConflict(
                f"validate requires a CANDIDATE (model {model_id} is "
                f"{row['status']})")

        checks: list[dict] = []
        failed: list[str] = []

        def check(name: str, ok: bool, detail: str = "") -> None:
            checks.append({"name": name, "ok": bool(ok), "detail": detail})
            if not ok:
                failed.append(f"{name}: {detail}" if detail else name)

        path = None
        try:
            path = self.artifact_path(row)
            check("artifact_contained", True, row["artifact"])
        except RegistryError as exc:
            check("artifact_contained", False, str(exc))

        detector = None
        if path is not None:
            exists = os.path.isfile(path)
            check("artifact_exists", exists, row["artifact"])
            if exists:
                digest = sha256_file(path)
                check("artifact_sha256", digest == row["artifact_sha256"],
                      f"file {digest[:12]}...")
                try:
                    detector = SpectraDetector.load(path)
                    check("artifact_loads", True,
                          f"model version {detector.info().get('version')}")
                except Exception as exc:  # noqa: BLE001 - gate records it
                    check("artifact_loads", False, str(exc))

        if detector is not None:
            info = detector.info()
            check("trained", bool(info.get("trained")),
                  f"n_train={info.get('n_train')}")
            check("threshold_set", info.get("threshold") is not None,
                  str(info.get("threshold")))
            check("min_training_rows",
                  int(info.get("n_train") or 0) >= MIN_TRAIN_ROWS,
                  f"n_train={info.get('n_train')} (need >= {MIN_TRAIN_ROWS})")
            check("feature_schema",
                  list(info.get("feature_names") or []) == list(FEATURE_NAMES),
                  "digest matches the current feature schema")

        metrics = {
            "checks": checks,
            "failed": failed,
            "passed": not failed,
            "validated_at": time.time(),
        }
        if failed:
            store.model_registry_set_status(
                model_id, "FAILED", metrics=metrics,
                error="; ".join(failed)[:500])
            self._append_audit("model.validate", {
                "model_id": model_id, "ok": False, "failed": failed,
            }, actor)
        else:
            store.model_registry_set_status(
                model_id, "VALIDATED", metrics=metrics, clear_error=True)
            self._append_audit("model.validate", {
                "model_id": model_id, "ok": True,
                "threshold": row.get("threshold"),
            }, actor)
        return store.model_registry_get(model_id)

    @_serialized
    def activate(self, model_id: str, *, actor: str | None = None,
                 action: str = "activate",
                 adopted: bool = False) -> dict:
        """VALIDATED/RETIRED -> ACTIVE: atomic promote + session side effects.

        The row is persisted first (single source of truth, single ACTIVE
        guaranteed by the transaction), then the engine hook applies the
        session effects.  A hook failure is recorded on the response
        (``applied: false``) rather than rolling back the promotion - the
        registry stays authoritative and the engine logs the degradation.
        """
        store = self._require_store()
        row = self.get(model_id)
        if row["status"] == "ACTIVE":
            raise RegistryConflict(f"model {model_id} is already active")
        if row["status"] not in ("VALIDATED", "RETIRED"):
            raise RegistryConflict(
                f"activate requires VALIDATED or RETIRED "
                f"(model {model_id} is {row['status']})")

        previous = store.model_registry_active()
        detector = self.trust_load(row)     # re-verify right before the swap
        promoted = store.model_registry_activate(model_id, time.time())

        applied, hook_error = True, None
        if self.on_activate is not None:
            try:
                self.on_activate(detector, promoted, action)
            except Exception as exc:  # noqa: BLE001 - see docstring
                applied, hook_error = False, str(exc)
                log.exception("model activation side effects failed (%s)",
                              model_id)
                self._record_failure("model_activation", exc)

        self._append_audit(
            "model.rollback" if action == "rollback" else "model.activate",
            {"model_id": model_id,
             "artifact_sha256": promoted["artifact_sha256"],
             "previous": (previous or {}).get("model_id"),
             "applied": applied,
             **({"adopted": True} if adopted else {})},
            actor)
        result = dict(promoted)
        result["applied"] = applied
        if hook_error:
            result["hook_error"] = hook_error
        return result

    @_serialized
    def rollback(self, *, actor: str | None = None) -> dict:
        """RETIRED -> ACTIVE for the most recently superseded model."""
        store = self._require_store()
        current = store.model_registry_active()
        if current is None:
            raise RegistryConflict("no active model to roll back from")
        cursor = float(current.get("last_activated_at")
                       or current.get("created_at") or 0.0)
        previous = store.model_registry_previous_active(cursor)
        if previous is None:
            raise RegistryConflict(
                "no previously activated model to roll back to")
        return self.activate(previous["model_id"], actor=actor,
                             action="rollback")

    @_serialized
    def retire(self, model_id: str, *, actor: str | None = None) -> dict:
        """CANDIDATE/VALIDATED -> RETIRED (the ACTIVE model can't retire)."""
        store = self._require_store()
        row = self.get(model_id)
        status = row["status"]
        if status == "ACTIVE":
            raise RegistryConflict(
                f"activate another model before retiring {model_id}")
        if status == "RETIRED":
            raise RegistryConflict(f"model {model_id} is already retired")
        if status == "FAILED":
            raise RegistryConflict(
                f"failed model {model_id} was never active - "
                "there is nothing to retire")
        updated = store.model_registry_set_status(
            model_id, "RETIRED", retired_at=time.time())
        self._append_audit("model.retire", {
            "model_id": model_id, "from": status,
            "artifact_sha256": row["artifact_sha256"],
        }, actor)
        return updated

    @_serialized
    def adopt(self, deployed_path: str, *, actor: str = "system") -> dict | None:
        """First startup: register + validate + activate the legacy artifact.

        Only on an *empty* registry (callers check first) with a trained
        deployed model - gives an existing deployment an explicit ACTIVE row
        without re-training.  The activation audit carries ``adopted: true``.
        """
        store = self._require_store()
        if store.model_registry_count() > 0:
            return None
        if not os.path.isfile(deployed_path):
            return None
        try:
            detector = SpectraDetector.load(deployed_path)
        except Exception as exc:  # noqa: BLE001 - adoption is opportunistic
            log.info("model adoption skipped (load failed): %s", exc)
            return None
        if not detector.is_trained:
            return None
        row = self.register(
            detector,
            source=f"adopted:{os.path.basename(deployed_path)}",
            metrics={"adopted": True, "n_train": detector.n_train},
            actor=actor)
        row = self.validate(row["model_id"], actor=actor)
        if row["status"] != "VALIDATED":
            log.warning("adopted model failed validation: %s", row.get("error"))
            return row
        return self.activate(row["model_id"], actor=actor, adopted=True)
