"""Audit trail service: guarded appends plus query/proof/certificate ops."""

from __future__ import annotations

import logging

from ..modules.audit import AuditLog, build_certificate, verify_certificate
from ..store import Store
from .resilience import FailureTracker

log = logging.getLogger("spectra.engine")


class AuditService:
    """Facade over the Module 5 hash-chained audit log.

    ``append`` is the guarded choke point every service uses from code paths
    that must never raise (hot path, capture loop); query/proof/certificate
    operations are the API surface.
    """

    def __init__(self, store: Store | None, model_path: str,
                 failures: FailureTracker) -> None:
        try:
            self.log = AuditLog(store)
        except Exception as exc:  # noqa: BLE001 - audit must never block startup
            log.warning("audit log disabled: %s", exc)
            self.log = AuditLog(store=None)
        self.store = store
        self.model_path = model_path
        self.failures = failures

    # -- guarded append ------------------------------------------------------

    def append(self, kind: str, payload: dict, leaves=None,
               actor: str = "spectra") -> dict | None:
        """Append to the audit log; never raises into the capture path.

        ``actor`` names the responsible principal (``"spectra"`` for engine
        activity, a username for authentication/user-management events).
        """
        try:
            return self.log.append(kind, payload, leaves=leaves, actor=actor)
        except Exception as exc:  # noqa: BLE001 - auditing must never kill capture
            self.failures.record("audit", exc)
            return None

    # -- queries -------------------------------------------------------------

    def entries(self, limit: int = 50, offset: int = 0,
                kind: str | None = None, *, kind_prefix: str | None = None,
                since: float | None = None, until: float | None = None,
                actor: str | None = None) -> dict:
        """Filtered page of entries; ``count`` reflects the same filters."""
        return {
            "count": self.log.count(kind, kind_prefix=kind_prefix,
                                    since=since, until=until, actor=actor),
            "signing_key": self.log.pubkey,
            "items": self.log.entries(limit=limit, offset=offset, kind=kind,
                                      kind_prefix=kind_prefix, since=since,
                                      until=until, actor=actor),
        }

    def head(self) -> dict:
        return self.log.head()

    def verify(self) -> dict:
        return self.log.verify()

    def checkpoint(self) -> dict:
        return self.log.checkpoint()

    def verify_checkpoint(self, seq: int | None = None) -> dict:
        return self.log.verify_checkpoint(seq=seq)

    def proof(self, seq: int, leaf: int) -> dict:
        proof = self.log.inclusion_proof(int(seq), int(leaf))
        if proof is None:
            raise ValueError(
                f"no Merkle leaf {leaf} on entry {seq} (entry missing or has no leaves)"
            )
        return proof

    # -- certificates ---------------------------------------------------------

    def certify(self, profile: str = "hipaa", since: float | None = None,
                until: float | None = None, min_flows: int = 1,
                disclose: int = 3, bits: int = 32) -> dict:
        """Issue a signed compliance certificate over persisted evidence."""
        if self.store is None:
            raise ValueError("persistence is required to issue certificates")
        return build_certificate(
            self.store, self.log, profile=profile, since=since, until=until,
            min_flows=min_flows, disclose=disclose, bits=bits,
            model_path=self.model_path,
        )

    def verify_certificate(self, bundle: dict) -> dict:
        return verify_certificate(bundle, log=self.log,
                                  model_path=self.model_path)
