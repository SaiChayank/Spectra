"""Digest sidecars for persisted ML state (bio/edge ``joblib`` artifacts).

``joblib.load`` executes whatever a pickle describes, and a partially
written or silently corrupted state file would otherwise be applied as
though it were trusted.  Every ``save`` records ``<path>.sha256`` and the
matching ``load`` refuses a file whose bytes no longer hash to it, so a
truncated dump or a stray rewrite can never be mistaken for good state.

This is *integrity* (corruption detection), not authentication: anyone
with write access to the directory can rewrite both files.  The signed
guarantee for the detector artifact itself comes from the model registry
(``artifact_sha256`` + audit) and from TEE attestation; these sidecars
only keep the add-on layers from loading damaged bytes.

Policy for a *missing* sidecar: the file predates this mechanism (an
existing deployment), so it is loaded with a warning instead of being
dropped - upgrades stay silent.  A sidecar that exists but cannot be read
or does not match is refused.
"""

from __future__ import annotations

import hashlib
import logging
import os

log = logging.getLogger("spectra.engine")

#: Suffix appended to an artifact path for its digest file.
DIGEST_SUFFIX = ".sha256"


def sha256_file(path: str) -> str:
    """Hex sha256 of a file, read in bounded chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_digest(path: str) -> None:
    """Record ``<path>.sha256`` for a just-written artifact (best effort).

    A failure here never fails the save: the artifact itself is already
    on disk and the next load simply falls back to the legacy policy.
    """
    try:
        with open(path + DIGEST_SUFFIX, "w", encoding="ascii") as fh:
            fh.write(sha256_file(path) + "\n")
    except OSError:  # pragma: no cover - digest is best effort
        log.warning("could not write digest sidecar for %s",
                    os.path.basename(path))


def digest_ok(path: str) -> bool:
    """Verify an artifact against its sidecar before it is loaded.

    ``False`` means "do not load" (the sidecar exists and disagrees, or
    cannot be read).  ``True`` covers a verified match and the legacy case
    of no sidecar at all, which is logged so operators can see unverified
    state.
    """
    sidecar = path + DIGEST_SUFFIX
    if not os.path.isfile(sidecar):
        log.info("no digest sidecar for %s - loading unverified legacy "
                 "state", os.path.basename(path))
        return True
    try:
        with open(sidecar, "r", encoding="ascii") as fh:
            recorded = fh.read().strip()
        actual = sha256_file(path)
    except OSError as exc:
        log.error("digest sidecar unreadable for %s: %s",
                  os.path.basename(path), exc)
        return False
    if recorded != actual:
        log.error("digest mismatch for %s - refusing to load corrupted "
                  "state", os.path.basename(path))
        return False
    return True
