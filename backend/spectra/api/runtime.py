"""Shared API runtime: config + the single engine instance.

Routers import the engine from here (rather than from ``api.app``) so the
app module can assemble the routers without a circular import.  Tests keep
importing ``spectra.api.app`` - it re-exports both names.
"""

from __future__ import annotations

from ..config import get_config
from ..pipeline import SpectraEngine

cfg = get_config()
engine = SpectraEngine(config=cfg)

# Rebuild the correlation graph from persisted history so cross-domain
# queries work immediately after an API restart (and after each capture,
# which resets the live view before re-hydrating it).
engine.hydrate_graph()
