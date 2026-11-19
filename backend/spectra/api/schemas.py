"""Shared base for response models.

``extra="allow"`` is the safety net: a response model may type the fields we
know, but it never drops one the service adds (the contract fixtures are the
proof; see ``frontend/contract/README.md``).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class Out(BaseModel):
    model_config = ConfigDict(extra="allow")
