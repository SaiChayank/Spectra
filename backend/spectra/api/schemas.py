"""Shared base for response models.

A response model only *describes* what the service already returns; it must
never change it (the contract fixtures are the proof, see
``frontend/contract/README.md``).  So:

* ``extra="allow"``: a field the model does not name is passed through;
* declared-but-absent fields are not emitted (a key the service omits stays
  omitted instead of turning into ``null``).
"""

from __future__ import annotations

from typing import Any, Union

from pydantic import BaseModel, ConfigDict, model_serializer

#: int stays int, float stays float (a plain ``float`` field would turn 0 into 0.0)
Num = Union[int, float]


class Out(BaseModel):
    model_config = ConfigDict(extra="allow")

    @model_serializer(mode="wrap")
    def _only_what_was_set(self, handler: Any) -> Any:
        out = handler(self)
        declared = type(self).model_fields
        return {k: v for k, v in out.items()
                if k not in declared or k in self.model_fields_set}
