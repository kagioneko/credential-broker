"""Action framework: specs + executor interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel


@dataclass(frozen=True)
class ActionSpec:
    name: str
    method: str
    path_template: str
    param_model: type[BaseModel]
    path_fields: frozenset[str]
    query_fields: frozenset[str]
    sanitize: Callable[[Any], Any]


@dataclass
class ActionResult:
    upstream_status: int
    body: Any
    duration_ms: int


class ActionExecutor(ABC):
    connector: str
    specs: dict[str, ActionSpec]

    def get_spec(self, action: str) -> ActionSpec | None:
        return self.specs.get(action)

    def action_names(self) -> frozenset[str]:
        return frozenset(self.specs)

    @abstractmethod
    async def run(self, spec: ActionSpec, params: BaseModel, *, secret: str) -> ActionResult:
        raise NotImplementedError
