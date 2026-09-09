"""Policy engine: allowlist checks + parameter validation. Default deny."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, ValidationError

from app.actions.base import ActionSpec
from app.actions.registry import ActionRegistry
from app.models.credential import TemporaryCredential


@dataclass
class PolicyDecision:
    allowed: bool
    error_code: str | None = None
    spec: ActionSpec | None = None
    params: BaseModel | None = None


class PolicyEngine:
    def __init__(self, registry: ActionRegistry) -> None:
        self._registry = registry

    def check(
        self, cred: TemporaryCredential, action: str, parameters: dict
    ) -> PolicyDecision:
        if action not in cred.allowed_actions:
            return PolicyDecision(False, "ACTION_NOT_ALLOWED")

        executor = self._registry.get(cred.connector)
        if executor is None:
            return PolicyDecision(False, "ACTION_NOT_ALLOWED")

        spec = executor.get_spec(action)
        if spec is None:
            return PolicyDecision(False, "ACTION_NOT_ALLOWED")

        if not isinstance(parameters, dict):
            return PolicyDecision(False, "INVALID_PARAMETER")

        try:
            params = spec.param_model.model_validate(parameters)
        except ValidationError:
            return PolicyDecision(False, "INVALID_PARAMETER")

        return PolicyDecision(True, None, spec, params)
