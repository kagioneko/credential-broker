"""Connector registry: connector name -> ActionExecutor.

The set of known connectors and their action names is available *before* an
executor instance exists, so config_loader can validate the YAML at startup.
"""

from __future__ import annotations

from app.actions.base import ActionExecutor
from app.actions.github import SPECS as GITHUB_SPECS

# Static metadata (no I/O clients needed) for startup validation.
_CONNECTOR_ACTIONS: dict[str, frozenset[str]] = {
    "github": frozenset(GITHUB_SPECS),
}


def known_connector(name: str) -> bool:
    return name in _CONNECTOR_ACTIONS


def connector_action_names(name: str) -> frozenset[str]:
    return _CONNECTOR_ACTIONS.get(name, frozenset())


class ActionRegistry:
    """Holds live executor instances (built at app startup with shared http client)."""

    def __init__(self) -> None:
        self._executors: dict[str, ActionExecutor] = {}

    def register(self, executor: ActionExecutor) -> None:
        self._executors[executor.connector] = executor

    def get(self, connector: str) -> ActionExecutor | None:
        return self._executors.get(connector)
