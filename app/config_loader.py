"""Load and validate the credential mapping / policy file.

All validation failures raise at startup (fail-closed): a running broker never
holds an inconsistent config.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from app.actions.registry import connector_action_names, known_connector
from app.models.config import BrokerConfig


class ConfigError(RuntimeError):
    pass


def load_config(path: str | Path) -> BrokerConfig:
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"config file not found: {p}")

    raw = yaml.safe_load(p.read_text()) or {}
    try:
        config = BrokerConfig.model_validate(raw)
    except Exception as exc:  # pydantic ValidationError
        raise ConfigError(f"invalid config: {exc}") from exc

    for cid, cred in config.credentials.items():
        if not known_connector(cred.connector):
            raise ConfigError(f"{cid}: unknown connector {cred.connector!r}")
        known_actions = connector_action_names(cred.connector)
        unknown = set(cred.allowed_actions) - known_actions
        if unknown:
            raise ConfigError(f"{cid}: unknown actions for {cred.connector}: {sorted(unknown)}")
        if cred.ttl > config.max_ttl:
            raise ConfigError(f"{cid}: ttl {cred.ttl} exceeds max_ttl {config.max_ttl}")
        if cred.ttl <= 0:
            raise ConfigError(f"{cid}: ttl must be positive")

    return config
