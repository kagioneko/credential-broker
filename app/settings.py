"""Runtime settings for the Credential Broker.

These come from the *environment* (systemd EnvironmentFile / process env), never
from the credential config file. The broker's own operational secrets
(BROKER_API_TOKEN) are separate from the secrets it brokers.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class BrokerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", extra="ignore")

    # Auth token that AI agents must present on every HTTP request.
    # Required by the HTTP entrypoint (create_app refuses to start without it).
    # Not used by the MCP stdio entrypoint, where the process boundary is the
    # trust boundary.
    broker_api_token: str | None = None

    # Path to the credential mapping / policy file.
    config_path: str = "config/credentials.yaml"

    # Path to the .env file the DotEnvProvider reads (tmpfs, Vault-derived in prod).
    dotenv_path: str = ".env"

    # Optional JSONL audit sink (NekoGuard ingest point). Unset = stderr only.
    audit_log_path: str | None = None

    # Bind is fixed in main.py / systemd; kept here only for logging.
    host: str = "127.0.0.1"
    port: int = 8787


def load_settings() -> BrokerSettings:
    return BrokerSettings()  # type: ignore[call-arg]
