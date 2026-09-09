"""Config models — the credential mapping / policy file (server-side, fixed)."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

_ID_RE = re.compile(r"^[a-z0-9_]+$")

KNOWN_PROVIDERS = {"dotenv"}


class CredentialConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    secret_name: str
    connector: str
    description: str
    ttl: int = 300
    allowed_actions: list[str] = Field(min_length=1)

    @field_validator("provider")
    @classmethod
    def _known_provider(cls, v: str) -> str:
        if v not in KNOWN_PROVIDERS:
            raise ValueError(f"unknown provider: {v!r}")
        return v


class RateLimitConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_per_min: int = 20
    execute_per_min: int = 60


class AnomalyThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enumeration: int = 5       # distinct unknown credential_ids in window
    denied_streak: int = 5     # policy_denied (allowed-but-forbidden action) in window
    expired_replay: int = 5    # execute on expired/unknown handle in window
    rate_limit_hits: int = 3   # rate_limited events in window


class AnomalyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    window_sec: int = 60
    cooldown_sec: int = 300     # min gap between repeats of the same pattern/client
    thresholds: AnomalyThresholds = Field(default_factory=AnomalyThresholds)


class BrokerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default_ttl: int = 300
    max_ttl: int = 900
    cleanup_interval_sec: int = 10
    max_response_bytes: int = 1_048_576
    max_response_items: int = 200
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    anomaly: AnomalyConfig = Field(default_factory=AnomalyConfig)
    credentials: dict[str, CredentialConfig]

    @field_validator("credentials")
    @classmethod
    def _valid_ids(cls, v: dict[str, CredentialConfig]) -> dict[str, CredentialConfig]:
        for cid in v:
            if not _ID_RE.match(cid):
                raise ValueError(f"invalid credential_id: {cid!r}")
        return v
