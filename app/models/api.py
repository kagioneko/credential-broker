"""Request / response models for the HTTP API."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

_ID_PATTERN = r"^[a-z0-9_]+$"
_HANDLE_PATTERN = r"^cred_[A-Za-z0-9_-]+$"


class CredentialRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    credential_id: str = Field(min_length=1, max_length=64)


class CredentialResponse(BaseModel):
    handle: str
    expires_in: int


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    credential_handle: str = Field(min_length=8, max_length=80, pattern=_HANDLE_PATTERN)
    action: str = Field(min_length=1, max_length=64, pattern=_ID_PATTERN)
    parameters: dict = Field(default_factory=dict)


class ExecuteResponse(BaseModel):
    status: str
    data: dict | list


class RevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    credential_handle: str = Field(min_length=8, max_length=80, pattern=_HANDLE_PATTERN)


class RevokeResponse(BaseModel):
    status: str


class CapabilityItem(BaseModel):
    credential_id: str
    description: str
    allowed_actions: list[str]


class CapabilitiesResponse(BaseModel):
    credentials: list[CapabilityItem]


class ErrorResponse(BaseModel):
    error: str
