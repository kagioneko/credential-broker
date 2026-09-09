"""HTTP API routes. Every route requires a valid broker token."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.broker import CredentialBroker
from app.deps import get_broker, get_client_id
from app.models.api import (
    CapabilitiesResponse,
    CredentialRequest,
    CredentialResponse,
    ExecuteRequest,
    ExecuteResponse,
    RevokeRequest,
    RevokeResponse,
)

router = APIRouter()


@router.get("/capabilities", response_model=CapabilitiesResponse)
def capabilities(
    _: str = Depends(get_client_id),
    broker: CredentialBroker = Depends(get_broker),
) -> CapabilitiesResponse:
    return broker.capabilities()


@router.post("/credentials/request", response_model=CredentialResponse)
def request_credential(
    body: CredentialRequest,
    client_id: str = Depends(get_client_id),
    broker: CredentialBroker = Depends(get_broker),
) -> CredentialResponse:
    return broker.issue(body.credential_id, client_id)


@router.post("/execute", response_model=ExecuteResponse)
async def execute(
    body: ExecuteRequest,
    client_id: str = Depends(get_client_id),
    broker: CredentialBroker = Depends(get_broker),
) -> ExecuteResponse:
    return await broker.execute(
        body.credential_handle, body.action, body.parameters, client_id
    )


@router.post("/credentials/revoke", response_model=RevokeResponse)
def revoke(
    body: RevokeRequest,
    _: str = Depends(get_client_id),
    broker: CredentialBroker = Depends(get_broker),
) -> RevokeResponse:
    return broker.revoke(body.credential_handle)
