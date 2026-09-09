"""FastAPI dependencies: broker-token auth + broker accessor."""

from __future__ import annotations

import secrets

from fastapi import Depends, Request

from app.broker import CredentialBroker
from app.errors import Unauthorized

_CLIENT_ID = "agent"  # v0.1: single logical client


def require_broker_token(request: Request) -> str:
    expected: str | None = request.app.state.broker_api_token
    if not expected:  # fail closed
        raise Unauthorized()
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise Unauthorized()
    if not secrets.compare_digest(token, expected):
        raise Unauthorized()
    return _CLIENT_ID


def get_broker(request: Request) -> CredentialBroker:
    return request.app.state.broker


def get_client_id(client_id: str = Depends(require_broker_token)) -> str:
    return client_id
