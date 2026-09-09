"""MCP stdio entrypoint for the Credential Broker.

Exposes the same four operations as the HTTP API as MCP tools. The AI client
(Claude Code, Codex, ...) sees only ``credential_id`` / ``action`` /
``parameters`` — there is no field in which a secret value could be typed, and
results are the broker's sanitised output.

Trust model: an MCP stdio server is spawned by its client; the process boundary
is the auth boundary, so there is no bearer token here (unlike the HTTP entry).
Each client gets its own process and its own in-memory handle store.

Run:  python -m app.mcp_server      (stdio; configured as an MCP server command)
"""

from __future__ import annotations

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.fastmcp import Context, FastMCP
from pydantic import ValidationError

from app.assembly import BrokerRuntime, broker_context
from app.config_loader import load_config
from app.errors import BrokerError
from app.models.api import CredentialRequest, ExecuteRequest, RevokeRequest
from app.settings import load_settings

_CLIENT_ID = "mcp"


class _BadInput(Exception):
    pass


def _validate(model, **kwargs):
    """Reuse the HTTP pydantic models so MCP shares the same length/format limits."""
    try:
        return model.model_validate(kwargs)
    except ValidationError:
        raise _BadInput from None


@asynccontextmanager
async def _lifespan(_server: FastMCP) -> AsyncIterator[BrokerRuntime]:
    settings = load_settings()
    config = load_config(settings.config_path)
    async with broker_context(settings, config) as rt:
        logging.getLogger("broker").info("credential-broker (mcp) ready")
        yield rt


mcp = FastMCP("credential-broker", lifespan=_lifespan)


def _rt(ctx: Context) -> BrokerRuntime:
    return ctx.request_context.lifespan_context


@mcp.tool()
async def list_capabilities(ctx: Context) -> dict:
    """List the credential IDs this broker can broker, with their allowed actions.

    Never returns provider names, secret names, or any secret material.
    """
    return _rt(ctx).broker.capabilities().model_dump()


@mcp.tool()
async def request_credential(credential_id: str, ctx: Context) -> dict:
    """Request a short-lived handle for a credential_id (see list_capabilities).

    Returns {"handle", "expires_in"} — never the secret itself. On failure
    returns {"error": "<CODE>"}.
    """
    try:
        body = _validate(CredentialRequest, credential_id=credential_id)
        return _rt(ctx).broker.issue(body.credential_id, _CLIENT_ID).model_dump()
    except _BadInput:
        return {"error": "INVALID_PARAMETER"}
    except BrokerError as exc:
        return {"error": exc.error_code}


@mcp.tool()
async def execute(
    credential_handle: str,
    action: str,
    ctx: Context,
    parameters: dict | None = None,
) -> dict:
    """Run an allowed action using a handle. The broker calls the upstream API;
    you get back only the sanitised result. On failure returns {"error": "<CODE>"}.
    """
    try:
        body = _validate(
            ExecuteRequest,
            credential_handle=credential_handle,
            action=action,
            parameters=parameters or {},
        )
        resp = await _rt(ctx).broker.execute(
            body.credential_handle, body.action, body.parameters, _CLIENT_ID
        )
        return resp.model_dump()
    except _BadInput:
        return {"error": "INVALID_PARAMETER"}
    except BrokerError as exc:
        return {"error": exc.error_code}


@mcp.tool()
async def revoke(credential_handle: str, ctx: Context) -> dict:
    """Destroy a handle now (before its TTL). Idempotent."""
    try:
        body = _validate(RevokeRequest, credential_handle=credential_handle)
    except _BadInput:
        return {"error": "INVALID_PARAMETER"}
    return _rt(ctx).broker.revoke(body.credential_handle).model_dump()


def main() -> None:
    # stdout is the JSON-RPC channel; everything else must go to stderr.
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    mcp.run()


if __name__ == "__main__":
    main()
