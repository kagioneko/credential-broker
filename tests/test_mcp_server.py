from __future__ import annotations

import json
from contextlib import asynccontextmanager

from mcp.shared.memory import create_connected_server_and_client_session

from tests.conftest import DOTENV_SECRET, REAL_LOOKING_TOKEN


def _payload(result) -> dict:
    sc = getattr(result, "structuredContent", None)
    if isinstance(sc, dict):
        return sc.get("result", sc)
    return json.loads(result.content[0].text)


@asynccontextmanager
async def _client():
    # Enter/exit in the caller's task (avoids anyio cancel-scope task mismatch).
    from app.mcp_server import mcp

    async with create_connected_server_and_client_session(mcp._mcp_server) as c:
        yield c


async def _call(c, name, args):
    return _payload(await c.call_tool(name, args))


async def test_lists_four_tools(env):
    async with _client() as c:
        tools = await c.list_tools()
    assert {t.name for t in tools.tools} == {
        "list_capabilities",
        "request_credential",
        "execute",
        "revoke",
    }


async def test_capabilities_has_no_secret_fields(env):
    async with _client() as c:
        data = await _call(c, "list_capabilities", {})
    assert data["credentials"][0]["credential_id"] == "github_reader"
    text = json.dumps(data)
    for leak in ("secret_name", "GITHUB_TOKEN", "dotenv", "provider"):
        assert leak not in text


async def test_request_returns_handle_only(env):
    async with _client() as c:
        data = await _call(c, "request_credential", {"credential_id": "github_reader"})
    assert set(data) == {"handle", "expires_in"}
    assert data["handle"].startswith("cred_")
    assert DOTENV_SECRET not in json.dumps(data)


async def test_unknown_credential_returns_error(env):
    async with _client() as c:
        data = await _call(c, "request_credential", {"credential_id": "OPENAI_API_KEY"})
    assert data == {"error": "UNKNOWN_CREDENTIAL"}


async def test_execute_and_revoke_roundtrip(env, gh):
    async with _client() as c:
        h = (await _call(c, "request_credential", {"credential_id": "github_reader"}))["handle"]

        data = await _call(c, "execute", {"credential_handle": h, "action": "list_repositories"})
        assert data["status"] == "success"
        blob = json.dumps(data)
        assert REAL_LOOKING_TOKEN not in blob
        assert DOTENV_SECRET not in blob

        denied = await _call(
            c,
            "execute",
            {"credential_handle": h, "action": "delete_repository", "parameters": {}},
        )
        assert denied == {"error": "ACTION_NOT_ALLOWED"}

        assert await _call(c, "revoke", {"credential_handle": h}) == {"status": "revoked"}

        gone = await _call(c, "execute", {"credential_handle": h, "action": "list_repositories"})
        assert gone == {"error": "EXPIRED_HANDLE"}
