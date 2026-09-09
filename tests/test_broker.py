from __future__ import annotations

from tests.conftest import DOTENV_SECRET, REAL_LOOKING_TOKEN, issue_handle


async def test_request_returns_handle_only(client):
    """TEST-001: no secret value in the credential-request response."""
    r = await client.post("/credentials/request", json={"credential_id": "github_reader"})
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"handle", "expires_in"}
    assert body["handle"].startswith("cred_")
    assert body["expires_in"] == 300
    assert DOTENV_SECRET not in r.text
    assert "ghp_" not in r.text


async def test_missing_broker_token_401(app):
    import httpx

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.post("/credentials/request", json={"credential_id": "github_reader"})
    assert r.status_code == 401


async def test_wrong_broker_token_401(client):
    client.headers["Authorization"] = "Bearer nope"
    r = await client.post("/credentials/request", json={"credential_id": "github_reader"})
    assert r.status_code == 401


async def test_revoke_then_execute_fails(client, gh):
    """TEST-003."""
    handle = await issue_handle(client)
    r = await client.post("/credentials/revoke", json={"credential_handle": handle})
    assert r.status_code == 200
    assert r.json() == {"status": "revoked"}

    r = await client.post(
        "/execute", json={"credential_handle": handle, "action": "list_repositories"}
    )
    assert r.status_code == 410
    assert r.json() == {"error": "EXPIRED_HANDLE"}


async def test_revoke_is_idempotent(client):
    r = await client.post(
        "/credentials/revoke", json={"credential_handle": "cred_doesnotexist"}
    )
    assert r.status_code == 200
    assert r.json() == {"status": "revoked"}


async def test_execute_list_repositories_ok(client, gh):
    handle = await issue_handle(client)
    r = await client.post(
        "/execute", json={"credential_handle": handle, "action": "list_repositories"}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "success"
    repo = body["data"][0]
    assert repo["full_name"] == "example-org/demo"
    # allowlist dropped these
    assert "owner" not in repo
    assert "permissions" not in repo
    # planted secret masked
    assert REAL_LOOKING_TOKEN not in r.text
    assert "***REDACTED***" in repo["description"]


async def test_execute_unknown_handle_is_expired(client):
    r = await client.post(
        "/execute",
        json={"credential_handle": "cred_bogus", "action": "list_repositories"},
    )
    assert r.status_code == 410
