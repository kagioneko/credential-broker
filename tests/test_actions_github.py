from __future__ import annotations

import httpx
import pytest

from tests.conftest import issue_handle


async def test_get_issue_body_preview_is_capped_and_masked(client, gh):
    handle = await issue_handle(client)
    r = await client.post(
        "/execute",
        json={
            "credential_handle": handle,
            "action": "get_issue",
            "parameters": {"owner": "example-org", "repo": "demo", "number": 7},
        },
    )
    assert r.status_code == 200
    issue = r.json()["data"]
    assert len(issue["body_preview"]) <= 2000
    assert "ghp_" not in issue["body_preview"]


async def test_upstream_4xx_maps_to_provider_error(client, respx_mock):
    respx_mock.get("https://api.github.com/user/repos").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"})
    )
    handle = await issue_handle(client)
    r = await client.post(
        "/execute", json={"credential_handle": handle, "action": "list_repositories"}
    )
    assert r.status_code == 502
    assert r.json() == {"error": "PROVIDER_ERROR"}
    assert "Not Found" not in r.text


async def test_bearer_header_sent_upstream(client, respx_mock):
    route = respx_mock.get("https://api.github.com/user/repos").mock(
        return_value=httpx.Response(200, json=[])
    )
    handle = await issue_handle(client)
    await client.post(
        "/execute", json={"credential_handle": handle, "action": "list_repositories"}
    )
    sent = route.calls.last.request
    from tests.conftest import DOTENV_SECRET

    assert sent.headers["authorization"] == f"Bearer {DOTENV_SECRET}"
    assert sent.headers["x-github-api-version"] == "2022-11-28"


async def test_list_response_item_cap(client, respx_mock):
    big = [
        {"id": i, "name": f"r{i}", "full_name": f"o/r{i}", "private": False,
         "html_url": "u", "description": "d", "default_branch": "main"}
        for i in range(500)
    ]
    respx_mock.get("https://api.github.com/user/repos").mock(
        return_value=httpx.Response(200, json=big)
    )
    handle = await issue_handle(client)
    r = await client.post(
        "/execute", json={"credential_handle": handle, "action": "list_repositories"}
    )
    assert r.status_code == 200
    data = r.json()["data"]
    assert data["truncated"] is True
    assert len(data["items"]) == 200


@pytest.mark.parametrize("action", ["list_repositories", "get_repository", "list_issues", "get_issue"])
async def test_all_allowed_actions_execute(client, gh, action):
    handle = await issue_handle(client)
    params = {}
    if action != "list_repositories":
        params = {"owner": "example-org", "repo": "demo"}
    if action == "get_issue":
        params["number"] = 7
    r = await client.post(
        "/execute",
        json={"credential_handle": handle, "action": action, "parameters": params},
    )
    assert r.status_code == 200, r.text
