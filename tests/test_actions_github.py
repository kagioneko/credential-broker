from __future__ import annotations

import httpx
import pytest

from tests.conftest import DOTENV_SECRET, REAL_LOOKING_TOKEN, issue_handle


@pytest.mark.parametrize("secret", [REAL_LOOKING_TOKEN, DOTENV_SECRET], ids=["pattern", "literal"])
async def test_body_preview_never_leaks_a_secret_cut_at_the_truncation_boundary(client, respx_mock, secret):
    # Place the secret so the 2000-char cut lands in its middle.
    respx_mock.get("https://api.github.com/repos/example-org/demo/issues/8").mock(
        return_value=httpx.Response(
            200,
            json={
                "number": 8,
                "title": "boundary",
                "state": "open",
                "html_url": "https://github.com/example-org/demo/issues/8",
                "user": {"login": "someone"},
                "labels": [],
                "body": "x" * 1979 + " " + secret + " tail",
            },
        )
    )
    handle = await issue_handle(client)
    r = await client.post(
        "/execute",
        json={
            "credential_handle": handle,
            "action": "get_issue",
            "parameters": {"owner": "example-org", "repo": "demo", "number": 8},
        },
    )
    assert r.status_code == 200
    assert len(r.json()["data"]["body_preview"]) <= 2000
    assert secret[:12] not in r.text


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
