from __future__ import annotations

from tests.conftest import issue_handle


async def test_delete_repository_denied(client, gh):
    """TEST-004."""
    handle = await issue_handle(client)
    r = await client.post(
        "/execute",
        json={
            "credential_handle": handle,
            "action": "delete_repository",
            "parameters": {"owner": "example-org", "repo": "demo"},
        },
    )
    assert r.status_code == 403
    assert r.json() == {"error": "ACTION_NOT_ALLOWED"}


async def test_unknown_action_denied(client):
    handle = await issue_handle(client)
    r = await client.post(
        "/execute",
        json={"credential_handle": handle, "action": "wat", "parameters": {}},
    )
    assert r.status_code == 403


async def test_bad_parameters_rejected(client, gh):
    handle = await issue_handle(client)
    r = await client.post(
        "/execute",
        json={
            "credential_handle": handle,
            "action": "get_repository",
            "parameters": {"owner": "example-org", "repo": "demo", "extra": "x"},
        },
    )
    assert r.status_code == 422
    assert r.json() == {"error": "INVALID_PARAMETER"}


async def test_path_traversal_in_owner_rejected(client, gh):
    handle = await issue_handle(client)
    r = await client.post(
        "/execute",
        json={
            "credential_handle": handle,
            "action": "get_repository",
            "parameters": {"owner": "../../..", "repo": "demo"},
        },
    )
    assert r.status_code == 422


async def test_per_page_out_of_range_rejected(client, gh):
    handle = await issue_handle(client)
    r = await client.post(
        "/execute",
        json={
            "credential_handle": handle,
            "action": "list_repositories",
            "parameters": {"per_page": 999},
        },
    )
    assert r.status_code == 422
