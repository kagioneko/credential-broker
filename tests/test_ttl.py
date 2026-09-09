from __future__ import annotations

from app.cleanup import _sweep_once
from app.security.audit import AuditLogger
from app.security.redaction import SecretRegistry
from tests.conftest import issue_handle


async def test_expired_after_ttl(client, gh, fake_clock):
    """TEST-002: handle unusable at t+301s."""
    handle = await issue_handle(client)

    # still valid just before expiry
    fake_clock.advance(299)
    r = await client.post(
        "/execute", json={"credential_handle": handle, "action": "list_repositories"}
    )
    assert r.status_code == 200

    fake_clock.advance(2)  # now t+301
    r = await client.post(
        "/execute", json={"credential_handle": handle, "action": "list_repositories"}
    )
    assert r.status_code == 410
    assert r.json() == {"error": "EXPIRED_HANDLE"}


async def test_cleanup_worker_removes_expired(app, client, fake_clock):
    await issue_handle(client)
    store = app.state.store
    assert len(store) == 1

    fake_clock.advance(301)
    removed = _sweep_once(store, AuditLogger(), SecretRegistry())
    assert removed == 1
    assert len(store) == 0


async def test_expired_handle_not_reusable_even_if_clock_rewinds(client, gh, fake_clock):
    handle = await issue_handle(client)
    fake_clock.advance(400)
    r = await client.post(
        "/execute", json={"credential_handle": handle, "action": "list_repositories"}
    )
    assert r.status_code == 410
    # handle purged; rewinding does not bring it back
    fake_clock.t = 1000.0
    r = await client.post(
        "/execute", json={"credential_handle": handle, "action": "list_repositories"}
    )
    assert r.status_code == 410
