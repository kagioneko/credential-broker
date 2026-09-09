"""Background worker that evicts expired temporary credentials."""

from __future__ import annotations

import asyncio

from app.security.audit import AuditLogger, handle_fingerprint
from app.security.redaction import SecretRegistry
from app.store import CredentialStore


async def cleanup_loop(
    store: CredentialStore,
    *,
    interval: int,
    audit: AuditLogger,
    secret_registry: SecretRegistry,
) -> None:
    while True:
        await asyncio.sleep(interval)
        _sweep_once(store, audit, secret_registry)


def _sweep_once(
    store: CredentialStore, audit: AuditLogger, secret_registry: SecretRegistry
) -> int:
    removed = 0
    for handle in store.expired_handles():
        cred = store.pop(handle)
        if cred is None:
            continue
        removed += 1
        secret_registry.deregister(cred.secret)
        audit.emit(
            "credential_expired",
            credential_id=cred.credential_id,
            handle_sha256=handle_fingerprint(handle),
            reason="ttl",
        )
    return removed
