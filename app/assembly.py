"""Transport-agnostic assembly of the broker and its background worker.

Both entrypoints use this: ``app/main.py`` (HTTP / FastAPI) and
``app/mcp_server.py`` (MCP stdio).
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx

from app.actions.github import GitHubReadExecutor
from app.actions.registry import ActionRegistry
from app.anomaly import AnomalyMonitor
from app.broker import CredentialBroker
from app.cleanup import cleanup_loop
from app.models.config import BrokerConfig
from app.policy import PolicyEngine
from app.providers.dotenv import DotEnvProvider
from app.ratelimit import SlidingWindowLimiter
from app.security.audit import AuditLogger
from app.security.redaction import SecretRegistry
from app.security.redaction import install as install_redaction
from app.settings import BrokerSettings
from app.store import CredentialStore


@dataclass
class BrokerRuntime:
    broker: CredentialBroker
    store: CredentialStore
    secret_registry: SecretRegistry
    audit: AuditLogger


@asynccontextmanager
async def broker_context(
    settings: BrokerSettings,
    config: BrokerConfig,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> AsyncIterator[BrokerRuntime]:
    secret_registry = SecretRegistry()
    install_redaction(secret_registry)

    providers = {"dotenv": DotEnvProvider(settings.dotenv_path)}
    store = CredentialStore(clock=clock)
    store.set_on_evict(lambda c: secret_registry.deregister(c.secret))

    registry = ActionRegistry()
    monitor = AnomalyMonitor(config.anomaly, clock=clock)
    audit = AuditLogger(sink_path=settings.audit_log_path, monitor=monitor)
    limiter = SlidingWindowLimiter(
        {
            "request": config.rate_limit.request_per_min,
            "execute": config.rate_limit.execute_per_min,
        },
        clock=clock,
    )

    http_client = httpx.AsyncClient(
        limits=httpx.Limits(max_connections=10, max_keepalive_connections=5)
    )
    registry.register(GitHubReadExecutor(http_client))

    broker = CredentialBroker(
        config=config,
        providers=providers,
        store=store,
        policy=PolicyEngine(registry),
        registry=registry,
        audit=audit,
        secret_registry=secret_registry,
        limiter=limiter,
        clock=clock,
    )

    cleanup_task = asyncio.create_task(
        cleanup_loop(
            store,
            interval=config.cleanup_interval_sec,
            audit=audit,
            secret_registry=secret_registry,
        )
    )
    try:
        yield BrokerRuntime(broker, store, secret_registry, audit)
    finally:
        cleanup_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await cleanup_task
        store.clear()
        secret_registry.clear()
        await http_client.aclose()
