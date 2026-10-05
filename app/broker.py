"""CredentialBroker — orchestrates issue / execute / revoke / capabilities."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable

from app.actions.registry import ActionRegistry
from app.errors import (
    ActionNotAllowed,
    CredentialProviderError,
    ExpiredHandle,
    InvalidParameter,
    ProviderError,
    RateLimited,
    UnknownCredential,
)
from app.models.api import (
    CapabilitiesResponse,
    CapabilityItem,
    CredentialResponse,
    ExecuteResponse,
    RevokeResponse,
)
from app.models.config import BrokerConfig
from app.models.credential import TemporaryCredential
from app.policy import PolicyEngine
from app.providers.base import ProviderLookupError, SecretProvider
from app.security.audit import AuditLogger, handle_fingerprint
from app.security.redaction import SecretRegistry
from app.security.sanitizer import enforce_caps, redact_literals, scrub
from app.store import CredentialStore

_ERROR_FOR_CODE = {
    "ACTION_NOT_ALLOWED": ActionNotAllowed,
    "INVALID_PARAMETER": InvalidParameter,
}


class CredentialBroker:
    def __init__(
        self,
        *,
        config: BrokerConfig,
        providers: dict[str, SecretProvider],
        store: CredentialStore,
        policy: PolicyEngine,
        registry: ActionRegistry,
        audit: AuditLogger,
        secret_registry: SecretRegistry,
        limiter,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config
        self._providers = providers
        self._store = store
        self._policy = policy
        self._registry = registry
        self._audit = audit
        self._secret_registry = secret_registry
        self._limiter = limiter
        self._clock = clock

    # ------------------------------------------------------------------ #
    def issue(self, credential_id: str, client_id: str) -> CredentialResponse:
        # Rate-limit BEFORE the config lookup so a flood of unknown ids cannot
        # bypass the limiter (and cannot spam the audit log / anomaly monitor).
        if not self._limiter.check("request"):
            self._audit.emit(
                "rate_limited",
                reason="rate_limit",
                client_id=client_id,
            )
            raise RateLimited()

        cfg = self._config.credentials.get(credential_id)
        if cfg is None:
            self._audit.emit(
                "policy_denied",
                credential_id=credential_id,
                reason="unknown",
                client_id=client_id,
            )
            raise UnknownCredential()

        provider = self._providers.get(cfg.provider)
        if provider is None:
            raise CredentialProviderError()
        try:
            secret = provider.get_secret(cfg.secret_name)
        except ProviderLookupError:
            self._audit.emit("provider_error", credential_id=credential_id, reason="provider")
            raise CredentialProviderError() from None

        handle = "cred_" + secrets.token_urlsafe(24)
        ttl = min(cfg.ttl, self._config.max_ttl)
        now_wall = time.time()
        cred = TemporaryCredential(
            handle=handle,
            credential_id=credential_id,
            connector=cfg.connector,
            secret=secret,
            allowed_actions=tuple(cfg.allowed_actions),
            created_at=now_wall,
            expires_at_mono=self._clock() + ttl,
            client_id=client_id,
        )
        self._store.put(cred)
        self._secret_registry.register(secret)
        self._audit.emit(
            "credential_issued",
            credential_id=credential_id,
            handle_sha256=handle_fingerprint(handle),
            client_id=client_id,
            expires_at=_iso(now_wall + ttl),
        )
        return CredentialResponse(handle=handle, expires_in=ttl)

    # ------------------------------------------------------------------ #
    async def execute(
        self, handle: str, action: str, parameters: dict, client_id: str
    ) -> ExecuteResponse:
        if not self._limiter.check("execute"):
            self._audit.emit("rate_limited", reason="rate_limit", client_id=client_id)
            raise RateLimited()

        cred = self._store.get(handle)
        if cred is None:
            self._audit.emit(
                "action_executed",
                handle_sha256=handle_fingerprint(handle),
                action=action,
                result="denied",
                reason="ttl",
                client_id=client_id,
            )
            raise ExpiredHandle()

        decision = self._policy.check(cred, action, parameters)
        if not decision.allowed:
            self._audit.emit(
                "policy_denied",
                credential_id=cred.credential_id,
                handle_sha256=handle_fingerprint(handle),
                action=action,
                result="denied",
                reason="policy",
                client_id=client_id,
            )
            raise _ERROR_FOR_CODE.get(decision.error_code, ActionNotAllowed)()

        executor = self._registry.get(cred.connector)
        if executor is None:
            raise ActionNotAllowed()

        secret = cred.secret  # fetched before the await; local ref deleted after
        # Keep an independent registry ref for the whole in-flight window so the
        # log backstop still covers this secret even if the handle is revoked
        # (and its store-derived ref dropped) mid-request.
        self._secret_registry.register(secret)
        try:
            result = await executor.run(decision.spec, decision.params, secret=secret)
        except ProviderError:
            self._audit.emit(
                "provider_error",
                credential_id=cred.credential_id,
                handle_sha256=handle_fingerprint(handle),
                action=action,
                result="error",
                reason="provider",
                client_id=client_id,
            )
            raise
        finally:
            self._secret_registry.deregister(secret)
            del secret

        known_secrets = {cred.secret, *self._secret_registry.snapshot()}
        # Redact the raw upstream body BEFORE the action sanitiser runs: sanitisers
        # may truncate strings, and a secret cut at the boundary would no longer
        # match either the patterns or the literal guard.
        raw = redact_literals(scrub(result.body), known_secrets)
        data = decision.spec.sanitize(raw)
        data = scrub(data)
        # Authoritative guard: strip any verbatim secret value regardless of format.
        data = redact_literals(data, known_secrets)
        data = enforce_caps(
            data,
            max_bytes=self._config.max_response_bytes,
            max_items=self._config.max_response_items,
        )
        self._audit.emit(
            "action_executed",
            credential_id=cred.credential_id,
            handle_sha256=handle_fingerprint(handle),
            action=action,
            result="success",
            upstream_status=result.upstream_status,
            duration_ms=result.duration_ms,
            client_id=client_id,
        )
        return ExecuteResponse(status="success", data=data)

    # ------------------------------------------------------------------ #
    def revoke(self, handle: str) -> RevokeResponse:
        cred = self._store.pop(handle)
        if cred is not None:
            self._secret_registry.deregister(cred.secret)
            self._audit.emit(
                "credential_revoked",
                credential_id=cred.credential_id,
                handle_sha256=handle_fingerprint(handle),
                reason="revoked",
            )
        return RevokeResponse(status="revoked")

    # ------------------------------------------------------------------ #
    def capabilities(self) -> CapabilitiesResponse:
        items = [
            CapabilityItem(
                credential_id=cid,
                description=cfg.description,
                allowed_actions=list(cfg.allowed_actions),
            )
            for cid, cfg in self._config.credentials.items()
        ]
        return CapabilitiesResponse(credentials=items)


def _iso(epoch: float) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(epoch, tz=UTC).isoformat()
