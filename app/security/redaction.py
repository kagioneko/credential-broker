"""Log redaction: defence-in-depth so a secret value never reaches a log sink.

Primary defence is still "do not pass secrets to the logger" (the AuditLogger
cannot carry free text at all). This module is the backstop.

The backstop works at the ``LogRecord`` factory level, not as a logger filter:
a filter attached to a logger only runs for records emitted directly on that
logger, so records propagated from arbitrary child loggers (or loggers with
``propagate=False`` such as uvicorn's) would bypass it. Rewriting the record at
creation time covers every logger and every handler in the process.
"""

from __future__ import annotations

import logging

from app.security.sanitizer import mask_secrets

_REDACTED = "***REDACTED***"


class SecretRegistry:
    """The set of currently-live secret values, reference counted."""

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}

    def register(self, secret: str) -> None:
        if not secret:
            return
        self._counts[secret] = self._counts.get(secret, 0) + 1

    def deregister(self, secret: str) -> None:
        if secret in self._counts:
            self._counts[secret] -= 1
            if self._counts[secret] <= 0:
                del self._counts[secret]

    def clear(self) -> None:
        self._counts.clear()

    def snapshot(self) -> frozenset[str]:
        return frozenset(self._counts)


def _redact_text(text: str, registry: SecretRegistry) -> str:
    for secret in registry.snapshot():
        if secret and secret in text:
            text = text.replace(secret, _REDACTED)
    return mask_secrets(text)


def _redact_exc_text(record: logging.LogRecord, registry: SecretRegistry) -> None:
    """Pre-render the traceback and redact it.

    Formatters render ``exc_info`` lazily and reuse ``exc_text`` when it is
    already set, so filling it here keeps exception messages (which may embed a
    secret) from bypassing msg/args redaction.
    """
    if record.exc_info and not record.exc_text:
        try:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        except Exception:
            return
    if record.exc_text:
        record.exc_text = _redact_text(record.exc_text, registry)


class RedactionFilter(logging.Filter):
    """Kept for targeted use (e.g. attaching to a specific test handler)."""

    def __init__(self, registry: SecretRegistry) -> None:
        super().__init__()
        self._registry = registry

    def filter(self, record: logging.LogRecord) -> bool:
        _redact_exc_text(record, self._registry)
        try:
            msg = record.getMessage()
        except Exception:
            msg = str(record.msg)
        red = _redact_text(msg, self._registry)
        if red != msg:
            record.msg = red
            record.args = ()
        return True


_ORIGINAL_FACTORY = logging.getLogRecordFactory()


def install(registry: SecretRegistry) -> None:
    """Install a process-wide LogRecord factory that redacts every record.

    Always rebuilds from the original factory, so repeated create_app() calls in
    tests replace the wrapper instead of stacking factories.
    """

    def factory(*args, **kwargs):
        record = _ORIGINAL_FACTORY(*args, **kwargs)
        _redact_exc_text(record, registry)
        try:
            msg = record.getMessage()
        except Exception:
            return record
        red = _redact_text(msg, registry)
        if red != msg:
            record.msg = red
            record.args = ()
        return record

    logging.setLogRecordFactory(factory)
