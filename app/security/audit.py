"""Structured audit log.

The emit API only accepts a fixed set of keyword fields. There is no free-text
parameter, so a secret can never be threaded through it (SR-002).

Optionally mirrors every line to a rotating JSONL file (the NekoGuard ingest
point) and feeds an AnomalyMonitor, whose findings are emitted back as
``anomaly_suspected`` events.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Protocol

_LOG = logging.getLogger("audit")

_ALLOWED_FIELDS = {
    "credential_id",
    "handle_sha256",
    "action",
    "result",
    "upstream_status",
    "duration_ms",
    "client_id",
    "expires_at",
    "reason",  # short enum-like code only (e.g. "ttl", "policy")
    "pattern",  # anomaly_suspected only
    "count",  # anomaly_suspected only
}

_ALLOWED_REASONS = {"ttl", "revoked", "policy", "provider", "rate_limit", "auth", "unknown"}


class _PrivateRotatingFileHandler(RotatingFileHandler):
    """Creates every file (including post-rotation ones) as 0600, independent of umask."""

    def _open(self):
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        return open(fd, self.mode, encoding=self.encoding, errors=self.errors)


def handle_fingerprint(handle: str) -> str:
    return hashlib.sha256(handle.encode()).hexdigest()[:16]


class _Monitor(Protocol):
    def observe(self, event: str, fields: dict) -> list[dict]: ...


class AuditLogger:
    def __init__(
        self,
        logger: logging.Logger | None = None,
        *,
        sink_path: str | Path | None = None,
        monitor: _Monitor | None = None,
    ) -> None:
        self._log = logger or _LOG
        self._monitor = monitor
        if sink_path is not None:
            self._attach_sink(Path(sink_path))

    def _attach_sink(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        # audit rows carry credential_id / action / handle fingerprints — not
        # secrets, but keep them off other users regardless of umask.
        with contextlib.suppress(OSError):
            os.chmod(path.parent, 0o700)
            if path.exists():
                os.chmod(path, 0o600)
        resolved = path.resolve()
        for h in list(self._log.handlers):
            if not isinstance(h, RotatingFileHandler):
                continue
            if Path(h.baseFilename) == resolved:
                return  # already attached (repeated create_app in tests)
            self._log.removeHandler(h)  # only one audit sink at a time
            h.close()
        handler = _PrivateRotatingFileHandler(
            path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._log.addHandler(handler)
        self._log.setLevel(logging.INFO)
        self._log.propagate = True
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)

    def emit(self, event: str, **fields) -> None:
        bad = set(fields) - _ALLOWED_FIELDS
        if bad:
            raise ValueError(f"audit: disallowed fields {sorted(bad)}")
        if "reason" in fields and fields["reason"] not in _ALLOWED_REASONS:
            raise ValueError("audit: disallowed reason")
        record = {
            "ts": datetime.now(UTC).isoformat(),
            "event": event,
            **{k: v for k, v in fields.items() if v is not None},
        }
        self._log.info(json.dumps(record, ensure_ascii=False, sort_keys=True))

        if self._monitor is not None and event != "anomaly_suspected":
            try:
                found = self._monitor.observe(event, fields)
            except Exception:  # detection must never break an operation
                found = []
            for a in found:
                self.emit(
                    "anomaly_suspected",
                    pattern=a["pattern"],
                    count=a["count"],
                    client_id=a.get("client_id"),
                )
