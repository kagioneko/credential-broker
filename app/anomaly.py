"""In-process anomaly monitor.

The broker routes every operation through the AuditLogger, so this watches that
event stream and, when a suspicious pattern crosses a threshold, produces an
``anomaly_suspected`` descriptor. That descriptor is written back into the audit
stream (and thus the audit log file), where NekoGuard picks it up.

This does not block anything — the allowlist, TTL and rate limiter already do.
It is a detection signal.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from collections.abc import Callable

from app.models.config import AnomalyConfig

# pattern name -> (predicate on (event, fields), AnomalyThresholds attr)
_PATTERNS = {
    "credential_enumeration": (
        lambda e, f: e == "policy_denied" and f.get("reason") == "unknown",
        "enumeration",
    ),
    "denied_action_streak": (
        lambda e, f: e == "policy_denied" and f.get("reason") == "policy",
        "denied_streak",
    ),
    "expired_handle_replay": (
        lambda e, f: e == "action_executed"
        and f.get("result") == "denied"
        and f.get("reason") == "ttl",
        "expired_replay",
    ),
    "rate_limit_hits": (
        lambda e, f: e == "rate_limited",
        "rate_limit_hits",
    ),
}


class AnomalyMonitor:
    def __init__(
        self, config: AnomalyConfig, *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._cfg = config
        self._clock = clock
        # pattern -> client_id -> deque[(ts, key)]. Hard cap per (pattern, client)
        # so a flood in one window cannot grow memory unbounded.
        self._hits: dict[str, dict[str, deque]] = defaultdict(
            lambda: defaultdict(lambda: deque(maxlen=10_000))
        )
        # (pattern, client_id) -> last emit ts
        self._last_emit: dict[tuple[str, str], float] = {}

    def observe(self, event: str, fields: dict) -> list[dict]:
        if not self._cfg.enabled:
            return []
        client = str(fields.get("client_id") or "unknown")
        now = self._clock()
        window = self._cfg.window_sec
        out: list[dict] = []

        for pattern, (matches, thresh_attr) in _PATTERNS.items():
            if not matches(event, fields):
                continue
            threshold = getattr(self._cfg.thresholds, thresh_attr)
            q = self._hits[pattern][client]
            # distinct-key for enumeration (distinct credential_ids), else event count
            key = fields.get("credential_id") if pattern == "credential_enumeration" else None
            q.append((now, key))
            cutoff = now - window
            while q and q[0][0] < cutoff:
                q.popleft()

            if pattern == "credential_enumeration":
                count = len({k for _, k in q if k is not None})
            else:
                count = len(q)

            if count < threshold:
                continue
            last = self._last_emit.get((pattern, client), 0.0)
            if now - last < self._cfg.cooldown_sec:
                continue
            self._last_emit[(pattern, client)] = now
            out.append({"pattern": pattern, "count": count, "client_id": client})

        return out
