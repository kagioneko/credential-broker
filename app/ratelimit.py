"""Minimal in-process sliding-window rate limiter (per action kind)."""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable


class SlidingWindowLimiter:
    def __init__(
        self,
        limits: dict[str, int],
        *,
        window_sec: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limits = limits
        self._window = window_sec
        self._clock = clock
        self._hits: dict[str, deque[float]] = {k: deque() for k in limits}

    def check(self, key: str) -> bool:
        """Return True if allowed, False if the window is exhausted. Records the hit."""
        limit = self._limits.get(key, 0)
        if limit <= 0:
            return True  # 0 or unknown -> disabled
        now = self._clock()
        q = self._hits.setdefault(key, deque())
        cutoff = now - self._window
        while q and q[0] <= cutoff:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True
