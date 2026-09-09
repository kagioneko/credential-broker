"""In-memory temporary credential store with monotonic-clock TTL.

Single event loop assumption: get()/pop() do not await, so no lock is needed in
v0.1. An asyncio.Lock is kept for a future multi-worker / async-provider world.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from app.models.credential import TemporaryCredential


class CredentialStore:
    def __init__(
        self,
        clock: Callable[[], float] = time.monotonic,
        on_evict: Callable[[TemporaryCredential], None] | None = None,
    ) -> None:
        self._clock = clock
        self._on_evict = on_evict
        self._data: dict[str, TemporaryCredential] = {}

    def set_on_evict(self, cb: Callable[[TemporaryCredential], None]) -> None:
        self._on_evict = cb

    def put(self, cred: TemporaryCredential) -> None:
        self._data[cred.handle] = cred

    def get(self, handle: str) -> TemporaryCredential | None:
        cred = self._data.get(handle)
        if cred is None:
            return None
        if cred.is_expired(self._clock()):
            self._data.pop(handle, None)
            if self._on_evict is not None:
                self._on_evict(cred)
            return None
        return cred

    def pop(self, handle: str) -> TemporaryCredential | None:
        return self._data.pop(handle, None)

    def expired_handles(self, now_mono: float | None = None) -> list[str]:
        now = self._clock() if now_mono is None else now_mono
        return [h for h, c in self._data.items() if c.is_expired(now)]

    def secret_in_use(self, secret: str, *, excluding: str | None = None) -> bool:
        return any(
            c.secret == secret for h, c in self._data.items() if h != excluding
        )

    def clear(self) -> None:
        self._data.clear()

    def __len__(self) -> int:
        return len(self._data)
