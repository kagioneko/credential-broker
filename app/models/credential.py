"""Internal model for a live temporary credential."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TemporaryCredential:
    handle: str
    credential_id: str
    connector: str
    secret: str
    allowed_actions: tuple[str, ...]
    created_at: float          # wall clock, for audit display only
    expires_at_mono: float     # time.monotonic() based, the only expiry authority
    client_id: str

    def remaining(self, now_mono: float) -> int:
        return max(0, int(self.expires_at_mono - now_mono))

    def is_expired(self, now_mono: float) -> bool:
        return now_mono >= self.expires_at_mono
