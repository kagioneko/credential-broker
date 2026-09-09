"""Response sanitisation.

Two independent layers:
 1. allowlist extraction  -> done per-action in actions/github.py
 2. pattern masking       -> mask_secrets() below, applied to free-text fields
Plus size / item caps enforced by the caller.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from app.errors import ProviderError

# Ordered list of (compiled regex, replacement).
_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    re.compile(r"\bgh[ousr]_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{8,}\b", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b"),  # JWT
]

_REDACTED = "***REDACTED***"


def mask_secrets(text: str) -> str:
    if not text:
        return text
    for pat in _PATTERNS:
        text = pat.sub(_REDACTED, text)
    return text


def scrub(value):
    """Recursively mask secret-looking substrings in str leaves of a JSON value."""
    if isinstance(value, str):
        return mask_secrets(value)
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if isinstance(value, dict):
        return {k: scrub(v) for k, v in value.items()}
    return value


def redact_literals(value, literals: Iterable[str]):
    """Recursively replace exact occurrences of known secret values with a marker.

    This does not depend on the shape of the secret (unknown / legacy / future
    token formats), so it is the authoritative guard, not mask_secrets().
    """
    lits = [s for s in dict.fromkeys(literals) if s and len(s) >= 8]
    if not lits:
        return value

    def _walk(x):
        if isinstance(x, str):
            for s in lits:
                if s in x:
                    x = x.replace(s, _REDACTED)
            return x
        if isinstance(x, list):
            return [_walk(v) for v in x]
        if isinstance(x, dict):
            return {k: _walk(v) for k, v in x.items()}
        return x

    return _walk(value)


def enforce_caps(data, *, max_bytes: int, max_items: int):
    """Cap serialised size and list length. Raises ProviderError if oversize."""
    import json

    truncated = False
    if isinstance(data, list) and len(data) > max_items:
        data = data[:max_items]
        truncated = True

    try:
        size = len(json.dumps(data, ensure_ascii=False))
    except (TypeError, ValueError):
        raise ProviderError() from None
    if size > max_bytes:
        raise ProviderError()

    if truncated and isinstance(data, list):
        return {"items": data, "truncated": True}
    return data
