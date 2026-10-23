"""The broker's upstream HTTP client must not expose its credentialed TLS calls
to ambient-environment interception: no proxy hijack (HTTP(S)_PROXY / ALL_PROXY)
and no TLS session-key logging (SSLKEYLOGFILE).

asyncio_mode is "auto" (see pyproject.toml), so the async test runs inside a
managed event loop; the client is created and closed within it.
"""

from __future__ import annotations

import ssl

import httpx

from app.assembly import _build_tls_context, _build_upstream_client


def test_tls_context_verifies_and_never_logs_keys(monkeypatch, tmp_path) -> None:
    # Regression (Codex 2026-10-23): ssl.create_default_context() reads
    # SSLKEYLOGFILE regardless of trust_env. Point it at a path under a missing
    # directory: if the context build consumed the var it would raise
    # FileNotFoundError. The broker's context must ignore it entirely.
    monkeypatch.setenv("SSLKEYLOGFILE", str(tmp_path / "missing" / "keys.log"))

    ctx = _build_tls_context()  # must not raise

    assert ctx.keylog_filename is None  # TLS session keys are never logged
    assert ctx.verify_mode is ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


async def test_upstream_client_ignores_ambient_proxy_env(monkeypatch, tmp_path) -> None:
    # With trust_env left at its default httpx WOULD honour this proxy; the
    # broker's client must stay immune even with the env vars set, and must build
    # cleanly with an SSLKEYLOGFILE trap present.
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.invalid:8080")
    monkeypatch.setenv("ALL_PROXY", "socks5://attacker.invalid:1080")
    monkeypatch.setenv("SSLKEYLOGFILE", str(tmp_path / "missing" / "keys.log"))

    client = _build_upstream_client()
    try:
        assert client.trust_env is False
        assert isinstance(client, httpx.AsyncClient)
    finally:
        await client.aclose()
