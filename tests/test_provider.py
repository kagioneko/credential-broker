from __future__ import annotations

import logging

import pytest

from app.providers.base import ProviderLookupError
from app.providers.dotenv import DotEnvProvider


def test_dotenv_reads_known_key(tmp_path):
    f = tmp_path / ".env"
    f.write_text("GITHUB_TOKEN=abc123\nOTHER=x\n")
    p = DotEnvProvider(f)
    assert p.get_secret("GITHUB_TOKEN") == "abc123"


def test_dotenv_unknown_key_raises_without_leaking(tmp_path):
    f = tmp_path / ".env"
    f.write_text("GITHUB_TOKEN=abc123\n")
    p = DotEnvProvider(f)
    with pytest.raises(ProviderLookupError) as ei:
        p.get_secret("NOPE")
    assert "abc123" not in str(ei.value)
    assert "NOPE" in str(ei.value) or "not found" in str(ei.value)


def test_dotenv_missing_file_raises(tmp_path):
    with pytest.raises(ProviderLookupError):
        DotEnvProvider(tmp_path / "absent.env")


def test_dotenv_get_secret_does_not_log_value(tmp_path, caplog):
    f = tmp_path / ".env"
    f.write_text("GITHUB_TOKEN=supersecretvalue\n")
    p = DotEnvProvider(f)
    with caplog.at_level(logging.DEBUG):
        p.get_secret("GITHUB_TOKEN")
    assert "supersecretvalue" not in caplog.text
