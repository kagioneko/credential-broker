from __future__ import annotations

import pytest

from app.config_loader import ConfigError, load_config

BASE = """
credentials:
  github_reader:
    provider: {provider}
    secret_name: GITHUB_TOKEN
    connector: {connector}
    description: d
    ttl: {ttl}
    allowed_actions:
      - {action}
"""


def _write(tmp_path, **kw):
    kw.setdefault("provider", "dotenv")
    kw.setdefault("connector", "github")
    kw.setdefault("ttl", 300)
    kw.setdefault("action", "list_repositories")
    p = tmp_path / "c.yaml"
    p.write_text(BASE.format(**kw))
    return p


def test_valid_config_loads(tmp_path):
    cfg = load_config(_write(tmp_path))
    assert "github_reader" in cfg.credentials


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.yaml")


def test_unknown_provider(tmp_path):
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, provider="vault"))


def test_unknown_connector(tmp_path):
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, connector="gitlab"))


def test_unknown_action(tmp_path):
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, action="delete_everything"))


def test_ttl_exceeds_max(tmp_path):
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, ttl=99999))


def test_bad_credential_id(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(
        "credentials:\n"
        "  'Bad Id':\n"
        "    provider: dotenv\n"
        "    secret_name: X\n"
        "    connector: github\n"
        "    description: d\n"
        "    allowed_actions: [list_repositories]\n"
    )
    with pytest.raises(ConfigError):
        load_config(p)
