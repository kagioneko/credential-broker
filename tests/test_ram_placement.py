"""Secret files must only ever be placed on RAM-backed filesystems (tmpfs/ramfs)."""

from __future__ import annotations

import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = ROOT / "deploy" / "mcp-launch.sh"


def _fstype(path: str) -> str:
    return subprocess.run(["stat", "-f", "-c", "%T", path], capture_output=True, text=True).stdout.strip()


@pytest.fixture
def smoke(monkeypatch):
    monkeypatch.setenv("SMOKE_GITHUB_TOKEN", "unused")
    monkeypatch.setenv("SMOKE_BROKER_TOKEN", "unused")
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    sys.modules.pop("smoke_real", None)
    return importlib.import_module("smoke_real")


def test_smoke_rejects_disk_backed_dir(smoke, tmp_path):
    if _fstype(str(tmp_path)) in ("tmpfs", "ramfs"):
        pytest.skip("tmp_path is itself RAM-backed here")
    assert smoke._is_ram_dir(str(tmp_path)) is False


def test_smoke_rejects_missing_or_empty(smoke, tmp_path):
    assert smoke._is_ram_dir(None) is False
    assert smoke._is_ram_dir("") is False
    assert smoke._is_ram_dir(str(tmp_path / "does-not-exist")) is False


def test_smoke_accepts_dev_shm_when_tmpfs(smoke):
    if not os.path.isdir("/dev/shm") or _fstype("/dev/shm") != "tmpfs":
        pytest.skip("/dev/shm is not tmpfs on this host")
    assert smoke._is_ram_dir("/dev/shm") is True


def test_smoke_fails_closed_when_no_ram_dir(smoke, monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setattr(smoke, "_is_ram_dir", lambda p: False)
    with pytest.raises(SystemExit):
        smoke._private_tmp_base()


def _launcher_is_ram_dir(path: str) -> int:
    script = f'source <(sed -n "/^is_ram_dir()/,/^}}/p" "{LAUNCHER}"); is_ram_dir "$1"'
    return subprocess.run(["bash", "-c", script, "_", path], capture_output=True).returncode


def test_launcher_rejects_disk_backed_dir(tmp_path):
    if _fstype(str(tmp_path)) in ("tmpfs", "ramfs"):
        pytest.skip("tmp_path is itself RAM-backed here")
    assert _launcher_is_ram_dir(str(tmp_path)) != 0
    assert _launcher_is_ram_dir(str(tmp_path / "missing")) != 0


def test_launcher_refuses_before_fetching_secret_when_no_ram_dir(tmp_path):
    """With every candidate on disk the launcher exits 1 and never calls the secret store."""
    if _fstype(str(tmp_path)) in ("tmpfs", "ramfs"):
        pytest.skip("tmp_path is itself RAM-backed here")
    marker = tmp_path / "vault-called"
    fakebin = tmp_path / "bin"
    fakebin.mkdir()
    (fakebin / "vault").write_text(f'#!/bin/bash\ntouch "{marker}"\necho x\n')
    (fakebin / "vault").chmod(0o755)
    # Point every candidate at disk: XDG_RUNTIME_DIR=tmp_path and /dev/shm replaced.
    patched = tmp_path / "launch.sh"
    patched.write_text(LAUNCHER.read_text().replace(" /dev/shm; do", f' "{tmp_path}"; do'))
    env = dict(os.environ, PATH=f"{fakebin}:{os.environ['PATH']}", VAULT_ADDR="https://example.invalid",
               XDG_RUNTIME_DIR=str(tmp_path), CREDENTIAL_BROKER_ROOT=str(tmp_path))
    r = subprocess.run(["bash", str(patched)], env=env, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 1
    assert "refusing" in r.stderr
    assert not marker.exists()
