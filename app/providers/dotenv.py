"""DotEnvProvider — reads secrets from a .env file.

In production the .env is generated on tmpfs from Vault by systemd ExecStartPre;
this class only knows "read a path". The file is parsed once at startup.
"""

from __future__ import annotations

from pathlib import Path

from dotenv import dotenv_values

from app.providers.base import ProviderLookupError, SecretProvider


class DotEnvProvider(SecretProvider):
    name = "dotenv"

    def __init__(self, dotenv_path: str | Path) -> None:
        p = Path(dotenv_path)
        if not p.is_file():
            raise ProviderLookupError("dotenv source unavailable")
        # dotenv_values never logs; values kept in-process only.
        self._values: dict[str, str] = {
            k: v for k, v in dotenv_values(p).items() if v is not None
        }

    def get_secret(self, secret_name: str) -> str:
        try:
            return self._values[secret_name]
        except KeyError:
            raise ProviderLookupError("secret not found") from None
