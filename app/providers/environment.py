"""EnvironmentProvider — v0.2 placeholder. Not registered in v0.1."""

from __future__ import annotations

import os

from app.providers.base import ProviderLookupError, SecretProvider


class EnvironmentProvider(SecretProvider):
    name = "environment"

    def get_secret(self, secret_name: str) -> str:
        try:
            return os.environ[secret_name]
        except KeyError:
            raise ProviderLookupError("secret not found") from None
