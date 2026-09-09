"""VaultProvider — v0.2 placeholder. Not registered in v0.1.

Intended shape: read one field of a KV secret via the secret store's API,
addressed by ``secret_name``, always fetching a single field (never dumping the
whole secret). Connection details come from the environment.
"""

from __future__ import annotations

from app.providers.base import ProviderLookupError, SecretProvider


class VaultProvider(SecretProvider):
    name = "vault"

    def __init__(self, *args, **kwargs) -> None:  # noqa: D401 - placeholder
        raise NotImplementedError("VaultProvider lands in v0.2")

    def get_secret(self, secret_name: str) -> str:
        raise ProviderLookupError("not implemented")
