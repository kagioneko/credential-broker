"""SecretProvider interface — abstracts over the underlying Secret Source."""

from __future__ import annotations

from abc import ABC, abstractmethod


class ProviderLookupError(RuntimeError):
    """Secret could not be resolved. Never carries the secret value or path detail."""


class SecretProvider(ABC):
    name: str

    @abstractmethod
    def get_secret(self, secret_name: str) -> str:
        """Return the secret value for ``secret_name`` or raise ProviderLookupError.

        Implementations MUST NOT log the value and MUST NOT include it in exceptions.
        """
        raise NotImplementedError
