"""Broker error hierarchy.

Every error surfaced to a client is normalised to ``{"error": "<CODE>"}`` with a
fixed HTTP status. No messages, no stack traces, no secret material (SR-003).
"""

from __future__ import annotations


class BrokerError(Exception):
    error_code: str = "INTERNAL_ERROR"
    http_status: int = 500

    def __init__(self, error_code: str | None = None, http_status: int | None = None) -> None:
        if error_code is not None:
            self.error_code = error_code
        if http_status is not None:
            self.http_status = http_status
        super().__init__(self.error_code)


class Unauthorized(BrokerError):
    error_code = "UNAUTHORIZED"
    http_status = 401


class RateLimited(BrokerError):
    error_code = "RATE_LIMITED"
    http_status = 429


class UnknownCredential(BrokerError):
    error_code = "UNKNOWN_CREDENTIAL"
    http_status = 404


class ExpiredHandle(BrokerError):
    error_code = "EXPIRED_HANDLE"
    http_status = 410


class ActionNotAllowed(BrokerError):
    error_code = "ACTION_NOT_ALLOWED"
    http_status = 403


class InvalidParameter(BrokerError):
    error_code = "INVALID_PARAMETER"
    http_status = 422


class CredentialProviderError(BrokerError):
    error_code = "CREDENTIAL_PROVIDER_ERROR"
    http_status = 502


class ProviderError(BrokerError):
    error_code = "PROVIDER_ERROR"
    http_status = 502
