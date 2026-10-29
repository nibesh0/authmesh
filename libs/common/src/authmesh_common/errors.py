"""One error taxonomy shared by all services.

Services raise `AppError`. A server interceptor turns it into a gRPC status plus
trailing metadata carrying the machine-readable code; the gateway reads that
metadata back and re-raises the same `AppError`, which its exception handler maps
to an HTTP status. The upshot is that an error raised deep in the auth-service
reaches the HTTP client with its meaning intact instead of collapsing into a
generic 500.
"""

from __future__ import annotations

import json
from enum import Enum
from typing import Any

import grpc

ERROR_CODE_HEADER = "x-authmesh-error-code"
ERROR_DETAILS_HEADER = "x-authmesh-error-details"
RETRY_AFTER_HEADER = "x-authmesh-retry-after"


class ErrorCode(str, Enum):
    INVALID_ARGUMENT = "invalid_argument"
    UNAUTHENTICATED = "unauthenticated"
    INVALID_CREDENTIALS = "invalid_credentials"
    PERMISSION_DENIED = "permission_denied"
    NOT_FOUND = "not_found"
    ALREADY_EXISTS = "already_exists"
    FAILED_PRECONDITION = "failed_precondition"
    MFA_REQUIRED = "mfa_required"
    INVALID_MFA_CODE = "invalid_mfa_code"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_DISABLED = "account_disabled"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_REVOKED = "token_revoked"
    TOKEN_REUSED = "token_reused"
    RATE_LIMITED = "rate_limited"
    WEAK_PASSWORD = "weak_password"
    UNAVAILABLE = "unavailable"
    INTERNAL = "internal"


_GRPC_STATUS: dict[ErrorCode, grpc.StatusCode] = {
    ErrorCode.INVALID_ARGUMENT: grpc.StatusCode.INVALID_ARGUMENT,
    ErrorCode.UNAUTHENTICATED: grpc.StatusCode.UNAUTHENTICATED,
    ErrorCode.INVALID_CREDENTIALS: grpc.StatusCode.UNAUTHENTICATED,
    ErrorCode.PERMISSION_DENIED: grpc.StatusCode.PERMISSION_DENIED,
    ErrorCode.NOT_FOUND: grpc.StatusCode.NOT_FOUND,
    ErrorCode.ALREADY_EXISTS: grpc.StatusCode.ALREADY_EXISTS,
    ErrorCode.FAILED_PRECONDITION: grpc.StatusCode.FAILED_PRECONDITION,
    ErrorCode.MFA_REQUIRED: grpc.StatusCode.UNAUTHENTICATED,
    ErrorCode.INVALID_MFA_CODE: grpc.StatusCode.UNAUTHENTICATED,
    ErrorCode.ACCOUNT_LOCKED: grpc.StatusCode.PERMISSION_DENIED,
    ErrorCode.ACCOUNT_DISABLED: grpc.StatusCode.PERMISSION_DENIED,
    ErrorCode.TOKEN_EXPIRED: grpc.StatusCode.UNAUTHENTICATED,
    ErrorCode.TOKEN_REVOKED: grpc.StatusCode.UNAUTHENTICATED,
    ErrorCode.TOKEN_REUSED: grpc.StatusCode.UNAUTHENTICATED,
    ErrorCode.RATE_LIMITED: grpc.StatusCode.RESOURCE_EXHAUSTED,
    ErrorCode.WEAK_PASSWORD: grpc.StatusCode.INVALID_ARGUMENT,
    ErrorCode.UNAVAILABLE: grpc.StatusCode.UNAVAILABLE,
    ErrorCode.INTERNAL: grpc.StatusCode.INTERNAL,
}

_HTTP_STATUS: dict[ErrorCode, int] = {
    ErrorCode.INVALID_ARGUMENT: 400,
    ErrorCode.WEAK_PASSWORD: 422,
    ErrorCode.UNAUTHENTICATED: 401,
    ErrorCode.INVALID_CREDENTIALS: 401,
    ErrorCode.MFA_REQUIRED: 401,
    ErrorCode.INVALID_MFA_CODE: 401,
    ErrorCode.TOKEN_EXPIRED: 401,
    ErrorCode.TOKEN_REVOKED: 401,
    ErrorCode.TOKEN_REUSED: 401,
    ErrorCode.PERMISSION_DENIED: 403,
    ErrorCode.ACCOUNT_LOCKED: 423,
    ErrorCode.ACCOUNT_DISABLED: 403,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.ALREADY_EXISTS: 409,
    ErrorCode.FAILED_PRECONDITION: 409,
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.UNAVAILABLE: 503,
    ErrorCode.INTERNAL: 500,
}

# Statuses that arrive as raw gRPC errors (channel problems, deadlines, or a
# service that failed before our interceptor could annotate the response).
_GRPC_FALLBACK: dict[grpc.StatusCode, ErrorCode] = {
    grpc.StatusCode.INVALID_ARGUMENT: ErrorCode.INVALID_ARGUMENT,
    grpc.StatusCode.UNAUTHENTICATED: ErrorCode.UNAUTHENTICATED,
    grpc.StatusCode.PERMISSION_DENIED: ErrorCode.PERMISSION_DENIED,
    grpc.StatusCode.NOT_FOUND: ErrorCode.NOT_FOUND,
    grpc.StatusCode.ALREADY_EXISTS: ErrorCode.ALREADY_EXISTS,
    grpc.StatusCode.FAILED_PRECONDITION: ErrorCode.FAILED_PRECONDITION,
    grpc.StatusCode.RESOURCE_EXHAUSTED: ErrorCode.RATE_LIMITED,
    grpc.StatusCode.UNAVAILABLE: ErrorCode.UNAVAILABLE,
    grpc.StatusCode.DEADLINE_EXCEEDED: ErrorCode.UNAVAILABLE,
}


class AppError(Exception):
    """An error with a stable code that survives the gRPC and HTTP boundaries."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        details: dict[str, Any] | None = None,
        retry_after: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}
        self.retry_after = retry_after

    @property
    def grpc_status(self) -> grpc.StatusCode:
        return _GRPC_STATUS.get(self.code, grpc.StatusCode.INTERNAL)

    @property
    def http_status(self) -> int:
        return _HTTP_STATUS.get(self.code, 500)

    def trailing_metadata(self) -> list[tuple[str, str]]:
        metadata = [(ERROR_CODE_HEADER, self.code.value)]
        if self.details:
            metadata.append((ERROR_DETAILS_HEADER, json.dumps(self.details, default=str)))
        if self.retry_after is not None:
            metadata.append((RETRY_AFTER_HEADER, str(self.retry_after)))
        return metadata

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code.value, "message": self.message}
        if self.details:
            payload["details"] = self.details
        if self.retry_after is not None:
            payload["retry_after"] = self.retry_after
        return payload

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"AppError(code={self.code.value!r}, message={self.message!r})"


# Convenience constructors for the cases raised most often.


def invalid_argument(message: str, **details: Any) -> AppError:
    return AppError(ErrorCode.INVALID_ARGUMENT, message, details=details or None)


def not_found(message: str, **details: Any) -> AppError:
    return AppError(ErrorCode.NOT_FOUND, message, details=details or None)


def already_exists(message: str, **details: Any) -> AppError:
    return AppError(ErrorCode.ALREADY_EXISTS, message, details=details or None)


def unauthenticated(
    message: str = "authentication required",
    code: ErrorCode = ErrorCode.UNAUTHENTICATED,
    **details: Any,
) -> AppError:
    return AppError(code, message, details=details or None)


def rate_limited(message: str, retry_after: int, **details: Any) -> AppError:
    return AppError(
        ErrorCode.RATE_LIMITED, message, details=details or None, retry_after=retry_after
    )


def from_rpc_error(exc: grpc.aio.AioRpcError) -> AppError:
    """Rebuild the original `AppError` from a failed gRPC call."""
    code: ErrorCode | None = None
    details: dict[str, Any] = {}
    retry_after: int | None = None

    for key, value in exc.trailing_metadata() or ():
        key_lower = key.lower()
        if key_lower == ERROR_CODE_HEADER:
            try:
                code = ErrorCode(value)
            except ValueError:
                code = None
        elif key_lower == ERROR_DETAILS_HEADER:
            try:
                parsed = json.loads(value)
                if isinstance(parsed, dict):
                    details = parsed
            except (TypeError, ValueError):
                pass
        elif key_lower == RETRY_AFTER_HEADER:
            try:
                retry_after = int(value)
            except (TypeError, ValueError):
                pass

    if code is None:
        code = _GRPC_FALLBACK.get(exc.code(), ErrorCode.INTERNAL)

    message = exc.details() or code.value.replace("_", " ")
    if code is ErrorCode.INTERNAL:
        # Never leak an upstream stack trace or internal detail string outward.
        message = "internal error"
        details = {}

    return AppError(code, message, details=details or None, retry_after=retry_after)
