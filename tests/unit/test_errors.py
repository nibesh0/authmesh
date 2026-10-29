"""The error taxonomy and its survival across the gRPC boundary.

`from_rpc_error` is what lets the gateway return "423 account_locked" instead of
"500 internal error" when the auth-service rejects a login. These tests build real
`AioRpcError` instances the way grpc would.
"""

from __future__ import annotations

import json

import grpc
import pytest

from authmesh_common.errors import (
    ERROR_CODE_HEADER,
    ERROR_DETAILS_HEADER,
    RETRY_AFTER_HEADER,
    AppError,
    ErrorCode,
    from_rpc_error,
)


def make_rpc_error(
    code: grpc.StatusCode, details: str = "", trailers: list[tuple[str, str]] | None = None
) -> grpc.aio.AioRpcError:
    return grpc.aio.AioRpcError(
        code=code,
        initial_metadata=grpc.aio.Metadata(),
        trailing_metadata=grpc.aio.Metadata(*(trailers or [])),
        details=details,
    )


def test_status_mapping_is_consistent() -> None:
    error = AppError(ErrorCode.ACCOUNT_LOCKED, "locked", retry_after=900)
    assert error.grpc_status is grpc.StatusCode.PERMISSION_DENIED
    assert error.http_status == 423


@pytest.mark.parametrize(
    ("code", "expected_http"),
    [
        (ErrorCode.INVALID_ARGUMENT, 400),
        (ErrorCode.INVALID_CREDENTIALS, 401),
        (ErrorCode.TOKEN_EXPIRED, 401),
        (ErrorCode.TOKEN_REUSED, 401),
        (ErrorCode.PERMISSION_DENIED, 403),
        (ErrorCode.ACCOUNT_DISABLED, 403),
        (ErrorCode.NOT_FOUND, 404),
        (ErrorCode.ALREADY_EXISTS, 409),
        (ErrorCode.ACCOUNT_LOCKED, 423),
        (ErrorCode.WEAK_PASSWORD, 422),
        (ErrorCode.RATE_LIMITED, 429),
        (ErrorCode.UNAVAILABLE, 503),
        (ErrorCode.INTERNAL, 500),
    ],
)
def test_http_status_per_code(code: ErrorCode, expected_http: int) -> None:
    assert AppError(code, "x").http_status == expected_http


def test_trailing_metadata_carries_code_details_and_retry_after() -> None:
    error = AppError(
        ErrorCode.RATE_LIMITED,
        "slow down",
        details={"scope": "login_ip"},
        retry_after=30,
    )
    trailers = dict(error.trailing_metadata())

    assert trailers[ERROR_CODE_HEADER] == "rate_limited"
    assert json.loads(trailers[ERROR_DETAILS_HEADER]) == {"scope": "login_ip"}
    assert trailers[RETRY_AFTER_HEADER] == "30"


def test_round_trip_through_rpc_error() -> None:
    original = AppError(
        ErrorCode.ACCOUNT_LOCKED,
        "too many failed attempts",
        details={"unlock_in_seconds": 900},
        retry_after=900,
    )
    rebuilt = from_rpc_error(
        make_rpc_error(
            original.grpc_status, original.message, list(original.trailing_metadata())
        )
    )

    assert rebuilt.code is ErrorCode.ACCOUNT_LOCKED
    assert rebuilt.message == "too many failed attempts"
    assert rebuilt.details == {"unlock_in_seconds": 900}
    assert rebuilt.retry_after == 900
    assert rebuilt.http_status == 423


def test_unannotated_status_falls_back_to_a_sensible_code() -> None:
    """A failure that never reached our interceptor (channel down, deadline) still
    has to produce something better than a 500."""
    assert (
        from_rpc_error(make_rpc_error(grpc.StatusCode.UNAVAILABLE, "connect failed")).code
        is ErrorCode.UNAVAILABLE
    )
    assert (
        from_rpc_error(make_rpc_error(grpc.StatusCode.DEADLINE_EXCEEDED, "timeout")).code
        is ErrorCode.UNAVAILABLE
    )
    assert (
        from_rpc_error(make_rpc_error(grpc.StatusCode.NOT_FOUND, "missing")).code
        is ErrorCode.NOT_FOUND
    )


def test_internal_errors_do_not_leak_upstream_detail() -> None:
    """An INTERNAL from a downstream service may contain a stack trace or a
    connection string; the client gets none of it."""
    rebuilt = from_rpc_error(
        make_rpc_error(
            grpc.StatusCode.INTERNAL,
            "psycopg2.OperationalError: password authentication failed for user 'svc'",
            [(ERROR_CODE_HEADER, "internal"), (ERROR_DETAILS_HEADER, '{"host":"db-1"}')],
        )
    )

    assert rebuilt.code is ErrorCode.INTERNAL
    assert rebuilt.message == "internal error"
    assert rebuilt.details == {}


def test_unknown_error_code_in_metadata_is_ignored() -> None:
    rebuilt = from_rpc_error(
        make_rpc_error(
            grpc.StatusCode.PERMISSION_DENIED,
            "nope",
            [(ERROR_CODE_HEADER, "a_code_from_a_newer_release")],
        )
    )
    assert rebuilt.code is ErrorCode.PERMISSION_DENIED


def test_malformed_details_metadata_is_ignored() -> None:
    rebuilt = from_rpc_error(
        make_rpc_error(
            grpc.StatusCode.INVALID_ARGUMENT,
            "bad",
            [(ERROR_CODE_HEADER, "invalid_argument"), (ERROR_DETAILS_HEADER, "{not json")],
        )
    )
    assert rebuilt.code is ErrorCode.INVALID_ARGUMENT
    assert rebuilt.details == {}


def test_payload_shape() -> None:
    payload = AppError(
        ErrorCode.RATE_LIMITED, "slow down", details={"scope": "x"}, retry_after=5
    ).to_payload()
    assert payload == {
        "code": "rate_limited",
        "message": "slow down",
        "details": {"scope": "x"},
        "retry_after": 5,
    }
