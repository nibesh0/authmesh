"""Logging redaction, request correlation and metric labelling.

The redaction test matters as much as any auth test: a log line containing a
password or a bearer token turns the log pipeline into a credential store.
"""

from __future__ import annotations

import json
import logging

import pytest

from authmesh_common import metrics
from authmesh_common.context import (
    REQUEST_ID_HEADER,
    get_request_id,
    outbound_metadata,
    request_context,
)
from authmesh_common.logging import REDACTED, JsonFormatter
from authmesh_common.timeutil import epoch_seconds, from_rfc3339, to_rfc3339, utcnow


def render(record_kwargs: dict, *, message: str = "test") -> dict:
    formatter = JsonFormatter(service="svc", environment="test", version="1.2.3")
    record = logging.LogRecord(
        name="test.logger",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=None,
    )
    for key, value in record_kwargs.items():
        setattr(record, key, value)
    return json.loads(formatter.format(record))


def test_json_log_has_the_expected_envelope() -> None:
    payload = render({}, message="hello")
    assert payload["msg"] == "hello"
    assert payload["level"] == "INFO"
    assert payload["service"] == "svc"
    assert payload["env"] == "test"
    assert payload["version"] == "1.2.3"
    assert payload["logger"] == "test.logger"
    assert payload["ts"].endswith("+00:00")


def test_extra_fields_are_included() -> None:
    payload = render({"grpc_method": "Login", "duration_ms": 12.5})
    assert payload["grpc_method"] == "Login"
    assert payload["duration_ms"] == 12.5


@pytest.mark.parametrize(
    "field",
    ["password", "new_password", "access_token", "refresh_token", "mfa_token", "secret",
     "totp_secret", "authorization", "recovery_codes"],
)
def test_sensitive_fields_are_redacted(field: str) -> None:
    payload = render({field: "super-secret-value"})
    assert payload[field] == REDACTED
    assert "super-secret-value" not in json.dumps(payload)


def test_redaction_reaches_into_nested_structures() -> None:
    payload = render({"body": {"email": "a@example.com", "password": "hunter2"}})
    assert payload["body"]["password"] == REDACTED
    assert payload["body"]["email"] == "a@example.com"


def test_redaction_reaches_into_lists() -> None:
    payload = render({"batch": [{"password": "one"}, {"password": "two"}]})
    assert [entry["password"] for entry in payload["batch"]] == [REDACTED, REDACTED]


def test_request_id_is_attached_when_bound() -> None:
    with request_context("abc123") as rid:
        assert rid == "abc123"
        payload = render({})
    assert payload["request_id"] == "abc123"
    # ...and gone once the context exits.
    assert "request_id" not in render({})


def test_unserializable_values_do_not_break_logging() -> None:
    class Opaque:
        def __repr__(self) -> str:
            return "<opaque>"

    payload = render({"thing": Opaque()})
    assert payload["thing"] == "<opaque>"


def test_exception_info_is_captured() -> None:
    formatter = JsonFormatter(service="svc", environment="test", version="1")
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        record = logging.LogRecord(
            "l", logging.ERROR, __file__, 1, "failed", (), sys.exc_info()
        )
    payload = json.loads(formatter.format(record))
    assert payload["error"]["type"] == "ValueError"
    assert payload["error"]["message"] == "boom"
    assert "ValueError: boom" in payload["error"]["stack"]


# -- context propagation ----------------------------------------------------


def test_request_context_generates_an_id_when_absent() -> None:
    with request_context() as rid:
        assert len(rid) == 32
        assert get_request_id() == rid


def test_nested_contexts_restore_the_outer_id() -> None:
    with request_context("outer"):
        with request_context("inner"):
            assert get_request_id() == "inner"
        assert get_request_id() == "outer"


def test_outbound_metadata_carries_the_request_id() -> None:
    with request_context("req-1", "user-1"):
        metadata = dict(outbound_metadata())
    assert metadata[REQUEST_ID_HEADER] == "req-1"
    assert metadata["x-user-id"] == "user-1"


def test_outbound_metadata_is_empty_without_context() -> None:
    assert outbound_metadata() == []


# -- metrics labelling ------------------------------------------------------


@pytest.mark.parametrize(
    ("full_method", "expected"),
    [
        ("/authmesh.auth.v1.AuthService/Login", ("AuthService", "Login")),
        ("/authmesh.user.v1.UserService/GetUser", ("UserService", "GetUser")),
        ("/grpc.health.v1.Health/Check", ("Health", "Check")),
        ("no-slashes", ("unknown", "no-slashes")),
    ],
)
def test_method_labels_stay_low_cardinality(full_method: str, expected: tuple) -> None:
    assert metrics.split_method(full_method) == expected


def test_metrics_render_includes_registered_series() -> None:
    metrics.set_build_info("svc", "1.0.0", "test")
    body = metrics.render().decode()
    assert "authmesh_build_info" in body


# -- time helpers -----------------------------------------------------------


def test_rfc3339_round_trip() -> None:
    now = utcnow()
    parsed = from_rfc3339(to_rfc3339(now))
    assert parsed is not None
    # Serialization is millisecond precision.
    assert abs((parsed - now).total_seconds()) < 0.001


def test_rfc3339_handles_empty_and_invalid_input() -> None:
    assert to_rfc3339(None) == ""
    assert from_rfc3339("") is None
    assert from_rfc3339("not a timestamp") is None


def test_epoch_seconds_matches_timestamp() -> None:
    now = utcnow()
    assert epoch_seconds(now) == int(now.timestamp())
