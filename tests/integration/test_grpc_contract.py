"""Contract-level checks against the running gRPC services.

These bypass the gateway and talk to auth-service/user-service directly, which is
the only way to verify the things Kubernetes and other services rely on:

* grpc.health.v1 answers both the liveness and the readiness service names, since
  the Deployment probes dial exactly those.
* server reflection is registered, so `grpcurl` works against a live pod.
* errors arrive with the machine-readable trailer that lets a caller reconstruct
  the original `AppError`.
"""

from __future__ import annotations

import grpc
import pytest
from grpc_health.v1 import health_pb2, health_pb2_grpc

from authmesh.auth.v1 import auth_pb2, auth_pb2_grpc
from authmesh.user.v1 import user_pb2, user_pb2_grpc
from authmesh_common.errors import ERROR_CODE_HEADER, ErrorCode, from_rpc_error
from authmesh_common.health import LIVENESS_SERVICE, READINESS_SERVICE

from .conftest import AUTH_TARGET, USER_TARGET

pytestmark = [pytest.mark.integration]

TIMEOUT = 5.0


async def channel_for(target: str):
    channel = grpc.aio.insecure_channel(target)
    try:
        await channel.channel_ready()
    except Exception:  # noqa: BLE001 - reported as a skip below
        await channel.close()
        pytest.skip(f"{target} is not reachable")
    return channel


@pytest.mark.parametrize("target", [AUTH_TARGET, USER_TARGET])
async def test_health_liveness_and_readiness(target: str) -> None:
    channel = await channel_for(target)
    try:
        stub = health_pb2_grpc.HealthStub(channel)

        liveness = await stub.Check(
            health_pb2.HealthCheckRequest(service=LIVENESS_SERVICE), timeout=TIMEOUT
        )
        assert liveness.status == health_pb2.HealthCheckResponse.SERVING

        readiness = await stub.Check(
            health_pb2.HealthCheckRequest(service=READINESS_SERVICE), timeout=TIMEOUT
        )
        assert readiness.status == health_pb2.HealthCheckResponse.SERVING
    finally:
        await channel.close()


@pytest.mark.parametrize("target", [AUTH_TARGET, USER_TARGET])
async def test_unknown_health_service_is_not_found(target: str) -> None:
    """A typo in the probe's `service` field must fail loudly rather than report
    SERVING for something that does not exist."""
    channel = await channel_for(target)
    try:
        stub = health_pb2_grpc.HealthStub(channel)
        with pytest.raises(grpc.aio.AioRpcError) as exc_info:
            await stub.Check(
                health_pb2.HealthCheckRequest(service="not-a-real-service"), timeout=TIMEOUT
            )
        assert exc_info.value.code() is grpc.StatusCode.NOT_FOUND
    finally:
        await channel.close()


@pytest.mark.parametrize(
    ("target", "expected_service"),
    [
        (AUTH_TARGET, "authmesh.auth.v1.AuthService"),
        (USER_TARGET, "authmesh.user.v1.UserService"),
    ],
)
async def test_server_reflection_lists_the_service(target: str, expected_service: str) -> None:
    from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc

    channel = await channel_for(target)
    try:
        stub = reflection_pb2_grpc.ServerReflectionStub(channel)

        async def requests():
            yield reflection_pb2.ServerReflectionRequest(list_services="")

        services: list[str] = []
        async for response in stub.ServerReflectionInfo(requests(), timeout=TIMEOUT):
            services.extend(item.name for item in response.list_services_response.service)
            break

        assert expected_service in services
        assert "grpc.health.v1.Health" in services
    finally:
        await channel.close()


async def test_introspect_reports_garbage_tokens_as_inactive() -> None:
    """Introspection is on the hot path for every authenticated request, so an
    invalid token is a normal result and must not be an error."""
    channel = await channel_for(AUTH_TARGET)
    try:
        stub = auth_pb2_grpc.AuthServiceStub(channel)
        response = await stub.Introspect(
            auth_pb2.IntrospectRequest(access_token="not.a.jwt"), timeout=TIMEOUT
        )
        assert response.active is False
        assert response.inactive_reason
        assert not response.user_id
    finally:
        await channel.close()


async def test_error_trailers_allow_the_caller_to_recover_the_code() -> None:
    channel = await channel_for(AUTH_TARGET)
    try:
        stub = auth_pb2_grpc.AuthServiceStub(channel)
        with pytest.raises(grpc.aio.AioRpcError) as exc_info:
            await stub.Register(
                auth_pb2.RegisterRequest(email="not-an-email", password="x"),
                timeout=TIMEOUT,
            )

        error = exc_info.value
        trailers = {key.lower(): value for key, value in (error.trailing_metadata() or ())}
        assert ERROR_CODE_HEADER in trailers

        rebuilt = from_rpc_error(error)
        assert rebuilt.code is ErrorCode.INVALID_ARGUMENT
        assert rebuilt.http_status == 400
    finally:
        await channel.close()


async def test_validation_errors_are_not_reported_as_internal() -> None:
    """Regression guard: `context.abort()` raises AbortError internally, and an
    interceptor that treats it as a crash turns every rejection into INTERNAL."""
    channel = await channel_for(AUTH_TARGET)
    try:
        stub = auth_pb2_grpc.AuthServiceStub(channel)
        with pytest.raises(grpc.aio.AioRpcError) as exc_info:
            await stub.GetProfile(auth_pb2.GetProfileRequest(user_id=""), timeout=TIMEOUT)
        assert exc_info.value.code() is grpc.StatusCode.INVALID_ARGUMENT
    finally:
        await channel.close()


async def test_missing_user_is_not_found_not_internal() -> None:
    channel = await channel_for(USER_TARGET)
    try:
        stub = user_pb2_grpc.UserServiceStub(channel)
        with pytest.raises(grpc.aio.AioRpcError) as exc_info:
            await stub.GetUser(
                user_pb2.GetUserRequest(id="00000000000000000000000000000000"),
                timeout=TIMEOUT,
            )
        assert exc_info.value.code() is grpc.StatusCode.NOT_FOUND
        assert from_rpc_error(exc_info.value).code is ErrorCode.NOT_FOUND
    finally:
        await channel.close()


async def test_request_id_is_echoed_in_trailers() -> None:
    """The gateway sends x-request-id; the server returns it so a client can
    correlate its own logs with the server's."""
    channel = await channel_for(AUTH_TARGET)
    try:
        stub = auth_pb2_grpc.AuthServiceStub(channel)
        call = stub.Introspect(
            auth_pb2.IntrospectRequest(access_token="x"),
            timeout=TIMEOUT,
            metadata=(("x-request-id", "itest-correlation-id"),),
        )
        await call
        trailers = {key.lower(): value for key, value in (await call.trailing_metadata() or ())}
        assert trailers.get("x-request-id") == "itest-correlation-id"
    finally:
        await channel.close()


async def test_user_service_rejects_a_request_without_a_selector() -> None:
    channel = await channel_for(USER_TARGET)
    try:
        stub = user_pb2_grpc.UserServiceStub(channel)
        with pytest.raises(grpc.aio.AioRpcError) as exc_info:
            await stub.GetUser(user_pb2.GetUserRequest(), timeout=TIMEOUT)
        assert exc_info.value.code() is grpc.StatusCode.INVALID_ARGUMENT
    finally:
        await channel.close()


async def test_audit_events_are_recorded_and_queryable() -> None:
    """The audit trail is written by the auth-service on every state change; this
    verifies the storage path directly."""
    import uuid

    channel = await channel_for(USER_TARGET)
    try:
        stub = user_pb2_grpc.UserServiceStub(channel)
        user_id = f"itest-{uuid.uuid4().hex}"

        await stub.RecordAuditEvent(
            user_pb2.AuditEvent(
                id=uuid.uuid4().hex,
                action="itest.event",
                user_id=user_id,
                email="itest@example.com",
                success=True,
                ip="10.1.2.3",
                reason="integration test",
                metadata={"key": "value"},
            ),
            timeout=TIMEOUT,
        )

        listed = await stub.ListAuditEvents(
            user_pb2.ListAuditEventsRequest(user_id=user_id, page_size=10), timeout=TIMEOUT
        )
        assert len(listed.events) == 1
        event = listed.events[0]
        assert event.action == "itest.event"
        assert event.ip == "10.1.2.3"
        assert event.metadata["key"] == "value"
        assert event.created_at
    finally:
        await channel.close()
