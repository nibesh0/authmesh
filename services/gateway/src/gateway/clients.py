"""gRPC client to the auth-service.

Holds one channel for the process lifetime: gRPC multiplexes concurrent calls
over a single HTTP/2 connection, so creating a channel per request would add a
TCP+HTTP/2 handshake to every login for no benefit.
"""

from __future__ import annotations

import grpc

from authmesh.auth.v1 import auth_pb2, auth_pb2_grpc
from authmesh_common.errors import AppError, ErrorCode, from_rpc_error
from authmesh_common.grpc_client import channel_is_ready, create_channel
from authmesh_common.logging import get_logger

from .settings import GatewaySettings

log = get_logger(__name__)


class AuthClient:
    def __init__(self, settings: GatewaySettings) -> None:
        self._settings = settings
        self._channel: grpc.aio.Channel | None = None
        self._stub: auth_pb2_grpc.AuthServiceStub | None = None

    async def connect(self) -> None:
        self._channel = create_channel(self._settings.auth_service_target)
        self._stub = auth_pb2_grpc.AuthServiceStub(self._channel)
        log.info(
            "auth-service client created",
            extra={"target": self._settings.auth_service_target},
        )

    async def close(self) -> None:
        if self._channel is not None:
            await self._channel.close(grace=1.0)
            self._channel = None
            self._stub = None

    async def ping(self) -> bool:
        if self._channel is None:
            return False
        return await channel_is_ready(self._channel, timeout=2.0)

    @property
    def _timeout(self) -> float:
        return self._settings.auth_service_timeout_seconds

    async def call(self, method_name: str, request):  # noqa: ANN001, ANN201
        """Invoke `method_name` and normalise failures into `AppError`."""
        if self._stub is None:
            raise AppError(ErrorCode.UNAVAILABLE, "auth service client not initialised")
        method = getattr(self._stub, method_name)
        try:
            return await method(request, timeout=self._timeout)
        except grpc.aio.AioRpcError as exc:
            raise from_rpc_error(exc) from exc

    # Thin wrappers keep call sites readable and give the type checker something
    # to hold on to.

    async def register(self, request: auth_pb2.RegisterRequest):  # noqa: ANN201
        return await self.call("Register", request)

    async def login(self, request: auth_pb2.LoginRequest):  # noqa: ANN201
        return await self.call("Login", request)

    async def verify_mfa(self, request: auth_pb2.VerifyMfaRequest):  # noqa: ANN201
        return await self.call("VerifyMfa", request)

    async def refresh(self, request: auth_pb2.RefreshRequest):  # noqa: ANN201
        return await self.call("Refresh", request)

    async def logout(self, request: auth_pb2.LogoutRequest):  # noqa: ANN201
        return await self.call("Logout", request)

    async def logout_all(self, request: auth_pb2.LogoutAllRequest):  # noqa: ANN201
        return await self.call("LogoutAll", request)

    async def introspect(self, request: auth_pb2.IntrospectRequest):  # noqa: ANN201
        return await self.call("Introspect", request)

    async def get_profile(self, request: auth_pb2.GetProfileRequest):  # noqa: ANN201
        return await self.call("GetProfile", request)

    async def change_password(self, request: auth_pb2.ChangePasswordRequest):  # noqa: ANN201
        return await self.call("ChangePassword", request)

    async def enroll_totp(self, request: auth_pb2.EnrollTotpRequest):  # noqa: ANN201
        return await self.call("EnrollTotp", request)

    async def activate_totp(self, request: auth_pb2.ActivateTotpRequest):  # noqa: ANN201
        return await self.call("ActivateTotp", request)

    async def disable_totp(self, request: auth_pb2.DisableTotpRequest):  # noqa: ANN201
        return await self.call("DisableTotp", request)

    async def list_sessions(self, request: auth_pb2.ListSessionsRequest):  # noqa: ANN201
        return await self.call("ListSessions", request)

    async def revoke_session(self, request: auth_pb2.RevokeSessionRequest):  # noqa: ANN201
        return await self.call("RevokeSession", request)
