"""Typed client for the user-service.

Wraps the generated stub so the auth logic never touches gRPC details: NOT_FOUND
becomes `None`, every other failure becomes an `AppError` with its original code,
and audit writes are best-effort because an audit outage must not block a login.
"""

from __future__ import annotations

import uuid

import grpc

from authmesh.user.v1 import user_pb2, user_pb2_grpc
from authmesh_common.context import get_request_id
from authmesh_common.errors import AppError, ErrorCode, from_rpc_error
from authmesh_common.grpc_client import channel_is_ready, create_channel
from authmesh_common.logging import get_logger
from authmesh_common.timeutil import to_rfc3339, utcnow

from .settings import AuthServiceSettings

log = get_logger(__name__)


class UserDirectory:
    def __init__(self, settings: AuthServiceSettings) -> None:
        self._settings = settings
        self._channel: grpc.aio.Channel | None = None
        self._stub: user_pb2_grpc.UserServiceStub | None = None

    async def connect(self) -> None:
        self._channel = create_channel(self._settings.user_service_target)
        self._stub = user_pb2_grpc.UserServiceStub(self._channel)
        log.info(
            "user-service client created",
            extra={"target": self._settings.user_service_target},
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
    def stub(self) -> user_pb2_grpc.UserServiceStub:
        if self._stub is None:
            raise AppError(ErrorCode.UNAVAILABLE, "user-service client not initialised")
        return self._stub

    @property
    def _timeout(self) -> float:
        return self._settings.user_service_timeout_seconds

    # -- users -------------------------------------------------------------

    async def create_user(
        self, *, email: str, display_name: str, password_hash: str, roles: list[str]
    ) -> user_pb2.User:
        try:
            return await self.stub.CreateUser(
                user_pb2.CreateUserRequest(
                    email=email,
                    display_name=display_name,
                    password_hash=password_hash,
                    roles=roles,
                ),
                timeout=self._timeout,
            )
        except grpc.aio.AioRpcError as exc:
            raise from_rpc_error(exc) from exc

    async def get_by_email(self, email: str) -> user_pb2.User | None:
        try:
            return await self.stub.GetUser(
                user_pb2.GetUserRequest(email=email), timeout=self._timeout
            )
        except grpc.aio.AioRpcError as exc:
            if exc.code() is grpc.StatusCode.NOT_FOUND:
                return None
            raise from_rpc_error(exc) from exc

    async def get_by_id(self, user_id: str) -> user_pb2.User | None:
        try:
            return await self.stub.GetUser(
                user_pb2.GetUserRequest(id=user_id), timeout=self._timeout
            )
        except grpc.aio.AioRpcError as exc:
            if exc.code() is grpc.StatusCode.NOT_FOUND:
                return None
            raise from_rpc_error(exc) from exc

    async def require_by_id(self, user_id: str) -> user_pb2.User:
        user = await self.get_by_id(user_id)
        if user is None:
            raise AppError(ErrorCode.NOT_FOUND, "user not found")
        return user

    async def update_user(self, request: user_pb2.UpdateUserRequest) -> user_pb2.User:
        try:
            return await self.stub.UpdateUser(request, timeout=self._timeout)
        except grpc.aio.AioRpcError as exc:
            raise from_rpc_error(exc) from exc

    # -- audit -------------------------------------------------------------

    async def record_audit(
        self,
        *,
        action: str,
        user_id: str = "",
        email: str = "",
        success: bool = True,
        ip: str = "",
        user_agent: str = "",
        reason: str = "",
        metadata: dict[str, str] | None = None,
    ) -> None:
        """Best-effort audit write.

        The trail is valuable but not worth failing a login over, so failures are
        logged (and the log itself carries the same fields, which means the record
        is still recoverable from the centralized logs).
        """
        event = user_pb2.AuditEvent(
            id=uuid.uuid4().hex,
            action=action,
            user_id=user_id,
            email=email,
            success=success,
            ip=ip,
            user_agent=user_agent[:512],
            request_id=get_request_id() or "",
            reason=reason,
            created_at=to_rfc3339(utcnow()),
            metadata=metadata or {},
        )
        try:
            await self.stub.RecordAuditEvent(event, timeout=self._timeout)
        except grpc.aio.AioRpcError as exc:
            log.warning(
                "audit write failed",
                extra={
                    "audit_action": action,
                    "audit_user_id": user_id,
                    "audit_success": success,
                    "audit_reason": reason,
                    "downstream_code": exc.code().name,
                },
            )
