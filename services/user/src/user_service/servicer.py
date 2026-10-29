"""gRPC surface of the user-service: protobuf <-> repository translation only.

Business rules live in the auth-service. This service is deliberately dumb so
that it can be reasoned about as "the database, over gRPC".
"""

from __future__ import annotations

import uuid
from typing import Any

import grpc

from authmesh.user.v1 import user_pb2, user_pb2_grpc
from authmesh_common.errors import invalid_argument
from authmesh_common.logging import get_logger
from authmesh_common.timeutil import from_rfc3339, to_rfc3339

from .repository import AuditRecord, UserRecord, UserRepository, normalize_email
from .settings import UserServiceSettings

log = get_logger(__name__)

SERVICE_FULL_NAME = user_pb2.DESCRIPTOR.services_by_name["UserService"].full_name


def _to_proto_user(record: UserRecord) -> user_pb2.User:
    return user_pb2.User(
        id=record.id,
        email=record.email,
        display_name=record.display_name,
        password_hash=record.password_hash,
        roles=record.roles,
        totp_enabled=record.totp_enabled,
        totp_secret_enc=record.totp_secret_enc or "",
        recovery_code_hashes=record.recovery_code_hashes,
        disabled=record.disabled,
        created_at=to_rfc3339(record.created_at),
        updated_at=to_rfc3339(record.updated_at),
        password_changed_at=to_rfc3339(record.password_changed_at),
    )


def _to_proto_audit(record: AuditRecord) -> user_pb2.AuditEvent:
    return user_pb2.AuditEvent(
        id=record.id,
        action=record.action,
        user_id=record.user_id,
        email=record.email,
        success=record.success,
        ip=record.ip,
        user_agent=record.user_agent,
        request_id=record.request_id,
        reason=record.reason,
        created_at=to_rfc3339(record.created_at),
        metadata=record.metadata,
    )


class UserServicer(user_pb2_grpc.UserServiceServicer):
    def __init__(self, repository: UserRepository, settings: UserServiceSettings) -> None:
        self._repo = repository
        self._settings = settings

    def _clamp_page_size(self, requested: int) -> int:
        if requested <= 0:
            return self._settings.default_page_size
        return min(requested, self._settings.max_page_size)

    async def CreateUser(  # noqa: N802
        self, request: user_pb2.CreateUserRequest, context: grpc.aio.ServicerContext
    ) -> user_pb2.User:
        email = normalize_email(request.email)
        if not email or "@" not in email:
            raise invalid_argument("a valid email is required")
        if not request.password_hash:
            raise invalid_argument("password_hash is required")

        record = await self._repo.create_user(
            user_id=uuid.uuid4().hex,
            email=email,
            display_name=request.display_name or email.split("@", 1)[0],
            password_hash=request.password_hash,
            roles=list(request.roles),
        )
        log.info("user created", extra={"created_user_id": record.id})
        return _to_proto_user(record)

    async def GetUser(  # noqa: N802
        self, request: user_pb2.GetUserRequest, context: grpc.aio.ServicerContext
    ) -> user_pb2.User:
        selector = request.WhichOneof("selector")
        if selector == "id":
            record = await self._repo.get_by_id(request.id)
        elif selector == "email":
            record = await self._repo.get_by_email(request.email)
        else:
            raise invalid_argument("either id or email must be provided")
        return _to_proto_user(record)

    async def UpdateUser(  # noqa: N802
        self, request: user_pb2.UpdateUserRequest, context: grpc.aio.ServicerContext
    ) -> user_pb2.User:
        if not request.id:
            raise invalid_argument("id is required")

        updates: dict[str, Any] = {}
        if request.HasField("display_name"):
            updates["display_name"] = request.display_name
        if request.HasField("password_hash"):
            updates["password_hash"] = request.password_hash
        if request.HasField("totp_enabled"):
            updates["totp_enabled"] = request.totp_enabled
        if request.HasField("totp_secret_enc"):
            updates["totp_secret_enc"] = request.totp_secret_enc
        if request.HasField("disabled"):
            updates["disabled"] = request.disabled
        if request.HasField("roles"):
            updates["roles"] = list(request.roles.values)
        if request.HasField("recovery_code_hashes"):
            updates["recovery_code_hashes"] = list(request.recovery_code_hashes.values)
        if request.HasField("clear_totp_secret") and request.clear_totp_secret:
            updates["$clear_totp_secret"] = True
        if (
            request.HasField("touch_password_changed_at")
            and request.touch_password_changed_at
        ):
            updates["$touch_password_changed_at"] = True

        if not updates:
            raise invalid_argument("no fields to update")

        record = await self._repo.update_user(request.id, updates)
        log.info(
            "user updated",
            extra={
                "updated_user_id": record.id,
                "fields": sorted(k for k in updates if not k.startswith("$")),
            },
        )
        return _to_proto_user(record)

    async def DeleteUser(  # noqa: N802
        self, request: user_pb2.DeleteUserRequest, context: grpc.aio.ServicerContext
    ) -> user_pb2.Empty:
        if not request.id:
            raise invalid_argument("id is required")
        await self._repo.delete_user(request.id)
        log.info("user deleted", extra={"deleted_user_id": request.id})
        return user_pb2.Empty()

    async def ListUsers(  # noqa: N802
        self, request: user_pb2.ListUsersRequest, context: grpc.aio.ServicerContext
    ) -> user_pb2.ListUsersResponse:
        records, next_token, total = await self._repo.list_users(
            page_size=self._clamp_page_size(request.page_size),
            page_token=request.page_token or None,
            email_prefix=request.email_prefix or None,
        )
        return user_pb2.ListUsersResponse(
            users=[_to_proto_user(record) for record in records],
            next_page_token=next_token or "",
            total=total,
        )

    async def RecordAuditEvent(  # noqa: N802
        self, request: user_pb2.AuditEvent, context: grpc.aio.ServicerContext
    ) -> user_pb2.Empty:
        if not request.action:
            raise invalid_argument("action is required")
        await self._repo.record_audit(
            AuditRecord(
                id=request.id or uuid.uuid4().hex,
                action=request.action,
                user_id=request.user_id,
                email=request.email,
                success=request.success,
                ip=request.ip,
                user_agent=request.user_agent,
                request_id=request.request_id,
                reason=request.reason,
                created_at=from_rfc3339(request.created_at),
                metadata=dict(request.metadata),
            )
        )
        return user_pb2.Empty()

    async def ListAuditEvents(  # noqa: N802
        self, request: user_pb2.ListAuditEventsRequest, context: grpc.aio.ServicerContext
    ) -> user_pb2.ListAuditEventsResponse:
        records, next_token = await self._repo.list_audit_events(
            user_id=request.user_id or None,
            action=request.action or None,
            page_size=self._clamp_page_size(request.page_size),
            page_token=request.page_token or None,
        )
        return user_pb2.ListAuditEventsResponse(
            events=[_to_proto_audit(record) for record in records],
            next_page_token=next_token or "",
        )
