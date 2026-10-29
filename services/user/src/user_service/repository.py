"""MongoDB persistence for users and audit events.

The repository owns everything Mongo-specific: document shape, indexes, cursor
pagination and translation of driver errors into `AppError`. The servicer above it
only deals in protobuf messages, so swapping the datastore would not touch the
gRPC layer.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING, ReturnDocument
from pymongo.errors import DuplicateKeyError, PyMongoError

from authmesh_common.errors import AppError, ErrorCode, already_exists, not_found
from authmesh_common.logging import get_logger
from authmesh_common.timeutil import utcnow

from .settings import UserServiceSettings

log = get_logger(__name__)

USERS_COLLECTION = "users"
AUDIT_COLLECTION = "audit_events"


def normalize_email(email: str) -> str:
    return email.strip().lower()


@dataclass
class UserRecord:
    id: str
    email: str
    display_name: str
    password_hash: str
    roles: list[str] = field(default_factory=list)
    totp_enabled: bool = False
    totp_secret_enc: str | None = None
    recovery_code_hashes: list[str] = field(default_factory=list)
    disabled: bool = False
    created_at: datetime | None = None
    updated_at: datetime | None = None
    password_changed_at: datetime | None = None

    @classmethod
    def from_document(cls, doc: dict[str, Any]) -> "UserRecord":
        return cls(
            id=doc["_id"],
            email=doc["email"],
            display_name=doc.get("display_name", ""),
            password_hash=doc.get("password_hash", ""),
            roles=list(doc.get("roles", [])),
            totp_enabled=bool(doc.get("totp_enabled", False)),
            totp_secret_enc=doc.get("totp_secret_enc"),
            recovery_code_hashes=list(doc.get("recovery_code_hashes", [])),
            disabled=bool(doc.get("disabled", False)),
            created_at=_as_utc(doc.get("created_at")),
            updated_at=_as_utc(doc.get("updated_at")),
            password_changed_at=_as_utc(doc.get("password_changed_at")),
        )


@dataclass
class AuditRecord:
    id: str
    action: str
    user_id: str = ""
    email: str = ""
    success: bool = True
    ip: str = ""
    user_agent: str = ""
    request_id: str = ""
    reason: str = ""
    created_at: datetime | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_document(cls, doc: dict[str, Any]) -> "AuditRecord":
        return cls(
            id=doc["_id"],
            action=doc.get("action", ""),
            user_id=doc.get("user_id", ""),
            email=doc.get("email", ""),
            success=bool(doc.get("success", True)),
            ip=doc.get("ip", ""),
            user_agent=doc.get("user_agent", ""),
            request_id=doc.get("request_id", ""),
            reason=doc.get("reason", ""),
            created_at=_as_utc(doc.get("created_at")),
            metadata=dict(doc.get("metadata", {})),
        )


def _as_utc(value: Any) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _encode_cursor(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), default=str).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(token: str) -> dict[str, Any]:
    padding = "=" * (-len(token) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(token + padding))
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise AppError(ErrorCode.INVALID_ARGUMENT, "invalid page token") from exc


class UserRepository:
    def __init__(self, settings: UserServiceSettings) -> None:
        self._settings = settings
        self._client: AsyncIOMotorClient | None = None
        self._db: AsyncIOMotorDatabase | None = None

    # -- connection --------------------------------------------------------

    async def connect(self) -> None:
        settings = self._settings
        self._client = AsyncIOMotorClient(
            settings.mongo_uri,
            serverSelectionTimeoutMS=settings.mongo_server_selection_timeout_ms,
            connectTimeoutMS=settings.mongo_connect_timeout_ms,
            socketTimeoutMS=settings.mongo_socket_timeout_ms,
            maxPoolSize=settings.mongo_max_pool_size,
            minPoolSize=settings.mongo_min_pool_size,
            appname=settings.service_name,
            tz_aware=True,
            uuidRepresentation="standard",
            retryWrites=True,
        )
        self._db = self._client[settings.mongo_database]
        log.info("mongo client created", extra={"database": settings.mongo_database})

    async def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
            self._db = None

    @property
    def db(self) -> AsyncIOMotorDatabase:
        if self._db is None:
            raise AppError(ErrorCode.UNAVAILABLE, "database connection not initialised")
        return self._db

    async def ping(self) -> bool:
        if self._client is None:
            return False
        try:
            await self._client.admin.command("ping")
            return True
        except PyMongoError as exc:
            log.warning("mongo ping failed", extra={"reason": str(exc)})
            return False

    async def ensure_indexes(self) -> None:
        """Idempotent; safe to run on every replica at boot."""
        users = self.db[USERS_COLLECTION]
        await users.create_index([("email", ASCENDING)], name="uniq_email", unique=True)
        await users.create_index([("created_at", DESCENDING)], name="created_at_desc")
        await users.create_index([("disabled", ASCENDING)], name="disabled")

        audit = self.db[AUDIT_COLLECTION]
        await audit.create_index(
            [("user_id", ASCENDING), ("created_at", DESCENDING)], name="user_recent"
        )
        await audit.create_index(
            [("action", ASCENDING), ("created_at", DESCENDING)], name="action_recent"
        )
        await audit.create_index([("created_at", DESCENDING)], name="recent")

        if self._settings.audit_retention_days > 0:
            ttl_seconds = self._settings.audit_retention_days * 86_400
            # Recreate the TTL index when the retention window changes: Mongo
            # rejects create_index on an existing name with different options.
            try:
                await audit.create_index(
                    [("created_at", ASCENDING)],
                    name="audit_ttl",
                    expireAfterSeconds=ttl_seconds,
                )
            except PyMongoError:
                await audit.drop_index("audit_ttl")
                await audit.create_index(
                    [("created_at", ASCENDING)],
                    name="audit_ttl",
                    expireAfterSeconds=ttl_seconds,
                )
        log.info("indexes ensured")

    # -- users -------------------------------------------------------------

    async def create_user(
        self,
        *,
        user_id: str,
        email: str,
        display_name: str,
        password_hash: str,
        roles: list[str],
    ) -> UserRecord:
        now = utcnow()
        document = {
            "_id": user_id,
            "email": normalize_email(email),
            "display_name": display_name,
            "password_hash": password_hash,
            "roles": roles or ["user"],
            "totp_enabled": False,
            "totp_secret_enc": None,
            "recovery_code_hashes": [],
            "disabled": False,
            "created_at": now,
            "updated_at": now,
            "password_changed_at": now,
        }
        try:
            await self.db[USERS_COLLECTION].insert_one(document)
        except DuplicateKeyError as exc:
            raise already_exists("a user with this email already exists") from exc
        return UserRecord.from_document(document)

    async def get_by_id(self, user_id: str) -> UserRecord:
        doc = await self.db[USERS_COLLECTION].find_one({"_id": user_id})
        if doc is None:
            raise not_found("user not found", user_id=user_id)
        return UserRecord.from_document(doc)

    async def get_by_email(self, email: str) -> UserRecord:
        doc = await self.db[USERS_COLLECTION].find_one({"email": normalize_email(email)})
        if doc is None:
            raise not_found("user not found")
        return UserRecord.from_document(doc)

    async def update_user(self, user_id: str, updates: dict[str, Any]) -> UserRecord:
        """Apply a partial update. `updates` may contain the sentinel keys
        `$clear_totp_secret` and `$touch_password_changed_at`."""
        set_fields: dict[str, Any] = {
            k: v for k, v in updates.items() if not k.startswith("$")
        }
        now = utcnow()
        set_fields["updated_at"] = now

        if updates.get("$clear_totp_secret"):
            set_fields["totp_secret_enc"] = None
            set_fields["recovery_code_hashes"] = []
        if updates.get("$touch_password_changed_at"):
            set_fields["password_changed_at"] = now
        if "email" in set_fields:
            set_fields["email"] = normalize_email(set_fields["email"])

        try:
            doc = await self.db[USERS_COLLECTION].find_one_and_update(
                {"_id": user_id},
                {"$set": set_fields},
                return_document=ReturnDocument.AFTER,
            )
        except DuplicateKeyError as exc:
            raise already_exists("a user with this email already exists") from exc

        if doc is None:
            raise not_found("user not found", user_id=user_id)
        return UserRecord.from_document(doc)

    async def delete_user(self, user_id: str) -> None:
        result = await self.db[USERS_COLLECTION].delete_one({"_id": user_id})
        if result.deleted_count == 0:
            raise not_found("user not found", user_id=user_id)

    async def list_users(
        self, *, page_size: int, page_token: str | None, email_prefix: str | None
    ) -> tuple[list[UserRecord], str | None, int]:
        query: dict[str, Any] = {}
        if email_prefix:
            # Anchored prefix match so the unique email index is still used.
            query["email"] = {"$regex": f"^{_escape_regex(normalize_email(email_prefix))}"}

        total = await self.db[USERS_COLLECTION].count_documents(query)

        if page_token:
            cursor_payload = _decode_cursor(page_token)
            last_id = cursor_payload.get("id")
            if last_id:
                query["_id"] = {"$gt": last_id}

        cursor = (
            self.db[USERS_COLLECTION]
            .find(query)
            .sort("_id", ASCENDING)
            .limit(page_size + 1)
        )
        docs = await cursor.to_list(length=page_size + 1)

        next_token: str | None = None
        if len(docs) > page_size:
            docs = docs[:page_size]
            next_token = _encode_cursor({"id": docs[-1]["_id"]})

        return [UserRecord.from_document(doc) for doc in docs], next_token, total

    # -- audit -------------------------------------------------------------

    async def record_audit(self, record: AuditRecord) -> None:
        document = {
            "_id": record.id,
            "action": record.action,
            "user_id": record.user_id,
            "email": record.email,
            "success": record.success,
            "ip": record.ip,
            "user_agent": record.user_agent,
            "request_id": record.request_id,
            "reason": record.reason,
            "created_at": record.created_at or utcnow(),
            "metadata": record.metadata,
        }
        try:
            await self.db[AUDIT_COLLECTION].insert_one(document)
        except DuplicateKeyError:
            # Same event id delivered twice (client retry); the write already
            # landed, so treat it as success.
            log.debug("duplicate audit event ignored", extra={"audit_id": record.id})

    async def list_audit_events(
        self,
        *,
        user_id: str | None,
        action: str | None,
        page_size: int,
        page_token: str | None,
    ) -> tuple[list[AuditRecord], str | None]:
        query: dict[str, Any] = {}
        if user_id:
            query["user_id"] = user_id
        if action:
            query["action"] = action

        if page_token:
            payload = _decode_cursor(page_token)
            created_before = payload.get("created_at")
            last_id = payload.get("id")
            parsed = (
                datetime.fromisoformat(created_before)
                if isinstance(created_before, str)
                else None
            )
            if parsed is not None:
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                # Tie-break on _id so events sharing a millisecond are not
                # skipped or repeated across pages.
                query["$or"] = [
                    {"created_at": {"$lt": parsed}},
                    {"created_at": parsed, "_id": {"$lt": last_id}},
                ]

        cursor = (
            self.db[AUDIT_COLLECTION]
            .find(query)
            .sort([("created_at", DESCENDING), ("_id", DESCENDING)])
            .limit(page_size + 1)
        )
        docs = await cursor.to_list(length=page_size + 1)

        next_token: str | None = None
        if len(docs) > page_size:
            docs = docs[:page_size]
            last = docs[-1]
            next_token = _encode_cursor(
                {
                    "created_at": _as_utc(last.get("created_at")),
                    "id": last["_id"],
                }
            )

        return [AuditRecord.from_document(doc) for doc in docs], next_token

    async def purge_audit_before(self, cutoff: datetime) -> int:
        result = await self.db[AUDIT_COLLECTION].delete_many(
            {"created_at": {"$lt": cutoff}}
        )
        return result.deleted_count

    async def retention_cutoff(self) -> datetime:
        return utcnow() - timedelta(days=self._settings.audit_retention_days)


_REGEX_SPECIAL = ".^$*+?()[]{}|\\"


def _escape_regex(value: str) -> str:
    return "".join("\\" + ch if ch in _REGEX_SPECIAL else ch for ch in value)
