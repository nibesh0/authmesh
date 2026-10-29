"""Request-scoped context propagated through the call chain.

The gateway mints a request id per inbound HTTP request and forwards it as gRPC
metadata; every downstream service picks it up so a single user action produces
one correlatable id across all three services' logs.
"""

from __future__ import annotations

import contextvars
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

REQUEST_ID_HEADER = "x-request-id"
USER_ID_HEADER = "x-user-id"

_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "authmesh_request_id", default=None
)
_user_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "authmesh_user_id", default=None
)


def new_request_id() -> str:
    return uuid.uuid4().hex


def get_request_id() -> str | None:
    return _request_id.get()


def set_request_id(value: str | None) -> contextvars.Token:
    return _request_id.set(value)


def get_user_id() -> str | None:
    return _user_id.get()


def set_user_id(value: str | None) -> contextvars.Token:
    return _user_id.set(value)


@contextmanager
def request_context(
    request_id: str | None = None, user_id: str | None = None
) -> Iterator[str]:
    """Bind a request id (generating one when absent) for the duration of a block."""
    rid = request_id or new_request_id()
    rid_token = _request_id.set(rid)
    uid_token = _user_id.set(user_id)
    try:
        yield rid
    finally:
        _request_id.reset(rid_token)
        _user_id.reset(uid_token)


def outbound_metadata(extra: dict[str, str] | None = None) -> list[tuple[str, str]]:
    """Metadata to attach to outgoing gRPC calls so context survives the hop."""
    metadata: list[tuple[str, str]] = []
    rid = get_request_id()
    if rid:
        metadata.append((REQUEST_ID_HEADER, rid))
    uid = get_user_id()
    if uid:
        metadata.append((USER_ID_HEADER, uid))
    for key, value in (extra or {}).items():
        metadata.append((key.lower(), value))
    return metadata
