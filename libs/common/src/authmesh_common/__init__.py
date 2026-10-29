"""Shared runtime for the authmesh platform."""

from .config import BaseServiceSettings
from .context import (
    REQUEST_ID_HEADER,
    get_request_id,
    new_request_id,
    outbound_metadata,
    request_context,
    set_request_id,
    set_user_id,
)
from .errors import AppError, ErrorCode, from_rpc_error
from .grpc_client import channel_is_ready, create_channel
from .grpc_server import GrpcApp, bootstrap_logging
from .health import LIVENESS_SERVICE, READINESS_SERVICE
from .logging import configure_logging, get_logger
from .timeutil import epoch_seconds, from_rfc3339, to_rfc3339, utcnow

__all__ = [
    "AppError",
    "BaseServiceSettings",
    "ErrorCode",
    "GrpcApp",
    "LIVENESS_SERVICE",
    "READINESS_SERVICE",
    "REQUEST_ID_HEADER",
    "bootstrap_logging",
    "channel_is_ready",
    "configure_logging",
    "create_channel",
    "epoch_seconds",
    "from_rfc3339",
    "from_rpc_error",
    "get_logger",
    "get_request_id",
    "new_request_id",
    "outbound_metadata",
    "request_context",
    "set_request_id",
    "set_user_id",
    "to_rfc3339",
    "utcnow",
]
