"""Structured logging.

Every service logs single-line JSON to stdout. In Kubernetes the container
runtime writes stdout to disk, Fluent Bit tails it and ships it to Loki, so the
JSON keys here are the fields you query on in Grafana. Nothing else is needed to
get centralized logging: do not add file handlers or log shippers to the app.
"""

from __future__ import annotations

import json
import logging
import sys
import traceback
from datetime import datetime, timezone
from typing import Any

from .context import get_request_id, get_user_id

# Attributes LogRecord always carries; anything else was passed via `extra=`
# and is therefore application context worth emitting.
_RESERVED = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)

_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "new_password",
        "current_password",
        "access_token",
        "refresh_token",
        "mfa_token",
        "token",
        "secret",
        "totp_secret",
        "authorization",
        "recovery_codes",
    }
)

REDACTED = "***redacted***"


def _redact(value: Any, key: str | None = None) -> Any:
    if key is not None and key.lower() in _SENSITIVE_KEYS:
        return REDACTED
    if isinstance(value, dict):
        return {k: _redact(v, k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v) for v in value]
    return value


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str, environment: str, version: str) -> None:
        super().__init__()
        self.service = service
        self.environment = environment
        self.version = version

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "service": self.service,
            "env": self.environment,
            "version": self.version,
        }

        request_id = get_request_id()
        if request_id:
            payload["request_id"] = request_id
        user_id = get_user_id()
        if user_id:
            payload["user_id"] = user_id

        for key, value in record.__dict__.items():
            if key in _RESERVED or key.startswith("_"):
                continue
            payload[key] = _redact(value, key)

        if record.exc_info:
            exc_type, exc_value, exc_tb = record.exc_info
            payload["error"] = {
                "type": getattr(exc_type, "__name__", str(exc_type)),
                "message": str(exc_value),
                "stack": "".join(traceback.format_exception(*record.exc_info))[-4000:],
            }
            del exc_tb

        try:
            return json.dumps(payload, default=str, separators=(",", ":"))
        except (TypeError, ValueError):
            return json.dumps(
                {
                    "ts": payload["ts"],
                    "level": "ERROR",
                    "logger": record.name,
                    "msg": "log serialization failed",
                    "service": self.service,
                }
            )


class ConsoleFormatter(logging.Formatter):
    """Human-readable output for local development."""

    def format(self, record: logging.LogRecord) -> str:
        rid = get_request_id()
        prefix = f"[{rid[:8]}] " if rid else ""
        base = (
            f"{self.formatTime(record, '%H:%M:%S')} {record.levelname:<7} "
            f"{prefix}{record.name}: {record.getMessage()}"
        )
        extras = {
            k: _redact(v, k)
            for k, v in record.__dict__.items()
            if k not in _RESERVED and not k.startswith("_")
        }
        if extras:
            base += " " + " ".join(f"{k}={v}" for k, v in extras.items())
        if record.exc_info:
            base += "\n" + "".join(traceback.format_exception(*record.exc_info))
        return base


def configure_logging(
    *,
    service: str,
    level: str = "INFO",
    fmt: str = "json",
    environment: str = "development",
    version: str = "0.0.0",
) -> None:
    """Install a single stdout handler and silence noisy third-party loggers."""
    formatter: logging.Formatter
    if fmt == "console":
        formatter = ConsoleFormatter()
    else:
        formatter = JsonFormatter(service=service, environment=environment, version=version)

    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level.upper())

    # Uvicorn duplicates access logs that our own middleware already emits with
    # richer context; keep its error channel but drop the duplicate stream.
    for noisy, noisy_level in (
        ("uvicorn.access", logging.WARNING),
        ("uvicorn.error", logging.INFO),
        ("pymongo", logging.WARNING),
        ("asyncio", logging.WARNING),
    ):
        logger = logging.getLogger(noisy)
        logger.setLevel(noisy_level)
        logger.propagate = True
        for existing in list(logger.handlers):
            logger.removeHandler(existing)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
