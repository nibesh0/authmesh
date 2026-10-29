"""Prometheus instrumentation shared by every service.

Each service exposes `/metrics`: the gateway serves it from its own HTTP app, the
gRPC services run a tiny side HTTP server on `metrics_port`. Prometheus finds
both through pod annotations (or a PodMonitor when prometheus-operator is
present).
"""

from __future__ import annotations

import threading
from typing import Iterable

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from prometheus_client import REGISTRY as DEFAULT_REGISTRY
from prometheus_client.exposition import start_http_server

CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"

# Buckets tuned for in-cluster RPCs: most calls land under 25ms, and bcrypt-bound
# login calls sit in the 100-500ms band, so we need resolution in both regions.
LATENCY_BUCKETS = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
)

registry: CollectorRegistry = DEFAULT_REGISTRY

BUILD_INFO = Gauge(
    "authmesh_build_info",
    "Static build metadata; value is always 1.",
    ["service", "version", "environment"],
)

GRPC_SERVER_STARTED = Counter(
    "grpc_server_started_total",
    "gRPC calls received by this server.",
    ["grpc_service", "grpc_method"],
)

GRPC_SERVER_HANDLED = Counter(
    "grpc_server_handled_total",
    "gRPC calls completed, by resulting status code.",
    ["grpc_service", "grpc_method", "grpc_code"],
)

GRPC_SERVER_LATENCY = Histogram(
    "grpc_server_handling_seconds",
    "Server-side latency of gRPC calls.",
    ["grpc_service", "grpc_method"],
    buckets=LATENCY_BUCKETS,
)

GRPC_SERVER_IN_FLIGHT = Gauge(
    "grpc_server_in_flight_requests",
    "gRPC calls currently being handled.",
    ["grpc_service"],
)

GRPC_CLIENT_HANDLED = Counter(
    "grpc_client_handled_total",
    "Outbound gRPC calls completed, by resulting status code.",
    ["grpc_service", "grpc_method", "grpc_code"],
)

GRPC_CLIENT_LATENCY = Histogram(
    "grpc_client_handling_seconds",
    "Client-side latency of outbound gRPC calls.",
    ["grpc_service", "grpc_method"],
    buckets=LATENCY_BUCKETS,
)

HTTP_REQUESTS = Counter(
    "http_requests_total",
    "HTTP requests handled by the gateway.",
    ["method", "route", "status"],
)

HTTP_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency.",
    ["method", "route"],
    buckets=LATENCY_BUCKETS,
)

HTTP_IN_FLIGHT = Gauge(
    "http_in_flight_requests",
    "HTTP requests currently in flight.",
)

DEPENDENCY_UP = Gauge(
    "authmesh_dependency_up",
    "Result of the most recent dependency health check (1 healthy, 0 unhealthy).",
    ["dependency"],
)

READINESS = Gauge(
    "authmesh_ready",
    "Whether this instance currently reports itself ready to serve (1/0).",
)

_metrics_server_lock = threading.Lock()
_metrics_server_started = False


def set_build_info(service: str, version: str, environment: str) -> None:
    BUILD_INFO.labels(service=service, version=version, environment=environment).set(1)


def split_method(full_method: str) -> tuple[str, str]:
    """`/authmesh.auth.v1.AuthService/Login` -> (`AuthService`, `Login`)."""
    trimmed = full_method.lstrip("/")
    if "/" not in trimmed:
        return "unknown", trimmed or "unknown"
    service, _, method = trimmed.partition("/")
    return service.rsplit(".", 1)[-1] or "unknown", method or "unknown"


def render() -> bytes:
    return generate_latest(registry)


def start_metrics_server(port: int, addr: str = "0.0.0.0") -> None:
    """Expose /metrics on a dedicated port (idempotent)."""
    global _metrics_server_started
    with _metrics_server_lock:
        if _metrics_server_started:
            return
        start_http_server(port, addr=addr, registry=registry)
        _metrics_server_started = True


def observe_dependencies(results: Iterable[tuple[str, bool]]) -> None:
    for name, healthy in results:
        DEPENDENCY_UP.labels(dependency=name).set(1 if healthy else 0)
