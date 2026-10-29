"""HTTP middleware: request correlation, access logs, metrics, hardening."""

from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from authmesh_common import metrics
from authmesh_common.context import REQUEST_ID_HEADER, new_request_id, request_context
from authmesh_common.logging import get_logger

log = get_logger("authmesh.gateway.http")

# Endpoints excluded from access logs and latency histograms: probes and scrapes
# would otherwise dominate both.
_QUIET_PATHS = frozenset({"/healthz", "/readyz", "/metrics", "/livez"})


def client_ip(request: Request, trusted_proxy_hops: int) -> str:
    """Resolve the caller's IP.

    X-Forwarded-For is attacker-controlled unless you know how many proxies are in
    front of you: the rightmost `trusted_proxy_hops` entries were appended by
    infrastructure you control, so the address just left of them is the furthest
    one that can be trusted. With 0 hops configured the header is ignored.
    """
    if trusted_proxy_hops > 0:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            parts = [part.strip() for part in forwarded.split(",") if part.strip()]
            if parts:
                index = max(0, len(parts) - trusted_proxy_hops)
                return parts[min(index, len(parts) - 1)]
    return request.client.host if request.client else ""


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Binds a request id, emits one access log line, records HTTP metrics."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        incoming = request.headers.get(REQUEST_ID_HEADER)
        # Only accept a caller-supplied id if it looks like one, so it cannot be
        # used to inject arbitrary content into log fields.
        request_id = (
            incoming
            if incoming and len(incoming) <= 64 and incoming.replace("-", "").isalnum()
            else new_request_id()
        )
        path = request.url.path
        quiet = path in _QUIET_PATHS

        with request_context(request_id):
            started = time.perf_counter()
            if not quiet:
                metrics.HTTP_IN_FLIGHT.inc()
            try:
                response = await call_next(request)
            except Exception:
                # The exception handlers below produce the response; log here so
                # the failure is recorded with its timing and route.
                if not quiet:
                    metrics.HTTP_IN_FLIGHT.dec()
                    metrics.HTTP_REQUESTS.labels(
                        method=request.method, route=path, status="500"
                    ).inc()
                log.exception(
                    "request failed",
                    extra={
                        "http_method": request.method,
                        "http_path": path,
                        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                    },
                )
                raise

            elapsed = time.perf_counter() - started
            response.headers[REQUEST_ID_HEADER] = request_id

            if not quiet:
                # The route template (/api/v1/me/sessions/{session_id}) keeps
                # cardinality bounded; the raw path would create a series per id.
                route = request.scope.get("route")
                route_label = getattr(route, "path", path)
                metrics.HTTP_IN_FLIGHT.dec()
                metrics.HTTP_REQUESTS.labels(
                    method=request.method,
                    route=route_label,
                    status=str(response.status_code),
                ).inc()
                metrics.HTTP_LATENCY.labels(
                    method=request.method, route=route_label
                ).observe(elapsed)

                log.info(
                    "request handled",
                    extra={
                        "http_method": request.method,
                        "http_path": path,
                        "http_status": response.status_code,
                        "duration_ms": round(elapsed * 1000, 2),
                        "client_ip": client_ip(request, _trusted_hops(request)),
                        "user_agent": request.headers.get("user-agent", "")[:200],
                    },
                )
            return response


def _trusted_hops(request: Request) -> int:
    settings = getattr(request.app.state, "settings", None)
    return getattr(settings, "trusted_proxy_hops", 0) if settings else 0


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        headers = response.headers
        headers.setdefault("x-content-type-options", "nosniff")
        headers.setdefault("x-frame-options", "DENY")
        headers.setdefault("referrer-policy", "no-referrer")
        headers.setdefault("cross-origin-opener-policy", "same-origin")
        headers.setdefault(
            "content-security-policy", "default-src 'none'; frame-ancestors 'none'"
        )
        # Tokens must never be cached by an intermediary.
        if request.url.path.startswith("/api/"):
            headers.setdefault("cache-control", "no-store")
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized bodies before they are buffered."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        super().__init__(app)
        self._max_bytes = max_bytes

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self._max_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error": {
                                "code": "payload_too_large",
                                "message": "request body is too large",
                            }
                        },
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": {
                            "code": "invalid_argument",
                            "message": "invalid Content-Length header",
                        }
                    },
                )
        return await call_next(request)
