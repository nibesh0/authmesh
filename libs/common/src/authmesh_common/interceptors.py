"""gRPC interceptors: context propagation, structured access logs, metrics, and
the single place where exceptions become gRPC statuses.

Only unary-unary handlers are wrapped. The health `Watch` stream and reflection
are intentionally passed through untouched so probe traffic does not flood the
logs or skew the latency histograms.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, NamedTuple

import grpc

from . import metrics
from .context import REQUEST_ID_HEADER, USER_ID_HEADER, request_context
from .errors import AppError, ErrorCode
from .logging import get_logger

log = get_logger("authmesh.grpc")

# Infrastructure RPCs that should not be logged or measured as application calls.
_INTERNAL_PREFIXES = ("/grpc.health.", "/grpc.reflection.")


def _is_internal(method: str) -> bool:
    return method.startswith(_INTERNAL_PREFIXES)


def _metadata_value(metadata: Sequence[tuple[str, Any]] | None, key: str) -> str | None:
    if not metadata:
        return None
    for entry_key, entry_value in metadata:
        if entry_key.lower() == key:
            return entry_value if isinstance(entry_value, str) else None
    return None


class ServerObservabilityInterceptor(grpc.aio.ServerInterceptor):
    """Binds request context, emits one access log per call, records metrics and
    converts `AppError` / unexpected exceptions into gRPC statuses."""

    def __init__(self, service_label: str) -> None:
        self._service_label = service_label

    async def intercept_service(
        self,
        continuation: Callable[
            [grpc.HandlerCallDetails], Awaitable[grpc.RpcMethodHandler]
        ],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        handler = await continuation(handler_call_details)
        if handler is None:
            return handler

        method = handler_call_details.method or "unknown"
        if _is_internal(method) or handler.request_streaming or handler.response_streaming:
            return handler

        grpc_service, grpc_method = metrics.split_method(method)
        inbound_metadata = handler_call_details.invocation_metadata
        behavior = handler.unary_unary

        async def wrapper(request: Any, context: grpc.aio.ServicerContext) -> Any:
            request_id = _metadata_value(inbound_metadata, REQUEST_ID_HEADER)
            user_id = _metadata_value(inbound_metadata, USER_ID_HEADER)

            with request_context(request_id, user_id) as rid:
                context.set_trailing_metadata(((REQUEST_ID_HEADER, rid),))
                metrics.GRPC_SERVER_STARTED.labels(
                    grpc_service=grpc_service, grpc_method=grpc_method
                ).inc()
                metrics.GRPC_SERVER_IN_FLIGHT.labels(grpc_service=grpc_service).inc()
                started = time.perf_counter()
                status = grpc.StatusCode.OK
                app_error: AppError | None = None

                try:
                    return await behavior(request, context)
                except AppError as exc:
                    app_error = exc
                    status = exc.grpc_status
                    raise
                except grpc.aio.AbortError:
                    # A handler (or an inner interceptor) called context.abort().
                    # The status is already set on the RPC and AbortError is only
                    # the unwinding mechanism, so it must pass through untouched:
                    # treating it as an unexpected exception would relabel a
                    # deliberate NOT_FOUND as INTERNAL.
                    status = grpc.StatusCode.ABORTED
                    raise
                except grpc.aio.AioRpcError as exc:
                    # A downstream call failed and the servicer let it bubble;
                    # surface it as UNAVAILABLE rather than a confusing INTERNAL.
                    status = grpc.StatusCode.UNAVAILABLE
                    app_error = AppError(
                        ErrorCode.UNAVAILABLE, "a downstream dependency is unavailable"
                    )
                    log.warning(
                        "downstream rpc failed",
                        extra={
                            "grpc_method": grpc_method,
                            "downstream_code": exc.code().name,
                            "downstream_details": exc.details(),
                        },
                    )
                    raise app_error from exc
                except Exception as exc:
                    status = grpc.StatusCode.INTERNAL
                    log.exception(
                        "unhandled exception in rpc handler",
                        extra={"grpc_method": grpc_method, "grpc_service": grpc_service},
                    )
                    raise AppError(ErrorCode.INTERNAL, "internal error") from exc
                finally:
                    elapsed = time.perf_counter() - started
                    metrics.GRPC_SERVER_IN_FLIGHT.labels(grpc_service=grpc_service).dec()
                    metrics.GRPC_SERVER_LATENCY.labels(
                        grpc_service=grpc_service, grpc_method=grpc_method
                    ).observe(elapsed)
                    metrics.GRPC_SERVER_HANDLED.labels(
                        grpc_service=grpc_service,
                        grpc_method=grpc_method,
                        grpc_code=status.name,
                    ).inc()

                    entry = {
                        "grpc_service": grpc_service,
                        "grpc_method": grpc_method,
                        "grpc_code": status.name,
                        "duration_ms": round(elapsed * 1000, 2),
                        "peer": context.peer(),
                    }
                    if app_error is not None:
                        entry["error_code"] = app_error.code.value
                        entry["error_message"] = app_error.message
                    if status is grpc.StatusCode.OK:
                        log.info("rpc handled", extra=entry)
                    elif status is grpc.StatusCode.INTERNAL:
                        log.error("rpc failed", extra=entry)
                    else:
                        log.warning("rpc rejected", extra=entry)

        return grpc.unary_unary_rpc_method_handler(
            wrapper,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )


class ErrorTranslationInterceptor(grpc.aio.ServerInterceptor):
    """Terminates `AppError` with its status code plus machine-readable trailers.

    Installed *outside* `ServerObservabilityInterceptor` (first in the interceptor
    tuple). The observability layer logs the error and re-raises it; this layer
    then converts it, and the `AbortError` that `context.abort()` raises goes
    straight to gRPC rather than back through the logging wrapper.
    """

    async def intercept_service(
        self,
        continuation: Callable[
            [grpc.HandlerCallDetails], Awaitable[grpc.RpcMethodHandler]
        ],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        handler = await continuation(handler_call_details)
        if handler is None:
            return handler

        method = handler_call_details.method or ""
        if _is_internal(method) or handler.request_streaming or handler.response_streaming:
            return handler

        behavior = handler.unary_unary

        async def wrapper(request: Any, context: grpc.aio.ServicerContext) -> Any:
            try:
                return await behavior(request, context)
            except AppError as exc:
                trailers = list(exc.trailing_metadata())
                existing = context.trailing_metadata()
                if existing:
                    trailers.extend((k, v) for k, v in existing)
                await context.abort(exc.grpc_status, exc.message, tuple(trailers))

        return grpc.unary_unary_rpc_method_handler(
            wrapper,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )


class _ClientCallDetails(NamedTuple):
    """Replacement call details carrying the augmented metadata.

    Deliberately a NamedTuple rather than a subclass of
    `grpc.aio.ClientCallDetails`: that base declares its fields as read-only
    properties, so any attempt to assign them in __init__ raises
    "AttributeError: can't set attribute". grpc only reads these attributes, so a
    structurally compatible tuple is what it wants.
    """

    method: str
    timeout: float | None
    metadata: grpc.aio.Metadata | None
    credentials: grpc.CallCredentials | None
    wait_for_ready: bool | None


class ClientContextInterceptor(grpc.aio.UnaryUnaryClientInterceptor):
    """Forwards the request id downstream and records client-side metrics."""

    async def intercept_unary_unary(
        self,
        continuation: Callable[[grpc.aio.ClientCallDetails, Any], Any],
        client_call_details: grpc.aio.ClientCallDetails,
        request: Any,
    ) -> Any:
        from .context import get_request_id, get_user_id

        metadata = grpc.aio.Metadata(*(client_call_details.metadata or ()))
        if REQUEST_ID_HEADER not in metadata:
            request_id = get_request_id()
            if request_id:
                metadata.add(REQUEST_ID_HEADER, request_id)
        if USER_ID_HEADER not in metadata:
            user_id = get_user_id()
            if user_id:
                metadata.add(USER_ID_HEADER, user_id)

        details = _ClientCallDetails(
            method=client_call_details.method,
            timeout=client_call_details.timeout,
            metadata=metadata,
            credentials=client_call_details.credentials,
            wait_for_ready=client_call_details.wait_for_ready,
        )

        method = (
            client_call_details.method
            if isinstance(client_call_details.method, str)
            else client_call_details.method.decode()
        )
        grpc_service, grpc_method = metrics.split_method(method)
        started = time.perf_counter()

        call = await continuation(details, request)
        try:
            response = await call
        except grpc.aio.AioRpcError as exc:
            metrics.GRPC_CLIENT_HANDLED.labels(
                grpc_service=grpc_service,
                grpc_method=grpc_method,
                grpc_code=exc.code().name,
            ).inc()
            metrics.GRPC_CLIENT_LATENCY.labels(
                grpc_service=grpc_service, grpc_method=grpc_method
            ).observe(time.perf_counter() - started)
            raise

        metrics.GRPC_CLIENT_HANDLED.labels(
            grpc_service=grpc_service, grpc_method=grpc_method, grpc_code="OK"
        ).inc()
        metrics.GRPC_CLIENT_LATENCY.labels(
            grpc_service=grpc_service, grpc_method=grpc_method
        ).observe(time.perf_counter() - started)
        return response
