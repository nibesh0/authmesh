"""Runtime harness for the asyncio gRPC services.

Both gRPC services boot through `GrpcApp`, which gives them identical behaviour
for the things that are easy to get subtly wrong per service: interceptor order,
health service registration, metrics exposure, and a shutdown sequence that
drains cleanly under a rolling update.

Shutdown order is deliberate:
  1. flip readiness to NOT_SERVING  -> kube-proxy starts removing the endpoint
  2. wait `drain_delay_seconds`     -> in-flight routing settles
  3. `server.stop(grace)`           -> refuse new RPCs, let current ones finish
  4. run shutdown hooks             -> close Redis/Mongo/channels
"""

from __future__ import annotations

import asyncio
import signal
from collections.abc import Awaitable, Callable, Iterable, Sequence
from concurrent import futures

import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc

from . import metrics
from .config import BaseServiceSettings
from .health import AsyncHealthServicer, DependencyProbe, HealthController
from .interceptors import ErrorTranslationInterceptor, ServerObservabilityInterceptor
from .logging import configure_logging, get_logger

log = get_logger("authmesh.server")

RegisterFn = Callable[[grpc.aio.Server], None]
Hook = Callable[[], Awaitable[None]]


def server_options(max_message_bytes: int = 4 * 1024 * 1024) -> list[tuple[str, object]]:
    return [
        ("grpc.max_receive_message_length", max_message_bytes),
        ("grpc.max_send_message_length", max_message_bytes),
        # Mirror of the client keepalive settings; without the min-ping guard the
        # server would send GOAWAY(too_many_pings) to well-behaved clients.
        ("grpc.keepalive_time_ms", 30_000),
        ("grpc.keepalive_timeout_ms", 10_000),
        ("grpc.keepalive_permit_without_calls", 1),
        ("grpc.http2.min_ping_interval_without_data_ms", 10_000),
        ("grpc.http2.max_pings_without_data", 0),
        # Recycle connections so DNS changes and new replicas get picked up.
        ("grpc.max_connection_age_ms", 300_000),
        ("grpc.max_connection_age_grace_ms", 20_000),
    ]


class GrpcApp:
    def __init__(
        self,
        *,
        settings: BaseServiceSettings,
        port: int,
        register: RegisterFn,
        service_names: Sequence[str],
        startup: Hook | None = None,
        shutdown: Hook | None = None,
        probes: Iterable[tuple[str, DependencyProbe]] = (),
        enable_reflection: bool = True,
        max_concurrent_rpcs: int | None = None,
        drain_delay_seconds: float = 3.0,
    ) -> None:
        self.settings = settings
        self.port = port
        self._register = register
        self._service_names = list(service_names)
        self._startup = startup
        self._shutdown = shutdown
        self._probes = list(probes)
        self._enable_reflection = enable_reflection
        self._max_concurrent_rpcs = max_concurrent_rpcs
        self._drain_delay = drain_delay_seconds
        self._stop_event: asyncio.Event | None = None
        self.health_servicer = AsyncHealthServicer()
        self.health: HealthController | None = None

    # -- lifecycle ---------------------------------------------------------

    def _install_signal_handlers(self, loop: asyncio.AbstractEventLoop) -> None:
        def request_stop(sig: signal.Signals) -> None:
            log.info("shutdown signal received", extra={"signal": sig.name})
            if self._stop_event is not None:
                self._stop_event.set()

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, request_stop, sig)
            except NotImplementedError:  # pragma: no cover - non-POSIX
                signal.signal(sig, lambda *_: request_stop(signal.SIGTERM))

    async def run(self) -> None:
        settings = self.settings
        self._stop_event = asyncio.Event()
        self._install_signal_handlers(asyncio.get_running_loop())

        server = grpc.aio.server(
            # Only used if a sync handler ever sneaks in; kept tiny on purpose.
            migration_thread_pool=futures.ThreadPoolExecutor(max_workers=4),
            # Order matters: the first entry is the outermost layer. Error
            # translation has to sit outside the observability layer so that the
            # AbortError raised by context.abort() is not mistaken for a handler
            # crash and relabelled INTERNAL.
            interceptors=(
                ErrorTranslationInterceptor(),
                ServerObservabilityInterceptor(settings.service_name),
            ),
            options=server_options(),
            maximum_concurrent_rpcs=self._max_concurrent_rpcs,
        )

        self._register(server)
        health_pb2_grpc.add_HealthServicer_to_server(self.health_servicer, server)

        self.health = HealthController(
            self.health_servicer,
            probes=self._probes,
            interval_seconds=settings.health_check_interval_seconds,
        )

        advertised = [*self._service_names, health_pb2.DESCRIPTOR.services_by_name["Health"].full_name]
        if self._enable_reflection:
            from grpc_reflection.v1alpha import reflection

            reflection.enable_server_reflection(
                [*advertised, reflection.SERVICE_NAME], server
            )

        if settings.metrics_enabled:
            metrics.start_metrics_server(settings.metrics_port)
            metrics.set_build_info(
                settings.service_name, settings.version, settings.environment
            )

        if self._startup is not None:
            await self._startup()

        bind_address = f"0.0.0.0:{self.port}"
        server.add_insecure_port(bind_address)
        await server.start()
        self.health.mark_live()
        await self.health.start()

        log.info(
            "grpc server listening",
            extra={
                "address": bind_address,
                "metrics_port": settings.metrics_port if settings.metrics_enabled else None,
                "services": self._service_names,
                "reflection": self._enable_reflection,
            },
        )

        await self._stop_event.wait()
        await self._graceful_shutdown(server)

    async def _graceful_shutdown(self, server: grpc.aio.Server) -> None:
        settings = self.settings
        log.info("draining", extra={"drain_delay_seconds": self._drain_delay})

        if self.health is not None:
            await self.health.stop()
        self.health_servicer.set("", health_pb2.HealthCheckResponse.NOT_SERVING)

        if self._drain_delay > 0:
            await asyncio.sleep(self._drain_delay)

        await server.stop(settings.shutdown_grace_seconds)

        if self._shutdown is not None:
            try:
                await self._shutdown()
            except Exception:
                log.exception("error during shutdown hook")

        log.info("shutdown complete")


def bootstrap_logging(settings: BaseServiceSettings) -> None:
    configure_logging(
        service=settings.service_name,
        level=settings.log_level,
        fmt=settings.log_format,
        environment=settings.environment,
        version=settings.version,
    )
