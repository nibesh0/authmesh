"""gRPC health checking for asyncio servers.

`grpcio-health-checking` ships a synchronous servicer, which cannot be mounted on
a `grpc.aio` server, so the servicer is implemented here against the same
generated stubs. Two health service names are registered:

* `""`      - liveness. SERVING from the moment the server accepts connections
              until shutdown begins. It answers "is this process wedged?" and
              must not depend on Redis/Mongo, otherwise a dependency blip would
              make Kubernetes restart otherwise-healthy pods.
* `ready`   - readiness. Driven by dependency probes, so a pod that cannot reach
              its datastore is pulled out of the Service endpoints without being
              killed.

Kubernetes talks to these directly via `livenessProbe.grpc` / `readinessProbe.grpc`.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Iterable

import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc

from . import metrics
from .logging import get_logger

LIVENESS_SERVICE = ""
READINESS_SERVICE = "ready"

ServingStatus = health_pb2.HealthCheckResponse.ServingStatus
SERVING = health_pb2.HealthCheckResponse.SERVING
NOT_SERVING = health_pb2.HealthCheckResponse.NOT_SERVING
SERVICE_UNKNOWN = health_pb2.HealthCheckResponse.SERVICE_UNKNOWN

log = get_logger(__name__)

# A probe returns (name, healthy). Probes must be cheap and must not raise.
DependencyProbe = Callable[[], Awaitable[bool]]


class AsyncHealthServicer(health_pb2_grpc.HealthServicer):
    """Minimal async implementation of grpc.health.v1.Health."""

    def __init__(self) -> None:
        self._status: dict[str, ServingStatus] = {}
        self._watchers: dict[str, set[asyncio.Queue[ServingStatus]]] = defaultdict(set)

    def status_of(self, service: str) -> ServingStatus:
        return self._status.get(service, SERVICE_UNKNOWN)

    def set(self, service: str, status: ServingStatus) -> None:
        if self._status.get(service) == status:
            return
        self._status[service] = status
        for queue in self._watchers.get(service, set()):
            queue.put_nowait(status)

    async def Check(  # noqa: N802 - gRPC method name
        self,
        request: health_pb2.HealthCheckRequest,
        context: grpc.aio.ServicerContext,
    ) -> health_pb2.HealthCheckResponse:
        status = self._status.get(request.service)
        if status is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "unknown health service")
        return health_pb2.HealthCheckResponse(status=status)

    async def Watch(  # noqa: N802 - gRPC method name
        self,
        request: health_pb2.HealthCheckRequest,
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[health_pb2.HealthCheckResponse]:
        queue: asyncio.Queue[ServingStatus] = asyncio.Queue()
        self._watchers[request.service].add(queue)
        try:
            yield health_pb2.HealthCheckResponse(status=self.status_of(request.service))
            while True:
                status = await queue.get()
                yield health_pb2.HealthCheckResponse(status=status)
        finally:
            self._watchers[request.service].discard(queue)


class HealthController:
    """Owns the liveness/readiness statuses and the dependency probe loop."""

    def __init__(
        self,
        servicer: AsyncHealthServicer,
        probes: Iterable[tuple[str, DependencyProbe]] = (),
        interval_seconds: float = 10.0,
    ) -> None:
        self._servicer = servicer
        self._probes = list(probes)
        self._interval = interval_seconds
        self._task: asyncio.Task[None] | None = None
        self._ready = False
        servicer.set(LIVENESS_SERVICE, NOT_SERVING)
        servicer.set(READINESS_SERVICE, NOT_SERVING)

    @property
    def is_ready(self) -> bool:
        return self._ready

    def mark_live(self) -> None:
        self._servicer.set(LIVENESS_SERVICE, SERVING)

    def mark_not_live(self) -> None:
        self._servicer.set(LIVENESS_SERVICE, NOT_SERVING)

    def _set_ready(self, ready: bool) -> None:
        if ready != self._ready:
            log.info("readiness changed", extra={"ready": ready})
        self._ready = ready
        self._servicer.set(READINESS_SERVICE, SERVING if ready else NOT_SERVING)
        metrics.READINESS.set(1 if ready else 0)

    async def check_now(self) -> bool:
        """Run every probe once and publish the aggregate result."""
        results: list[tuple[str, bool]] = []
        for name, probe in self._probes:
            try:
                healthy = bool(await probe())
            except Exception as exc:  # a probe must never take the process down
                log.warning(
                    "dependency probe failed",
                    extra={"dependency": name, "reason": str(exc)},
                )
                healthy = False
            results.append((name, healthy))

        metrics.observe_dependencies(results)
        ready = all(healthy for _, healthy in results)
        self._set_ready(ready)
        return ready

    async def start(self) -> None:
        await self.check_now()
        self._task = asyncio.create_task(self._loop(), name="health-probe-loop")

    async def _loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self._interval)
                await self.check_now()
        except asyncio.CancelledError:  # pragma: no cover - shutdown path
            raise

    async def stop(self) -> None:
        """Flip readiness off first so load balancers drain before we exit."""
        self._set_ready(False)
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
