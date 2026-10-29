"""Entrypoint for the MongoDB-backed user-service."""

from __future__ import annotations

import asyncio

import grpc

from authmesh.user.v1 import user_pb2_grpc
from authmesh_common.grpc_server import GrpcApp, bootstrap_logging
from authmesh_common.logging import get_logger

from .repository import UserRepository
from .servicer import SERVICE_FULL_NAME, UserServicer
from .settings import UserServiceSettings

log = get_logger("authmesh.user.main")


async def main() -> None:
    settings = UserServiceSettings()
    bootstrap_logging(settings)

    repository = UserRepository(settings)

    async def startup() -> None:
        await repository.connect()
        if settings.ensure_indexes:
            # Best effort: a replica that loses the race to create indexes, or
            # starts while Mongo is still electing a primary, should come up and
            # let the readiness probe gate traffic instead of crash-looping.
            try:
                await repository.ensure_indexes()
            except Exception:
                log.exception("index creation failed; continuing without it")

    async def shutdown() -> None:
        await repository.close()

    app = GrpcApp(
        settings=settings,
        port=settings.grpc_port,
        register=lambda server: user_pb2_grpc.add_UserServiceServicer_to_server(
            UserServicer(repository, settings), server
        ),
        service_names=[SERVICE_FULL_NAME],
        startup=startup,
        shutdown=shutdown,
        probes=[("mongodb", repository.ping)],
    )

    log.info(
        "starting user-service",
        extra={"version": settings.version, "environment": settings.environment},
    )
    await app.run()


def run() -> None:
    try:
        asyncio.run(main())
    except KeyboardInterrupt:  # pragma: no cover - local dev convenience
        pass


if __name__ == "__main__":
    run()
