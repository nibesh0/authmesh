"""Entrypoint for the authentication service."""

from __future__ import annotations

import asyncio

from authmesh.auth.v1 import auth_pb2_grpc
from authmesh_common.grpc_server import GrpcApp, bootstrap_logging
from authmesh_common.logging import get_logger

from .service import AuthCore
from .servicer import SERVICE_FULL_NAME, AuthServicer
from .settings import AuthServiceSettings
from .store import SecurityStore
from .tokens import TokenService
from .totp import TotpService
from .users_client import UserDirectory

log = get_logger("authmesh.auth.main")


async def main() -> None:
    settings = AuthServiceSettings()
    bootstrap_logging(settings)

    store = SecurityStore(settings)
    users = UserDirectory(settings)
    core = AuthCore(
        settings=settings,
        store=store,
        users=users,
        tokens=TokenService(settings),
        totp=TotpService(settings),
    )

    async def startup() -> None:
        await store.connect()
        await users.connect()

    async def shutdown() -> None:
        await users.close()
        await store.close()

    app = GrpcApp(
        settings=settings,
        port=settings.grpc_port,
        register=lambda server: auth_pb2_grpc.add_AuthServiceServicer_to_server(
            AuthServicer(core, settings), server
        ),
        service_names=[SERVICE_FULL_NAME],
        startup=startup,
        shutdown=shutdown,
        # Readiness requires both dependencies: without Redis the service cannot
        # validate sessions, and without the user-service it cannot read accounts.
        probes=[("redis", store.ping), ("user-service", users.ping)],
    )

    log.info(
        "starting auth-service",
        extra={
            "version": settings.version,
            "environment": settings.environment,
            "access_token_ttl": settings.access_token_ttl_seconds,
            "refresh_token_ttl": settings.refresh_token_ttl_seconds,
            "rate_limit_enabled": settings.rate_limit_enabled,
            "lockout_enabled": settings.lockout_enabled,
        },
    )
    await app.run()


def run() -> None:
    try:
        asyncio.run(main())
    except KeyboardInterrupt:  # pragma: no cover
        pass


if __name__ == "__main__":
    run()
