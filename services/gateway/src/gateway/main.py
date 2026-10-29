"""Entrypoint for the HTTP gateway."""

from __future__ import annotations

import uvicorn

from authmesh_common.logging import get_logger

from .app import create_app
from .settings import GatewaySettings

log = get_logger("authmesh.gateway.main")


def run() -> None:
    settings = GatewaySettings()
    app = create_app(settings)

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=settings.http_port,
        # Our own JSON logging is already installed; uvicorn's dictConfig would
        # replace the root handler and we would lose structured output.
        log_config=None,
        access_log=False,
        # Must exceed the readiness drain in the lifespan shutdown hook, and stay
        # below the pod's terminationGracePeriodSeconds.
        timeout_graceful_shutdown=int(settings.shutdown_grace_seconds),
        # Only meaningful behind a proxy; the client IP is derived from
        # X-Forwarded-For by our middleware using trusted_proxy_hops.
        proxy_headers=False,
        server_header=False,
        date_header=True,
    )


if __name__ == "__main__":
    run()
