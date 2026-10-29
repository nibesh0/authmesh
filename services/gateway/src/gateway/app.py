"""FastAPI application factory."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from authmesh_common import metrics
from authmesh_common.logging import configure_logging, get_logger

from .clients import AuthClient
from .errors import register_exception_handlers
from .middleware import (
    BodySizeLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from .routes import account, auth, health
from .settings import GatewaySettings

log = get_logger("authmesh.gateway")

DESCRIPTION = """
HTTP/REST edge for the authmesh platform.

Everything below is served by the gateway and executed over gRPC by the
`auth-service` (credentials, tokens, sessions) and the `user-service`
(persistence). The gateway holds no signing key: it validates bearer tokens by
introspecting them, so a revoked session stops working immediately.

**Tokens** - `POST /auth/login` returns a short-lived access token and a
long-lived refresh token. Send the access token as `Authorization: Bearer <token>`.
When it expires, call `POST /auth/refresh`; the refresh token is rotated on every
use and replaying an old one revokes the session.

**Errors** - every failure returns
`{"error": {"code", "message", "request_id"}}`. Branch on `code`, not on the
message text.
"""

TAGS_METADATA = [
    {
        "name": "authentication",
        "description": "Registration, login, two-factor challenges and token lifecycle.",
    },
    {
        "name": "account",
        "description": "Operations on the calling user: profile, password, 2FA, sessions.",
    },
]


def create_app(settings: GatewaySettings | None = None) -> FastAPI:
    settings = settings or GatewaySettings()
    configure_logging(
        service=settings.service_name,
        level=settings.log_level,
        fmt=settings.log_format,
        environment=settings.environment,
        version=settings.version,
    )

    auth_client = AuthClient(settings)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        await auth_client.connect()
        application.state.ready = True
        metrics.set_build_info(
            settings.service_name, settings.version, settings.environment
        )
        log.info(
            "gateway started",
            extra={
                "http_port": settings.http_port,
                "auth_target": settings.auth_service_target,
                "docs": settings.docs_enabled,
            },
        )
        try:
            yield
        finally:
            # Fail readiness first, pause so the endpoint is withdrawn, then close
            # the channel. Without the pause, in-flight requests routed a moment
            # earlier would hit a closed channel.
            application.state.ready = False
            metrics.READINESS.set(0)
            await asyncio.sleep(min(settings.shutdown_grace_seconds, 3.0))
            await auth_client.close()
            log.info("gateway stopped")

    app = FastAPI(
        title="authmesh API",
        version=settings.version,
        description=DESCRIPTION,
        openapi_tags=TAGS_METADATA,
        lifespan=lifespan,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url="/redoc" if settings.docs_enabled else None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )

    app.state.settings = settings
    app.state.auth_client = auth_client
    app.state.ready = False

    # Middleware runs bottom-up on the request path: size limit rejects first,
    # then security headers wrap, then context/logging sees the final response.
    app.add_middleware(RequestContextMiddleware)
    if settings.security_headers_enabled:
        app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)

    if settings.cors_allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_allow_origins,
            allow_credentials=settings.cors_allow_credentials,
            allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
            allow_headers=["authorization", "content-type", "x-request-id"],
            max_age=600,
        )

    register_exception_handlers(app)

    app.include_router(health.router)
    app.include_router(auth.router, prefix=settings.api_prefix)
    app.include_router(account.router, prefix=settings.api_prefix)

    @app.get("/", include_in_schema=False)
    async def root() -> dict[str, str]:
        return {
            "service": settings.service_name,
            "version": settings.version,
            "docs": "/docs" if settings.docs_enabled else "disabled",
            "api": settings.api_prefix,
        }

    return app
