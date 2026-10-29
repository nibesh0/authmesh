"""Probe and scrape endpoints.

`/healthz` answers "is this process alive" and must not touch dependencies: if it
did, an auth-service blip would make Kubernetes restart healthy gateway pods.
`/readyz` answers "can this pod serve traffic" and does check the downstream
channel, so a gateway that cannot reach the auth-service is removed from the
Service endpoints while it recovers.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, Response, status

from authmesh_common import metrics

from ..schemas import HealthResponse

router = APIRouter(tags=["operations"], include_in_schema=False)


@router.get("/healthz", response_model=HealthResponse)
async def healthz(request: Request) -> HealthResponse:
    settings = request.app.state.settings
    return HealthResponse(
        status="ok", service=settings.service_name, version=settings.version
    )


@router.get("/readyz")
async def readyz(request: Request) -> Response:
    state = request.app.state
    ready = bool(getattr(state, "ready", False)) and await state.auth_client.ping()
    metrics.READINESS.set(1 if ready else 0)
    metrics.observe_dependencies([("auth-service", ready)])

    if not ready:
        return Response(
            content='{"status":"not_ready","dependencies":{"auth-service":false}}',
            media_type="application/json",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return Response(
        content='{"status":"ready","dependencies":{"auth-service":true}}',
        media_type="application/json",
        status_code=status.HTTP_200_OK,
    )


@router.get("/metrics")
async def prometheus_metrics() -> Response:
    return Response(content=metrics.render(), media_type=metrics.CONTENT_TYPE_LATEST)
