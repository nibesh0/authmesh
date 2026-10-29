"""FastAPI dependencies: bearer authentication and caller metadata.

The gateway holds no signing key and does no local JWT validation. It asks the
auth-service to introspect every bearer token, which means a revoked session stops
working immediately across the whole platform instead of remaining valid until the
access token's own expiry.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from authmesh.auth.v1 import auth_pb2
from authmesh_common.context import set_user_id
from authmesh_common.errors import AppError, ErrorCode

from .clients import AuthClient
from .middleware import client_ip
from .settings import GatewaySettings

# auto_error=False so a missing header produces our error envelope rather than
# Starlette's default `{"detail": "Not authenticated"}`.
bearer_scheme = HTTPBearer(auto_error=False, description="Access token")

# Introspection reasons that should be reported verbatim; anything else collapses
# into a generic unauthenticated response.
_REPORTABLE_REASONS = {
    ErrorCode.TOKEN_EXPIRED.value,
    ErrorCode.TOKEN_REVOKED.value,
    ErrorCode.TOKEN_REUSED.value,
}


@dataclass(frozen=True)
class Principal:
    user_id: str
    email: str
    roles: tuple[str, ...]
    session_id: str
    jti: str
    access_token: str

    def has_role(self, role: str) -> bool:
        return role in self.roles


def get_settings(request: Request) -> GatewaySettings:
    return request.app.state.settings


def get_auth_client(request: Request) -> AuthClient:
    return request.app.state.auth_client


@dataclass(frozen=True)
class CallerMeta:
    ip: str
    user_agent: str

    def to_proto(self) -> auth_pb2.CallerContext:
        return auth_pb2.CallerContext(ip=self.ip, user_agent=self.user_agent)


def get_caller(request: Request) -> CallerMeta:
    settings: GatewaySettings = request.app.state.settings
    return CallerMeta(
        ip=client_ip(request, settings.trusted_proxy_hops),
        user_agent=request.headers.get("user-agent", "")[:512],
    )


async def current_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    auth: AuthClient = Depends(get_auth_client),
) -> Principal:
    if credentials is None or not credentials.credentials:
        raise AppError(
            ErrorCode.UNAUTHENTICATED, "an Authorization: Bearer <token> header is required"
        )
    if credentials.scheme.lower() != "bearer":
        raise AppError(ErrorCode.UNAUTHENTICATED, "unsupported authorization scheme")

    token = credentials.credentials
    result = await auth.introspect(auth_pb2.IntrospectRequest(access_token=token))

    if not result.active:
        reason = result.inactive_reason or ErrorCode.UNAUTHENTICATED.value
        if reason in _REPORTABLE_REASONS:
            code = ErrorCode(reason)
            message = {
                ErrorCode.TOKEN_EXPIRED: "the access token has expired",
                ErrorCode.TOKEN_REVOKED: "this session is no longer valid",
                ErrorCode.TOKEN_REUSED: "this session was revoked",
            }[code]
            raise AppError(code, message)
        raise AppError(ErrorCode.UNAUTHENTICATED, "the access token is not valid")

    set_user_id(result.user_id)
    return Principal(
        user_id=result.user_id,
        email=result.email,
        roles=tuple(result.roles),
        session_id=result.session_id,
        jti=result.jti,
        access_token=token,
    )


def require_roles(*required: str):  # noqa: ANN201
    """Dependency factory for role-gated endpoints."""

    async def dependency(
        principal: Principal = Depends(current_principal),
    ) -> Principal:
        if not any(principal.has_role(role) for role in required):
            raise AppError(
                ErrorCode.PERMISSION_DENIED,
                "this operation requires additional privileges",
                details={"required_roles": list(required)},
            )
        return principal

    return dependency
