"""Unauthenticated authentication endpoints: register, login, 2FA challenge,
refresh, logout and token introspection."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response, status

from authmesh.auth.v1 import auth_pb2
from authmesh_common.logging import get_logger

from ..clients import AuthClient
from ..deps import CallerMeta, Principal, current_principal, get_auth_client, get_caller
from ..schemas import (
    ErrorResponse,
    IntrospectRequest,
    IntrospectResponse,
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    MfaVerifyRequest,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    TokenResponse,
    UserResponse,
)

log = get_logger("authmesh.gateway.auth")

router = APIRouter(prefix="/auth", tags=["authentication"])

COMMON_ERRORS = {
    400: {"model": ErrorResponse, "description": "Malformed request"},
    401: {"model": ErrorResponse, "description": "Authentication failed"},
    429: {"model": ErrorResponse, "description": "Rate limited"},
    503: {"model": ErrorResponse, "description": "A dependency is unavailable"},
}


def to_user(profile: auth_pb2.UserProfile) -> UserResponse:
    return UserResponse(
        id=profile.id,
        email=profile.email,
        display_name=profile.display_name,
        roles=list(profile.roles),
        totp_enabled=profile.totp_enabled,
        disabled=profile.disabled,
        created_at=profile.created_at,
        updated_at=profile.updated_at,
    )


def to_tokens(pair: auth_pb2.TokenPair) -> TokenResponse:
    return TokenResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        token_type="Bearer",
        expires_in=pair.expires_in,
        refresh_expires_in=pair.refresh_expires_in,
        session_id=pair.session_id,
    )


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an account",
    responses={
        409: {"model": ErrorResponse, "description": "Email already registered"},
        422: {"model": ErrorResponse, "description": "Password policy not met"},
        **COMMON_ERRORS,
    },
)
async def register(
    payload: RegisterRequest,
    auth: AuthClient = Depends(get_auth_client),
    caller: CallerMeta = Depends(get_caller),
) -> RegisterResponse:
    response = await auth.register(
        auth_pb2.RegisterRequest(
            email=str(payload.email),
            password=payload.password,
            display_name=payload.display_name,
            ctx=caller.to_proto(),
        )
    )
    return RegisterResponse(user=to_user(response.user))


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Exchange credentials for tokens",
    description=(
        "Returns an access/refresh token pair. If the account has two-factor "
        "authentication enabled and no `totp_code` was supplied, responds with "
        "`mfa_required: true` and an `mfa_token` to be exchanged at "
        "`/auth/mfa/verify`."
    ),
    responses={
        403: {"model": ErrorResponse, "description": "Account disabled"},
        423: {"model": ErrorResponse, "description": "Account temporarily locked"},
        **COMMON_ERRORS,
    },
)
async def login(
    payload: LoginRequest,
    auth: AuthClient = Depends(get_auth_client),
    caller: CallerMeta = Depends(get_caller),
) -> LoginResponse:
    response = await auth.login(
        auth_pb2.LoginRequest(
            email=str(payload.email),
            password=payload.password,
            totp_code=payload.totp_code or "",
            ctx=caller.to_proto(),
        )
    )
    if response.mfa_required:
        return LoginResponse(
            mfa_required=True,
            mfa_token=response.mfa_token,
            user=to_user(response.user),
        )
    return LoginResponse(
        mfa_required=False,
        tokens=to_tokens(response.tokens),
        user=to_user(response.user),
    )


@router.post(
    "/mfa/verify",
    response_model=LoginResponse,
    summary="Complete a two-factor challenge",
    description=(
        "Accepts either a TOTP code from the authenticator app or one of the "
        "recovery codes issued at enrollment. Recovery codes are single use."
    ),
    responses=COMMON_ERRORS,
)
async def verify_mfa(
    payload: MfaVerifyRequest,
    auth: AuthClient = Depends(get_auth_client),
    caller: CallerMeta = Depends(get_caller),
) -> LoginResponse:
    response = await auth.verify_mfa(
        auth_pb2.VerifyMfaRequest(
            mfa_token=payload.mfa_token,
            code=payload.code,
            ctx=caller.to_proto(),
        )
    )
    return LoginResponse(
        mfa_required=False,
        tokens=to_tokens(response.tokens),
        user=to_user(response.user),
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Rotate a refresh token",
    description=(
        "Returns a new access token and a new refresh token; the presented refresh "
        "token is invalidated. Presenting an already-rotated token is treated as a "
        "leak and revokes the entire session."
    ),
    responses=COMMON_ERRORS,
)
async def refresh(
    payload: RefreshRequest,
    auth: AuthClient = Depends(get_auth_client),
    caller: CallerMeta = Depends(get_caller),
) -> TokenResponse:
    response = await auth.refresh(
        auth_pb2.RefreshRequest(
            refresh_token=payload.refresh_token, ctx=caller.to_proto()
        )
    )
    return to_tokens(response.tokens)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="End the current session",
    description=(
        "Revokes the session and denylists the presented access token for its "
        "remaining lifetime. Idempotent: always returns 204."
    ),
)
async def logout(
    payload: LogoutRequest,
    principal: Principal = Depends(current_principal),
    auth: AuthClient = Depends(get_auth_client),
) -> Response:
    await auth.logout(
        auth_pb2.LogoutRequest(
            refresh_token=payload.refresh_token or "",
            access_token=principal.access_token,
        )
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/introspect",
    response_model=IntrospectResponse,
    summary="Validate an access token",
    description=(
        "Intended for other internal services. Reports whether a token is currently "
        "usable, taking revocation into account, and never raises for an invalid "
        "token."
    ),
)
async def introspect(
    payload: IntrospectRequest,
    auth: AuthClient = Depends(get_auth_client),
) -> IntrospectResponse:
    result = await auth.introspect(
        auth_pb2.IntrospectRequest(access_token=payload.access_token)
    )
    if not result.active:
        return IntrospectResponse(active=False, inactive_reason=result.inactive_reason)
    return IntrospectResponse(
        active=True,
        user_id=result.user_id,
        email=result.email,
        roles=list(result.roles),
        session_id=result.session_id,
        jti=result.jti,
        issued_at=result.issued_at,
        expires_at=result.expires_at,
    )
