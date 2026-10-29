"""Authenticated endpoints scoped to the calling user: profile, password,
two-factor enrollment and session management."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Path, status

from authmesh.auth.v1 import auth_pb2
from authmesh_common.logging import get_logger

from ..clients import AuthClient
from ..deps import CallerMeta, Principal, current_principal, get_auth_client, get_caller
from ..schemas import (
    ChangePasswordRequest,
    ErrorResponse,
    LogoutAllRequest,
    RevocationResponse,
    SessionListResponse,
    SessionResponse,
    TotpActivateRequest,
    TotpDisableRequest,
    TotpEnrollResponse,
    TotpStatusResponse,
    UserResponse,
)
from .auth import to_user

log = get_logger("authmesh.gateway.account")

router = APIRouter(prefix="/me", tags=["account"])

AUTH_ERRORS = {
    401: {"model": ErrorResponse, "description": "Missing or invalid access token"},
    403: {"model": ErrorResponse, "description": "Not permitted"},
}


@router.get(
    "",
    response_model=UserResponse,
    summary="Current user profile",
    responses=AUTH_ERRORS,
)
async def get_profile(
    principal: Principal = Depends(current_principal),
    auth: AuthClient = Depends(get_auth_client),
) -> UserResponse:
    profile = await auth.get_profile(
        auth_pb2.GetProfileRequest(user_id=principal.user_id)
    )
    return to_user(profile)


@router.post(
    "/password",
    response_model=RevocationResponse,
    summary="Change password",
    description=(
        "Requires the current password. By default every other session is revoked, "
        "so a password change after a suspected compromise actually evicts the "
        "attacker; the response reports how many were ended."
    ),
    responses={
        422: {"model": ErrorResponse, "description": "New password policy not met"},
        **AUTH_ERRORS,
    },
)
async def change_password(
    payload: ChangePasswordRequest,
    principal: Principal = Depends(current_principal),
    auth: AuthClient = Depends(get_auth_client),
    caller: CallerMeta = Depends(get_caller),
) -> RevocationResponse:
    response = await auth.change_password(
        auth_pb2.ChangePasswordRequest(
            user_id=principal.user_id,
            current_password=payload.current_password,
            new_password=payload.new_password,
            keep_other_sessions=payload.keep_other_sessions,
            current_session_id=principal.session_id,
            ctx=caller.to_proto(),
        )
    )
    return RevocationResponse(sessions_revoked=response.sessions_revoked)


# -- two-factor authentication ---------------------------------------------


@router.post(
    "/2fa/enroll",
    response_model=TotpEnrollResponse,
    summary="Begin TOTP enrollment",
    description=(
        "Returns a shared secret, an otpauth:// URI for QR display, and single-use "
        "recovery codes. Two-factor authentication is not active until "
        "`/me/2fa/activate` confirms a generated code, so a misconfigured "
        "authenticator cannot lock the account out. The secret and recovery codes "
        "are shown exactly once."
    ),
    responses={
        409: {"model": ErrorResponse, "description": "Already enrolled"},
        **AUTH_ERRORS,
    },
)
async def enroll_totp(
    principal: Principal = Depends(current_principal),
    auth: AuthClient = Depends(get_auth_client),
) -> TotpEnrollResponse:
    response = await auth.enroll_totp(
        auth_pb2.EnrollTotpRequest(user_id=principal.user_id)
    )
    return TotpEnrollResponse(
        secret=response.secret,
        otpauth_uri=response.otpauth_uri,
        recovery_codes=list(response.recovery_codes),
    )


@router.post(
    "/2fa/activate",
    response_model=TotpStatusResponse,
    summary="Activate TOTP",
    responses=AUTH_ERRORS,
)
async def activate_totp(
    payload: TotpActivateRequest,
    principal: Principal = Depends(current_principal),
    auth: AuthClient = Depends(get_auth_client),
) -> TotpStatusResponse:
    response = await auth.activate_totp(
        auth_pb2.ActivateTotpRequest(
            user_id=principal.user_id, totp_code=payload.totp_code
        )
    )
    return TotpStatusResponse(
        totp_enabled=response.totp_enabled,
        recovery_codes_remaining=response.recovery_codes_remaining,
    )


@router.post(
    "/2fa/disable",
    response_model=TotpStatusResponse,
    summary="Disable TOTP",
    description="Requires the account password: removing a factor is a privileged action.",
    responses=AUTH_ERRORS,
)
async def disable_totp(
    payload: TotpDisableRequest,
    principal: Principal = Depends(current_principal),
    auth: AuthClient = Depends(get_auth_client),
) -> TotpStatusResponse:
    response = await auth.disable_totp(
        auth_pb2.DisableTotpRequest(
            user_id=principal.user_id, password=payload.password
        )
    )
    return TotpStatusResponse(
        totp_enabled=response.totp_enabled,
        recovery_codes_remaining=response.recovery_codes_remaining,
    )


# -- sessions ---------------------------------------------------------------


@router.get(
    "/sessions",
    response_model=SessionListResponse,
    summary="List active sessions",
    description="The session used for this request is flagged with `current: true`.",
    responses=AUTH_ERRORS,
)
async def list_sessions(
    principal: Principal = Depends(current_principal),
    auth: AuthClient = Depends(get_auth_client),
) -> SessionListResponse:
    response = await auth.list_sessions(
        auth_pb2.ListSessionsRequest(
            user_id=principal.user_id, current_session_id=principal.session_id
        )
    )
    return SessionListResponse(
        sessions=[
            SessionResponse(
                id=item.id,
                created_at=item.created_at,
                last_used_at=item.last_used_at,
                expires_at=item.expires_at,
                ip=item.ip,
                user_agent=item.user_agent,
                current=item.current,
            )
            for item in response.sessions
        ]
    )


@router.delete(
    "/sessions/{session_id}",
    response_model=RevocationResponse,
    summary="Revoke one session",
    description=(
        "Takes effect immediately: access tokens carrying this session id stop "
        "validating even though they have not expired."
    ),
    responses={
        404: {"model": ErrorResponse, "description": "No such session for this user"},
        **AUTH_ERRORS,
    },
)
async def revoke_session(
    session_id: str = Path(min_length=1, max_length=64),
    principal: Principal = Depends(current_principal),
    auth: AuthClient = Depends(get_auth_client),
) -> RevocationResponse:
    response = await auth.revoke_session(
        auth_pb2.RevokeSessionRequest(
            user_id=principal.user_id, session_id=session_id
        )
    )
    return RevocationResponse(sessions_revoked=response.sessions_revoked)


@router.post(
    "/sessions/revoke-all",
    response_model=RevocationResponse,
    status_code=status.HTTP_200_OK,
    summary="Sign out everywhere",
    responses=AUTH_ERRORS,
)
async def revoke_all_sessions(
    payload: LogoutAllRequest,
    principal: Principal = Depends(current_principal),
    auth: AuthClient = Depends(get_auth_client),
) -> RevocationResponse:
    response = await auth.logout_all(
        auth_pb2.LogoutAllRequest(
            user_id=principal.user_id,
            except_session_id=principal.session_id
            if payload.keep_current_session
            else "",
        )
    )
    return RevocationResponse(sessions_revoked=response.sessions_revoked)
