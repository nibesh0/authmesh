"""gRPC adapter for `AuthCore`: protobuf in, protobuf out, no business rules."""

from __future__ import annotations

from datetime import datetime, timezone

import grpc

from authmesh.auth.v1 import auth_pb2, auth_pb2_grpc
from authmesh.user.v1 import user_pb2
from authmesh_common.context import set_user_id
from authmesh_common.errors import invalid_argument
from authmesh_common.logging import get_logger
from authmesh_common.timeutil import to_rfc3339

from .service import AuthCore, CallerInfo, TokenBundle
from .settings import AuthServiceSettings
from .store import SessionRecord

log = get_logger(__name__)

SERVICE_FULL_NAME = auth_pb2.DESCRIPTOR.services_by_name["AuthService"].full_name


def _caller(ctx: auth_pb2.CallerContext) -> CallerInfo:
    return CallerInfo(ip=ctx.ip or "", user_agent=ctx.user_agent or "")


def _profile(user: user_pb2.User) -> auth_pb2.UserProfile:
    return auth_pb2.UserProfile(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        roles=list(user.roles),
        totp_enabled=user.totp_enabled,
        disabled=user.disabled,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


def _token_pair(bundle: TokenBundle) -> auth_pb2.TokenPair:
    return auth_pb2.TokenPair(
        access_token=bundle.access_token,
        refresh_token=bundle.refresh_token,
        token_type="Bearer",
        expires_in=bundle.expires_in,
        refresh_expires_in=bundle.refresh_expires_in,
        session_id=bundle.session_id,
    )


def _epoch_to_rfc3339(value: int) -> str:
    if not value:
        return ""
    return to_rfc3339(datetime.fromtimestamp(value, tz=timezone.utc))


def _session(record: SessionRecord, current: bool) -> auth_pb2.Session:
    return auth_pb2.Session(
        id=record.id,
        created_at=_epoch_to_rfc3339(record.created_at),
        last_used_at=_epoch_to_rfc3339(record.last_used_at),
        expires_at=_epoch_to_rfc3339(record.expires_at),
        ip=record.ip,
        user_agent=record.user_agent,
        current=current,
    )


class AuthServicer(auth_pb2_grpc.AuthServiceServicer):
    def __init__(self, core: AuthCore, settings: AuthServiceSettings) -> None:
        self._core = core
        self._settings = settings

    # -- registration / login ---------------------------------------------

    async def Register(  # noqa: N802
        self, request: auth_pb2.RegisterRequest, context: grpc.aio.ServicerContext
    ) -> auth_pb2.RegisterResponse:
        user = await self._core.register(
            email=request.email,
            password=request.password,
            display_name=request.display_name,
            caller=_caller(request.ctx),
        )
        set_user_id(user.id)
        return auth_pb2.RegisterResponse(user=_profile(user))

    async def Login(  # noqa: N802
        self, request: auth_pb2.LoginRequest, context: grpc.aio.ServicerContext
    ) -> auth_pb2.LoginResponse:
        outcome = await self._core.login(
            email=request.email,
            password=request.password,
            totp_code=request.totp_code,
            caller=_caller(request.ctx),
        )
        set_user_id(outcome.user.id)
        if outcome.mfa_required:
            return auth_pb2.LoginResponse(
                mfa_required=True,
                mfa_token=outcome.mfa_token,
                user=_profile(outcome.user),
            )
        return auth_pb2.LoginResponse(
            mfa_required=False,
            tokens=_token_pair(outcome.tokens),
            user=_profile(outcome.user),
        )

    async def VerifyMfa(  # noqa: N802
        self, request: auth_pb2.VerifyMfaRequest, context: grpc.aio.ServicerContext
    ) -> auth_pb2.LoginResponse:
        if not request.mfa_token:
            raise invalid_argument("mfa_token is required")
        if not request.code:
            raise invalid_argument("code is required")

        outcome = await self._core.verify_mfa(
            mfa_token=request.mfa_token,
            code=request.code,
            caller=_caller(request.ctx),
        )
        set_user_id(outcome.user.id)
        return auth_pb2.LoginResponse(
            mfa_required=False,
            tokens=_token_pair(outcome.tokens),
            user=_profile(outcome.user),
        )

    # -- tokens ------------------------------------------------------------

    async def Refresh(  # noqa: N802
        self, request: auth_pb2.RefreshRequest, context: grpc.aio.ServicerContext
    ) -> auth_pb2.RefreshResponse:
        if not request.refresh_token:
            raise invalid_argument("refresh_token is required")
        bundle = await self._core.refresh(
            refresh_token=request.refresh_token, caller=_caller(request.ctx)
        )
        return auth_pb2.RefreshResponse(tokens=_token_pair(bundle))

    async def Logout(  # noqa: N802
        self, request: auth_pb2.LogoutRequest, context: grpc.aio.ServicerContext
    ) -> auth_pb2.RevocationResponse:
        if not request.refresh_token and not request.access_token:
            raise invalid_argument("refresh_token or access_token is required")
        revoked = await self._core.logout(
            refresh_token=request.refresh_token, access_token=request.access_token
        )
        return auth_pb2.RevocationResponse(sessions_revoked=revoked)

    async def LogoutAll(  # noqa: N802
        self, request: auth_pb2.LogoutAllRequest, context: grpc.aio.ServicerContext
    ) -> auth_pb2.RevocationResponse:
        set_user_id(request.user_id)
        revoked = await self._core.logout_all(
            user_id=request.user_id, except_session_id=request.except_session_id
        )
        return auth_pb2.RevocationResponse(sessions_revoked=revoked)

    async def Introspect(  # noqa: N802
        self, request: auth_pb2.IntrospectRequest, context: grpc.aio.ServicerContext
    ) -> auth_pb2.IntrospectResponse:
        result = await self._core.introspect(access_token=request.access_token)
        if not result.active:
            return auth_pb2.IntrospectResponse(
                active=False, inactive_reason=result.inactive_reason
            )
        set_user_id(result.user_id)
        return auth_pb2.IntrospectResponse(
            active=True,
            user_id=result.user_id,
            email=result.email,
            roles=list(result.roles),
            session_id=result.session_id,
            jti=result.jti,
            issued_at=result.issued_at,
            expires_at=result.expires_at,
            totp_enabled=result.totp_enabled,
        )

    # -- profile / credentials --------------------------------------------

    async def GetProfile(  # noqa: N802
        self, request: auth_pb2.GetProfileRequest, context: grpc.aio.ServicerContext
    ) -> auth_pb2.UserProfile:
        if not request.user_id:
            raise invalid_argument("user_id is required")
        set_user_id(request.user_id)
        user = await self._core.get_profile(user_id=request.user_id)
        return _profile(user)

    async def ChangePassword(  # noqa: N802
        self, request: auth_pb2.ChangePasswordRequest, context: grpc.aio.ServicerContext
    ) -> auth_pb2.RevocationResponse:
        if not request.user_id:
            raise invalid_argument("user_id is required")
        set_user_id(request.user_id)
        revoked = await self._core.change_password(
            user_id=request.user_id,
            current_password=request.current_password,
            new_password=request.new_password,
            keep_other_sessions=request.keep_other_sessions,
            current_session_id=request.current_session_id,
            caller=_caller(request.ctx),
        )
        return auth_pb2.RevocationResponse(sessions_revoked=revoked)

    # -- 2FA ---------------------------------------------------------------

    async def EnrollTotp(  # noqa: N802
        self, request: auth_pb2.EnrollTotpRequest, context: grpc.aio.ServicerContext
    ) -> auth_pb2.EnrollTotpResponse:
        if not request.user_id:
            raise invalid_argument("user_id is required")
        set_user_id(request.user_id)
        secret, uri, recovery_codes = await self._core.enroll_totp(
            user_id=request.user_id
        )
        return auth_pb2.EnrollTotpResponse(
            secret=secret, otpauth_uri=uri, recovery_codes=recovery_codes
        )

    async def ActivateTotp(  # noqa: N802
        self, request: auth_pb2.ActivateTotpRequest, context: grpc.aio.ServicerContext
    ) -> auth_pb2.TotpStatusResponse:
        if not request.user_id:
            raise invalid_argument("user_id is required")
        if not request.totp_code:
            raise invalid_argument("totp_code is required")
        set_user_id(request.user_id)
        enabled, remaining = await self._core.activate_totp(
            user_id=request.user_id, totp_code=request.totp_code
        )
        return auth_pb2.TotpStatusResponse(
            totp_enabled=enabled, recovery_codes_remaining=remaining
        )

    async def DisableTotp(  # noqa: N802
        self, request: auth_pb2.DisableTotpRequest, context: grpc.aio.ServicerContext
    ) -> auth_pb2.TotpStatusResponse:
        if not request.user_id:
            raise invalid_argument("user_id is required")
        if not request.password:
            raise invalid_argument("password is required to disable two-factor auth")
        set_user_id(request.user_id)
        enabled, remaining = await self._core.disable_totp(
            user_id=request.user_id, password=request.password
        )
        return auth_pb2.TotpStatusResponse(
            totp_enabled=enabled, recovery_codes_remaining=remaining
        )

    # -- sessions ----------------------------------------------------------

    async def ListSessions(  # noqa: N802
        self, request: auth_pb2.ListSessionsRequest, context: grpc.aio.ServicerContext
    ) -> auth_pb2.ListSessionsResponse:
        if not request.user_id:
            raise invalid_argument("user_id is required")
        set_user_id(request.user_id)
        sessions = await self._core.list_sessions(
            user_id=request.user_id, current_session_id=request.current_session_id
        )
        return auth_pb2.ListSessionsResponse(
            sessions=[_session(record, current) for record, current in sessions]
        )

    async def RevokeSession(  # noqa: N802
        self, request: auth_pb2.RevokeSessionRequest, context: grpc.aio.ServicerContext
    ) -> auth_pb2.RevocationResponse:
        if not request.user_id:
            raise invalid_argument("user_id is required")
        set_user_id(request.user_id)
        revoked = await self._core.revoke_session(
            user_id=request.user_id, session_id=request.session_id
        )
        return auth_pb2.RevocationResponse(sessions_revoked=revoked)
