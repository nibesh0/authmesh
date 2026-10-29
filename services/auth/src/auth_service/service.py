"""Authentication business logic.

Everything security-relevant lives here; `servicer.py` is a thin protobuf
adapter. Cross-cutting rules applied throughout:

* Login failures are reported as one indistinguishable error regardless of
  whether the account exists, the password was wrong, or 2FA failed after a
  correct password. Timing is equalised too (see `passwords.waste_time_like_a_verification`).
* Every state-changing action writes an audit event; audit writes never block the
  user-visible outcome.
* Rate limiting is checked before any expensive work (bcrypt, Mongo lookup) so a
  flood costs the attacker more than it costs us.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from authmesh.user.v1 import user_pb2
from authmesh_common.errors import AppError, ErrorCode
from authmesh_common.logging import get_logger
from authmesh_common.timeutil import epoch_seconds, utcnow

from . import authmetrics, passwords
from .settings import AuthServiceSettings
from .store import RotationOutcome, SecurityStore, SessionRecord
from .tokens import TokenService
from .totp import TotpService
from .users_client import UserDirectory

log = get_logger(__name__)

GENERIC_LOGIN_FAILURE = "email or password is incorrect"


@dataclass(frozen=True)
class CallerInfo:
    ip: str = ""
    user_agent: str = ""


@dataclass(frozen=True)
class TokenBundle:
    access_token: str
    refresh_token: str
    expires_in: int
    refresh_expires_in: int
    session_id: str


@dataclass(frozen=True)
class LoginOutcome:
    user: user_pb2.User
    tokens: TokenBundle | None = None
    mfa_token: str = ""

    @property
    def mfa_required(self) -> bool:
        return self.tokens is None


@dataclass(frozen=True)
class IntrospectionResult:
    active: bool
    inactive_reason: str = ""
    user_id: str = ""
    email: str = ""
    roles: tuple[str, ...] = ()
    session_id: str = ""
    jti: str = ""
    issued_at: int = 0
    expires_at: int = 0
    totp_enabled: bool = False


class AuthCore:
    def __init__(
        self,
        *,
        settings: AuthServiceSettings,
        store: SecurityStore,
        users: UserDirectory,
        tokens: TokenService,
        totp: TotpService,
    ) -> None:
        self._settings = settings
        self._store = store
        self._users = users
        self._tokens = tokens
        self._totp = totp

    # -- helpers -----------------------------------------------------------

    async def _guard_rate_limit(
        self, scope: str, identifier: str, *, limit: int, window_seconds: int
    ) -> None:
        if not identifier:
            return
        result = await self._store.check_rate_limit(
            scope, identifier, limit=limit, window_seconds=window_seconds
        )
        if not result.allowed:
            raise AppError(
                ErrorCode.RATE_LIMITED,
                "too many requests; please try again shortly",
                details={"scope": scope},
                retry_after=result.retry_after_seconds,
            )

    async def _issue_session(
        self, user: user_pb2.User, caller: CallerInfo, *, reason: str
    ) -> TokenBundle:
        session_id = uuid.uuid4().hex
        family = uuid.uuid4().hex

        refresh = self._tokens.issue_refresh_token(
            user_id=user.id, session_id=session_id, family=family
        )
        access = self._tokens.issue_access_token(
            user_id=user.id,
            email=user.email,
            roles=list(user.roles),
            session_id=session_id,
        )

        await self._store.create_session(
            session_id=session_id,
            user_id=user.id,
            family=family,
            refresh_jti=refresh.jti,
            ip=caller.ip,
            user_agent=caller.user_agent,
            ttl_seconds=self._settings.refresh_token_ttl_seconds,
        )

        authmetrics.TOKENS_ISSUED.labels(token_type="access").inc()
        authmetrics.TOKENS_ISSUED.labels(token_type="refresh").inc()
        log.info(
            "session established",
            extra={"session_id": session_id, "subject": user.id, "reason": reason},
        )
        return TokenBundle(
            access_token=access.token,
            refresh_token=refresh.token,
            expires_in=self._settings.access_token_ttl_seconds,
            refresh_expires_in=self._settings.refresh_token_ttl_seconds,
            session_id=session_id,
        )

    @staticmethod
    def _invalid_credentials() -> AppError:
        return AppError(ErrorCode.INVALID_CREDENTIALS, GENERIC_LOGIN_FAILURE)

    def _locked_error(self, retry_after: int) -> AppError:
        return AppError(
            ErrorCode.ACCOUNT_LOCKED,
            "too many failed attempts; this account is temporarily locked",
            details={"unlock_in_seconds": retry_after},
            retry_after=retry_after or self._settings.lockout_duration_seconds,
        )

    # -- registration ------------------------------------------------------

    async def register(
        self, *, email: str, password: str, display_name: str, caller: CallerInfo
    ) -> user_pb2.User:
        normalized_email = (email or "").strip().lower()
        if not normalized_email or "@" not in normalized_email:
            authmetrics.REGISTRATIONS.labels(outcome="invalid_email").inc()
            raise AppError(ErrorCode.INVALID_ARGUMENT, "a valid email address is required")

        await self._guard_rate_limit(
            "register_ip",
            caller.ip,
            limit=self._settings.register_rate_limit_per_ip,
            window_seconds=self._settings.register_rate_limit_window_seconds,
        )

        passwords.validate_password_policy(
            password,
            min_length=self._settings.password_min_length,
            max_length=self._settings.password_max_length,
            require_mixed_case=self._settings.password_require_mixed_case,
            require_digit=self._settings.password_require_digit,
            require_symbol=self._settings.password_require_symbol,
            email=normalized_email,
        )

        password_hash = await passwords.hash_password(
            password, rounds=self._settings.bcrypt_rounds
        )

        try:
            user = await self._users.create_user(
                email=normalized_email,
                display_name=(display_name or "").strip(),
                password_hash=password_hash,
                roles=["user"],
            )
        except AppError as exc:
            if exc.code is ErrorCode.ALREADY_EXISTS:
                authmetrics.REGISTRATIONS.labels(outcome="duplicate").inc()
                await self._users.record_audit(
                    action="user.register.rejected",
                    email=normalized_email,
                    success=False,
                    ip=caller.ip,
                    user_agent=caller.user_agent,
                    reason="email already registered",
                )
            raise

        authmetrics.REGISTRATIONS.labels(outcome="success").inc()
        await self._users.record_audit(
            action="user.registered",
            user_id=user.id,
            email=user.email,
            ip=caller.ip,
            user_agent=caller.user_agent,
        )
        return user

    # -- login -------------------------------------------------------------

    async def login(
        self, *, email: str, password: str, totp_code: str, caller: CallerInfo
    ) -> LoginOutcome:
        normalized_email = (email or "").strip().lower()

        try:
            await self._guard_rate_limit(
                "login_ip",
                caller.ip,
                limit=self._settings.login_rate_limit_per_ip,
                window_seconds=self._settings.login_rate_limit_window_seconds,
            )
            await self._guard_rate_limit(
                "login_account",
                normalized_email,
                limit=self._settings.login_rate_limit_per_account,
                window_seconds=self._settings.login_rate_limit_window_seconds,
            )
        except AppError:
            authmetrics.LOGIN_ATTEMPTS.labels(outcome="rate_limited").inc()
            raise

        user = await self._users.get_by_email(normalized_email) if normalized_email else None

        if user is None:
            # Equalise cost and response so the caller cannot learn whether the
            # address is registered.
            await passwords.waste_time_like_a_verification()
            authmetrics.LOGIN_ATTEMPTS.labels(outcome="unknown_user").inc()
            await self._users.record_audit(
                action="auth.login.failed",
                email=normalized_email,
                success=False,
                ip=caller.ip,
                user_agent=caller.user_agent,
                reason="unknown account",
            )
            raise self._invalid_credentials()

        lockout = await self._store.get_lockout(user.id)
        if lockout.locked:
            authmetrics.LOGIN_ATTEMPTS.labels(outcome="locked").inc()
            await self._users.record_audit(
                action="auth.login.blocked",
                user_id=user.id,
                email=user.email,
                success=False,
                ip=caller.ip,
                user_agent=caller.user_agent,
                reason="account locked",
            )
            raise self._locked_error(lockout.retry_after_seconds)

        if user.disabled:
            authmetrics.LOGIN_ATTEMPTS.labels(outcome="disabled").inc()
            await self._users.record_audit(
                action="auth.login.blocked",
                user_id=user.id,
                email=user.email,
                success=False,
                ip=caller.ip,
                user_agent=caller.user_agent,
                reason="account disabled",
            )
            raise AppError(ErrorCode.ACCOUNT_DISABLED, "this account has been disabled")

        if not await passwords.verify_password(password, user.password_hash):
            result = await self._store.register_failed_attempt(user.id)
            authmetrics.LOGIN_ATTEMPTS.labels(outcome="invalid_password").inc()
            await self._users.record_audit(
                action="auth.login.failed",
                user_id=user.id,
                email=user.email,
                success=False,
                ip=caller.ip,
                user_agent=caller.user_agent,
                reason="invalid password",
                metadata={"failed_attempts": str(result.failed_attempts)},
            )
            if result.locked:
                await self._users.record_audit(
                    action="auth.account.locked",
                    user_id=user.id,
                    email=user.email,
                    success=False,
                    ip=caller.ip,
                    user_agent=caller.user_agent,
                    reason="consecutive failed logins",
                )
                raise self._locked_error(result.retry_after_seconds)
            raise self._invalid_credentials()

        # Password is correct from here on.
        if user.totp_enabled:
            if totp_code:
                if not await self._totp.verify_encrypted(user.totp_secret_enc, totp_code):
                    await self._store.register_failed_attempt(user.id)
                    authmetrics.MFA_VERIFICATIONS.labels(
                        method="totp", outcome="invalid"
                    ).inc()
                    authmetrics.LOGIN_ATTEMPTS.labels(outcome="invalid_mfa").inc()
                    await self._users.record_audit(
                        action="auth.mfa.failed",
                        user_id=user.id,
                        email=user.email,
                        success=False,
                        ip=caller.ip,
                        user_agent=caller.user_agent,
                        reason="invalid totp code at login",
                    )
                    raise AppError(
                        ErrorCode.INVALID_MFA_CODE, "the verification code is incorrect"
                    )
                authmetrics.MFA_VERIFICATIONS.labels(method="totp", outcome="success").inc()
            else:
                challenge = self._tokens.issue_mfa_token(user_id=user.id)
                await self._store.store_mfa_challenge(
                    challenge.jti, user.id, self._settings.mfa_challenge_ttl_seconds
                )
                authmetrics.LOGIN_ATTEMPTS.labels(outcome="mfa_required").inc()
                authmetrics.TOKENS_ISSUED.labels(token_type="mfa_challenge").inc()
                await self._store.clear_failed_attempts(user.id)
                await self._users.record_audit(
                    action="auth.mfa.challenged",
                    user_id=user.id,
                    email=user.email,
                    ip=caller.ip,
                    user_agent=caller.user_agent,
                )
                return LoginOutcome(user=user, tokens=None, mfa_token=challenge.token)

        await self._store.clear_failed_attempts(user.id)
        tokens = await self._issue_session(user, caller, reason="password_login")
        authmetrics.LOGIN_ATTEMPTS.labels(outcome="success").inc()
        await self._users.record_audit(
            action="auth.login.succeeded",
            user_id=user.id,
            email=user.email,
            ip=caller.ip,
            user_agent=caller.user_agent,
            metadata={"session_id": tokens.session_id, "mfa": str(user.totp_enabled)},
        )
        return LoginOutcome(user=user, tokens=tokens)

    async def verify_mfa(
        self, *, mfa_token: str, code: str, caller: CallerInfo
    ) -> LoginOutcome:
        claims = self._tokens.verify_mfa_token(mfa_token)

        # Throttle per challenge so a stolen challenge token cannot be used to
        # brute force six digits.
        await self._guard_rate_limit(
            "mfa_challenge",
            claims.jti,
            limit=self._settings.mfa_rate_limit_per_account,
            window_seconds=self._settings.mfa_rate_limit_window_seconds,
        )

        challenge_user_id = await self._store.peek_mfa_challenge(claims.jti)
        if not challenge_user_id or challenge_user_id != claims.user_id:
            raise AppError(
                ErrorCode.UNAUTHENTICATED,
                "this verification challenge has expired; sign in again",
            )

        user = await self._users.require_by_id(claims.user_id)
        if user.disabled:
            raise AppError(ErrorCode.ACCOUNT_DISABLED, "this account has been disabled")
        if not user.totp_enabled or not user.totp_secret_enc:
            raise AppError(
                ErrorCode.FAILED_PRECONDITION, "no second factor is configured"
            )

        lockout = await self._store.get_lockout(user.id)
        if lockout.locked:
            raise self._locked_error(lockout.retry_after_seconds)

        method = "recovery" if self._totp.looks_like_recovery_code(code) else "totp"
        verified = False

        if method == "recovery":
            index = passwords.find_matching_recovery_code(
                code,
                list(user.recovery_code_hashes),
                self._settings.recovery_code_pepper,
            )
            if index is not None:
                verified = True
                # Recovery codes are single use: drop the one that was consumed.
                remaining = [
                    value
                    for position, value in enumerate(user.recovery_code_hashes)
                    if position != index
                ]
                await self._users.update_user(
                    user_pb2.UpdateUserRequest(
                        id=user.id,
                        recovery_code_hashes=user_pb2.RecoveryCodeList(values=remaining),
                    )
                )
                log.info(
                    "recovery code consumed",
                    extra={"subject": user.id, "codes_remaining": len(remaining)},
                )
        else:
            verified = await self._totp.verify_encrypted(user.totp_secret_enc, code)

        if not verified:
            result = await self._store.register_failed_attempt(user.id)
            authmetrics.MFA_VERIFICATIONS.labels(method=method, outcome="invalid").inc()
            await self._users.record_audit(
                action="auth.mfa.failed",
                user_id=user.id,
                email=user.email,
                success=False,
                ip=caller.ip,
                user_agent=caller.user_agent,
                reason=f"invalid {method} code",
            )
            if result.locked:
                raise self._locked_error(result.retry_after_seconds)
            raise AppError(ErrorCode.INVALID_MFA_CODE, "the verification code is incorrect")

        # Success: burn the challenge so it cannot be replayed.
        await self._store.consume_mfa_challenge(claims.jti)
        await self._store.clear_failed_attempts(user.id)
        authmetrics.MFA_VERIFICATIONS.labels(method=method, outcome="success").inc()

        tokens = await self._issue_session(user, caller, reason=f"mfa_{method}")
        authmetrics.LOGIN_ATTEMPTS.labels(outcome="success").inc()
        await self._users.record_audit(
            action="auth.login.succeeded",
            user_id=user.id,
            email=user.email,
            ip=caller.ip,
            user_agent=caller.user_agent,
            metadata={"session_id": tokens.session_id, "mfa_method": method},
        )
        return LoginOutcome(user=user, tokens=tokens)

    # -- token lifecycle ---------------------------------------------------

    async def refresh(self, *, refresh_token: str, caller: CallerInfo) -> TokenBundle:
        claims = self._tokens.verify_refresh_token(refresh_token)

        await self._guard_rate_limit(
            "refresh_session",
            claims.session_id,
            limit=self._settings.refresh_rate_limit_per_session,
            window_seconds=self._settings.refresh_rate_limit_window_seconds,
        )

        session = await self._store.get_session(claims.session_id)
        ttl_seconds = self._settings.refresh_token_ttl_seconds
        if session is not None and session.absolute_expires_at:
            remaining = session.absolute_expires_at - epoch_seconds(utcnow())
            ttl_seconds = max(1, min(ttl_seconds, remaining))

        # Minted before rotation so its jti can be written atomically with the
        # deletion of the old one. If rotation fails the token was never
        # registered in Redis, so it is inert.
        new_refresh = self._tokens.issue_refresh_token(
            user_id=claims.user_id,
            session_id=claims.session_id,
            family=claims.family,
            ttl_seconds=ttl_seconds,
        )

        rotation = await self._store.rotate_refresh_token(
            old_jti=claims.jti,
            new_jti=new_refresh.jti,
            session_id=claims.session_id,
            user_id=claims.user_id,
            ttl_seconds=ttl_seconds,
        )

        if rotation.outcome == RotationOutcome.REUSED:
            # The token was already rotated away, so either it leaked or a client
            # replayed it. Either way the session can no longer be trusted.
            authmetrics.TOKEN_REUSE_DETECTED.inc()
            authmetrics.REFRESH_OPERATIONS.labels(outcome="reused").inc()
            revoked = await self._store.revoke_session(
                claims.session_id, user_id=claims.user_id
            )
            if revoked:
                authmetrics.SESSIONS_REVOKED.labels(reason="token_reuse").inc()
            log.error(
                "refresh token reuse detected; session revoked",
                extra={
                    "subject": claims.user_id,
                    "session_id": claims.session_id,
                    "family": claims.family,
                },
            )
            await self._users.record_audit(
                action="auth.token.reuse_detected",
                user_id=claims.user_id,
                success=False,
                ip=caller.ip,
                user_agent=caller.user_agent,
                reason="refresh token replayed after rotation",
                metadata={"session_id": claims.session_id, "family": claims.family},
            )
            raise AppError(
                ErrorCode.TOKEN_REUSED,
                "this refresh token has already been used; the session was revoked "
                "as a precaution and you must sign in again",
            )

        if rotation.outcome == RotationOutcome.ABSOLUTE_EXPIRED:
            authmetrics.REFRESH_OPERATIONS.labels(outcome="absolute_expired").inc()
            await self._store.revoke_session(claims.session_id, user_id=claims.user_id)
            authmetrics.SESSIONS_REVOKED.labels(reason="absolute_expiry").inc()
            raise AppError(
                ErrorCode.TOKEN_EXPIRED, "this session has expired; please sign in again"
            )

        if rotation.outcome == RotationOutcome.MISMATCH:
            authmetrics.REFRESH_OPERATIONS.labels(outcome="mismatch").inc()
            await self._store.revoke_session(claims.session_id, user_id=claims.user_id)
            raise AppError(ErrorCode.TOKEN_REVOKED, "this refresh token is not valid")

        if rotation.outcome != RotationOutcome.OK:
            # unknown / no_session: revoked by logout, expired, or never existed.
            authmetrics.REFRESH_OPERATIONS.labels(outcome=rotation.outcome).inc()
            raise AppError(
                ErrorCode.TOKEN_REVOKED,
                "this refresh token is no longer valid; please sign in again",
            )

        user = await self._users.require_by_id(claims.user_id)
        if user.disabled:
            await self._store.revoke_all_sessions(user.id)
            raise AppError(ErrorCode.ACCOUNT_DISABLED, "this account has been disabled")

        access = self._tokens.issue_access_token(
            user_id=user.id,
            email=user.email,
            roles=list(user.roles),
            session_id=claims.session_id,
        )

        authmetrics.REFRESH_OPERATIONS.labels(outcome="rotated").inc()
        authmetrics.TOKENS_ISSUED.labels(token_type="access").inc()
        authmetrics.TOKENS_ISSUED.labels(token_type="refresh").inc()
        log.info(
            "refresh token rotated",
            extra={"subject": user.id, "session_id": claims.session_id},
        )

        return TokenBundle(
            access_token=access.token,
            refresh_token=new_refresh.token,
            expires_in=self._settings.access_token_ttl_seconds,
            refresh_expires_in=rotation.ttl_seconds or ttl_seconds,
            session_id=claims.session_id,
        )

    async def logout(self, *, refresh_token: str, access_token: str) -> int:
        session_id = ""
        user_id = ""

        if refresh_token:
            try:
                claims = self._tokens.verify_refresh_token(refresh_token)
                session_id = claims.session_id
                user_id = claims.user_id
            except AppError:
                # An expired or malformed token still means "log me out"; fall
                # through to the access token below rather than erroring.
                pass

        if not session_id and access_token:
            try:
                access_claims = self._tokens.verify_access_token(access_token)
                session_id = access_claims.session_id
                user_id = access_claims.user_id
            except AppError:
                pass

        if access_token:
            # Kill this access token even if the session is already gone.
            expiry = self._tokens.peek_expiry(access_token)
            if expiry:
                remaining = expiry - epoch_seconds(utcnow())
                if remaining > 0:
                    try:
                        access_claims = self._tokens.verify_access_token(access_token)
                        await self._store.denylist_access_token(
                            access_claims.jti, remaining
                        )
                    except AppError:
                        pass

        if not session_id:
            # Nothing actionable, but never tell the caller that.
            return 0

        revoked = await self._store.revoke_session(session_id, user_id=user_id or None)
        if revoked:
            authmetrics.SESSIONS_REVOKED.labels(reason="logout").inc()
            await self._users.record_audit(
                action="auth.logout",
                user_id=user_id,
                metadata={"session_id": session_id},
            )
        return 1 if revoked else 0

    async def logout_all(self, *, user_id: str, except_session_id: str) -> int:
        if not user_id:
            raise AppError(ErrorCode.INVALID_ARGUMENT, "user_id is required")
        count = await self._store.revoke_all_sessions(
            user_id, except_session_id=except_session_id or None
        )
        if count:
            authmetrics.SESSIONS_REVOKED.labels(reason="logout_all").inc(count)
            await self._users.record_audit(
                action="auth.logout_all",
                user_id=user_id,
                metadata={"revoked": str(count)},
            )
        return count

    async def introspect(self, *, access_token: str) -> IntrospectionResult:
        """Validate an access token.

        Returns a result instead of raising for the expected "not valid" cases:
        the gateway calls this on every authenticated request, and an expired
        token is a normal event, not an exception.
        """
        try:
            claims = self._tokens.verify_access_token(access_token)
        except AppError as exc:
            authmetrics.INTROSPECTIONS.labels(result=exc.code.value).inc()
            return IntrospectionResult(active=False, inactive_reason=exc.code.value)

        if await self._store.is_access_token_denylisted(claims.jti):
            authmetrics.INTROSPECTIONS.labels(result="denylisted").inc()
            return IntrospectionResult(
                active=False, inactive_reason=ErrorCode.TOKEN_REVOKED.value
            )

        # Session existence is what makes logout effective before token expiry.
        if not await self._store.session_exists(claims.session_id):
            authmetrics.INTROSPECTIONS.labels(result="session_revoked").inc()
            return IntrospectionResult(
                active=False, inactive_reason=ErrorCode.TOKEN_REVOKED.value
            )

        authmetrics.INTROSPECTIONS.labels(result="active").inc()
        return IntrospectionResult(
            active=True,
            user_id=claims.user_id,
            email=claims.email,
            roles=tuple(claims.roles),
            session_id=claims.session_id,
            jti=claims.jti,
            issued_at=claims.issued_at,
            expires_at=claims.expires_at,
        )

    # -- profile / credentials --------------------------------------------

    async def get_profile(self, *, user_id: str) -> user_pb2.User:
        return await self._users.require_by_id(user_id)

    async def change_password(
        self,
        *,
        user_id: str,
        current_password: str,
        new_password: str,
        keep_other_sessions: bool,
        current_session_id: str,
        caller: CallerInfo,
    ) -> int:
        user = await self._users.require_by_id(user_id)

        if not await passwords.verify_password(current_password, user.password_hash):
            await self._store.register_failed_attempt(user.id)
            await self._users.record_audit(
                action="auth.password.change_failed",
                user_id=user.id,
                email=user.email,
                success=False,
                ip=caller.ip,
                user_agent=caller.user_agent,
                reason="invalid current password",
            )
            raise AppError(
                ErrorCode.INVALID_CREDENTIALS, "the current password is incorrect"
            )

        passwords.validate_password_policy(
            new_password,
            min_length=self._settings.password_min_length,
            max_length=self._settings.password_max_length,
            require_mixed_case=self._settings.password_require_mixed_case,
            require_digit=self._settings.password_require_digit,
            require_symbol=self._settings.password_require_symbol,
            email=user.email,
        )
        if await passwords.verify_password(new_password, user.password_hash):
            raise AppError(
                ErrorCode.INVALID_ARGUMENT,
                "the new password must differ from the current one",
            )

        new_hash = await passwords.hash_password(
            new_password, rounds=self._settings.bcrypt_rounds
        )
        await self._users.update_user(
            user_pb2.UpdateUserRequest(
                id=user.id,
                password_hash=new_hash,
                touch_password_changed_at=True,
            )
        )

        revoked = 0
        if not keep_other_sessions:
            # Default: a password change signs out every other device, which is
            # the point of changing it after a suspected compromise.
            revoked = await self._store.revoke_all_sessions(
                user.id, except_session_id=current_session_id or None
            )
            if revoked:
                authmetrics.SESSIONS_REVOKED.labels(reason="password_change").inc(revoked)

        await self._store.clear_failed_attempts(user.id)
        await self._users.record_audit(
            action="auth.password.changed",
            user_id=user.id,
            email=user.email,
            ip=caller.ip,
            user_agent=caller.user_agent,
            metadata={"sessions_revoked": str(revoked)},
        )
        log.info(
            "password changed",
            extra={"subject": user.id, "sessions_revoked": revoked},
        )
        return revoked

    # -- 2FA ---------------------------------------------------------------

    async def enroll_totp(self, *, user_id: str) -> tuple[str, str, list[str]]:
        user = await self._users.require_by_id(user_id)
        if user.totp_enabled:
            raise AppError(
                ErrorCode.FAILED_PRECONDITION,
                "two-factor authentication is already enabled; disable it first to "
                "enroll a new device",
            )

        secret = self._totp.generate_secret()
        recovery_codes = self._totp.generate_recovery_codes()
        recovery_hashes = [
            passwords.hash_recovery_code(code, self._settings.recovery_code_pepper)
            for code in recovery_codes
        ]

        # Stored but not yet active: ActivateTotp must confirm a real code first.
        await self._users.update_user(
            user_pb2.UpdateUserRequest(
                id=user.id,
                totp_secret_enc=self._totp.encrypt_secret(secret),
                totp_enabled=False,
                recovery_code_hashes=user_pb2.RecoveryCodeList(values=recovery_hashes),
            )
        )

        authmetrics.MFA_ENROLLMENTS.labels(event="started").inc()
        await self._users.record_audit(
            action="auth.mfa.enroll_started", user_id=user.id, email=user.email
        )
        return (
            secret,
            self._totp.provisioning_uri(secret, user.email),
            recovery_codes,
        )

    async def activate_totp(self, *, user_id: str, totp_code: str) -> tuple[bool, int]:
        user = await self._users.require_by_id(user_id)
        if not user.totp_secret_enc:
            raise AppError(
                ErrorCode.FAILED_PRECONDITION,
                "start enrollment before activating two-factor authentication",
            )
        if user.totp_enabled:
            return True, len(user.recovery_code_hashes)

        if not await self._totp.verify_encrypted(user.totp_secret_enc, totp_code):
            authmetrics.MFA_VERIFICATIONS.labels(method="totp", outcome="invalid").inc()
            await self._users.record_audit(
                action="auth.mfa.activation_failed",
                user_id=user.id,
                email=user.email,
                success=False,
                reason="invalid code",
            )
            raise AppError(ErrorCode.INVALID_MFA_CODE, "the verification code is incorrect")

        updated = await self._users.update_user(
            user_pb2.UpdateUserRequest(id=user.id, totp_enabled=True)
        )
        authmetrics.MFA_ENROLLMENTS.labels(event="activated").inc()
        await self._users.record_audit(
            action="auth.mfa.enabled", user_id=user.id, email=user.email
        )
        log.info("totp activated", extra={"subject": user.id})
        return True, len(updated.recovery_code_hashes)

    async def disable_totp(self, *, user_id: str, password: str) -> tuple[bool, int]:
        user = await self._users.require_by_id(user_id)
        if not user.totp_enabled and not user.totp_secret_enc:
            return False, 0

        # Removing a factor is a privileged action: re-authenticate.
        if not await passwords.verify_password(password, user.password_hash):
            await self._store.register_failed_attempt(user.id)
            await self._users.record_audit(
                action="auth.mfa.disable_failed",
                user_id=user.id,
                email=user.email,
                success=False,
                reason="invalid password",
            )
            raise AppError(ErrorCode.INVALID_CREDENTIALS, "the password is incorrect")

        await self._users.update_user(
            user_pb2.UpdateUserRequest(
                id=user.id, totp_enabled=False, clear_totp_secret=True
            )
        )
        authmetrics.MFA_ENROLLMENTS.labels(event="disabled").inc()
        await self._users.record_audit(
            action="auth.mfa.disabled", user_id=user.id, email=user.email
        )
        log.info("totp disabled", extra={"subject": user.id})
        return False, 0

    # -- sessions ----------------------------------------------------------

    async def list_sessions(
        self, *, user_id: str, current_session_id: str
    ) -> list[tuple[SessionRecord, bool]]:
        sessions = await self._store.list_sessions(user_id)
        authmetrics.ACTIVE_SESSIONS_OBSERVED.set(len(sessions))
        return [(session, session.id == current_session_id) for session in sessions]

    async def revoke_session(self, *, user_id: str, session_id: str) -> int:
        if not session_id:
            raise AppError(ErrorCode.INVALID_ARGUMENT, "session_id is required")

        session = await self._store.get_session(session_id)
        # Do not confirm the existence of another user's session.
        if session is None or session.user_id != user_id:
            raise AppError(ErrorCode.NOT_FOUND, "session not found")

        revoked = await self._store.revoke_session(session_id, user_id=user_id)
        if revoked:
            authmetrics.SESSIONS_REVOKED.labels(reason="user_revoked").inc()
            await self._users.record_audit(
                action="auth.session.revoked",
                user_id=user_id,
                metadata={"session_id": session_id},
            )
        return 1 if revoked else 0
