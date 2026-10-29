"""JWT minting and verification.

Three token types, all signed with the same key but separated by a `typ` claim
that is checked on every decode. Without that check an attacker could present a
refresh token (long-lived, broad) where an access token is expected, or replay an
MFA challenge token as a credential.

Claims that matter downstream:
  sid - session id; lets logout revoke an access token before it expires, because
        Introspect also verifies the session still exists in Redis.
  jti - unique token id; the unit of denylisting and of refresh rotation.
  fam - refresh token family; a whole family is burned when reuse is detected.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

import jwt

from authmesh_common.errors import AppError, ErrorCode
from authmesh_common.timeutil import epoch_seconds, utcnow

from .settings import AuthServiceSettings

TYPE_ACCESS = "access"
TYPE_REFRESH = "refresh"
TYPE_MFA = "mfa"

# Tolerated clock skew between the signer and the verifier.
LEEWAY_SECONDS = 10


@dataclass(frozen=True)
class IssuedToken:
    token: str
    jti: str
    issued_at: datetime
    expires_at: datetime

    @property
    def ttl_seconds(self) -> int:
        return max(0, int((self.expires_at - self.issued_at).total_seconds()))


@dataclass(frozen=True)
class AccessClaims:
    user_id: str
    email: str
    roles: list[str]
    session_id: str
    jti: str
    issued_at: int
    expires_at: int


@dataclass(frozen=True)
class RefreshClaims:
    user_id: str
    session_id: str
    family: str
    jti: str
    issued_at: int
    expires_at: int


@dataclass(frozen=True)
class MfaClaims:
    user_id: str
    jti: str
    expires_at: int


class TokenService:
    def __init__(self, settings: AuthServiceSettings) -> None:
        self._settings = settings

    # -- issuing -----------------------------------------------------------

    def _encode(self, claims: dict[str, object]) -> str:
        return jwt.encode(
            claims,
            self._settings.jwt_secret,
            algorithm=self._settings.jwt_algorithm,
        )

    def _base_claims(self, subject: str, ttl_seconds: int, token_type: str) -> tuple[dict, str, datetime, datetime]:
        now = utcnow()
        expires_at = now + timedelta(seconds=ttl_seconds)
        jti = uuid.uuid4().hex
        claims: dict[str, object] = {
            "iss": self._settings.jwt_issuer,
            "aud": self._settings.jwt_audience,
            "sub": subject,
            "typ": token_type,
            "jti": jti,
            "iat": epoch_seconds(now),
            "nbf": epoch_seconds(now) - LEEWAY_SECONDS,
            "exp": epoch_seconds(expires_at),
        }
        return claims, jti, now, expires_at

    def issue_access_token(
        self,
        *,
        user_id: str,
        email: str,
        roles: list[str],
        session_id: str,
    ) -> IssuedToken:
        claims, jti, now, expires_at = self._base_claims(
            user_id, self._settings.access_token_ttl_seconds, TYPE_ACCESS
        )
        claims.update({"sid": session_id, "email": email, "roles": roles})
        return IssuedToken(self._encode(claims), jti, now, expires_at)

    def issue_refresh_token(
        self, *, user_id: str, session_id: str, family: str, ttl_seconds: int | None = None
    ) -> IssuedToken:
        claims, jti, now, expires_at = self._base_claims(
            user_id,
            ttl_seconds
            if ttl_seconds is not None
            else self._settings.refresh_token_ttl_seconds,
            TYPE_REFRESH,
        )
        claims.update({"sid": session_id, "fam": family})
        return IssuedToken(self._encode(claims), jti, now, expires_at)

    def issue_mfa_token(self, *, user_id: str) -> IssuedToken:
        claims, jti, now, expires_at = self._base_claims(
            user_id, self._settings.mfa_challenge_ttl_seconds, TYPE_MFA
        )
        return IssuedToken(self._encode(claims), jti, now, expires_at)

    # -- verifying ---------------------------------------------------------

    def _decode(self, token: str, expected_type: str) -> dict:
        if not token:
            raise AppError(ErrorCode.UNAUTHENTICATED, "token is missing")

        secrets_to_try = [self._settings.jwt_secret]
        if self._settings.jwt_secret_previous:
            secrets_to_try.append(self._settings.jwt_secret_previous)

        last_error: Exception | None = None
        for secret in secrets_to_try:
            try:
                claims = jwt.decode(
                    token,
                    secret,
                    algorithms=[self._settings.jwt_algorithm],
                    audience=self._settings.jwt_audience,
                    issuer=self._settings.jwt_issuer,
                    leeway=LEEWAY_SECONDS,
                    options={
                        "require": ["exp", "iat", "sub", "jti", "typ"],
                        "verify_exp": True,
                        "verify_aud": True,
                        "verify_iss": True,
                    },
                )
            except jwt.ExpiredSignatureError as exc:
                # Expiry is independent of which key signed it: fail immediately.
                raise AppError(ErrorCode.TOKEN_EXPIRED, "token has expired") from exc
            except jwt.InvalidTokenError as exc:
                last_error = exc
                continue

            actual_type = claims.get("typ")
            if actual_type != expected_type:
                raise AppError(
                    ErrorCode.UNAUTHENTICATED,
                    "token is not valid for this operation",
                    details={"expected_type": expected_type, "actual_type": actual_type},
                )
            return claims

        raise AppError(ErrorCode.UNAUTHENTICATED, "token is invalid") from last_error

    def verify_access_token(self, token: str) -> AccessClaims:
        claims = self._decode(token, TYPE_ACCESS)
        session_id = claims.get("sid")
        if not session_id:
            raise AppError(ErrorCode.UNAUTHENTICATED, "token is missing a session")
        roles = claims.get("roles") or []
        return AccessClaims(
            user_id=str(claims["sub"]),
            email=str(claims.get("email", "")),
            roles=[str(role) for role in roles],
            session_id=str(session_id),
            jti=str(claims["jti"]),
            issued_at=int(claims["iat"]),
            expires_at=int(claims["exp"]),
        )

    def verify_refresh_token(self, token: str) -> RefreshClaims:
        claims = self._decode(token, TYPE_REFRESH)
        session_id = claims.get("sid")
        family = claims.get("fam")
        if not session_id or not family:
            raise AppError(ErrorCode.UNAUTHENTICATED, "refresh token is malformed")
        return RefreshClaims(
            user_id=str(claims["sub"]),
            session_id=str(session_id),
            family=str(family),
            jti=str(claims["jti"]),
            issued_at=int(claims["iat"]),
            expires_at=int(claims["exp"]),
        )

    def verify_mfa_token(self, token: str) -> MfaClaims:
        claims = self._decode(token, TYPE_MFA)
        return MfaClaims(
            user_id=str(claims["sub"]),
            jti=str(claims["jti"]),
            expires_at=int(claims["exp"]),
        )

    @staticmethod
    def peek_expiry(token: str) -> int | None:
        """Read `exp` without verifying, to size a denylist TTL for a token we
        have already rejected or are revoking. Never use for authorization."""
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
        except jwt.InvalidTokenError:
            return None
        exp = claims.get("exp")
        return int(exp) if isinstance(exp, (int, float)) else None
