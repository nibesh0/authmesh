"""Request and response models.

These are the public contract of the platform. They are intentionally not
generated from the protobufs: the internal messages carry fields that must never
be exposed (password hashes, encrypted TOTP secrets), and the REST shape should
be free to evolve independently of the wire format between services.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class ErrorResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "error": {
                    "code": "invalid_credentials",
                    "message": "email or password is incorrect",
                    "request_id": "9f2c1d0e7a5b4c3d",
                }
            }
        }
    )
    error: dict[str, Any]


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    display_name: str = Field(default="", max_length=120)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    # Supplying the code up front completes 2FA without the extra round trip.
    totp_code: str | None = Field(default=None, max_length=16)


class MfaVerifyRequest(BaseModel):
    mfa_token: str = Field(min_length=1)
    # A 6-digit TOTP code or a recovery code such as "a3k9x-2m7pq".
    code: str = Field(min_length=1, max_length=32)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class LogoutRequest(BaseModel):
    refresh_token: str | None = None


class LogoutAllRequest(BaseModel):
    # Keeps the session making the request alive by default.
    keep_current_session: bool = True


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)
    # Default false: changing a password signs other devices out.
    keep_other_sessions: bool = False


class TotpActivateRequest(BaseModel):
    totp_code: str = Field(min_length=6, max_length=8)


class TotpDisableRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class IntrospectRequest(BaseModel):
    access_token: str = Field(min_length=1)


class UserResponse(BaseModel):
    id: str
    email: str
    display_name: str
    roles: list[str]
    totp_enabled: bool
    disabled: bool
    created_at: str
    updated_at: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int
    refresh_expires_in: int
    session_id: str


class LoginResponse(BaseModel):
    mfa_required: bool = False
    # Present only when mfa_required is true; exchange it at /auth/mfa/verify.
    mfa_token: str | None = None
    tokens: TokenResponse | None = None
    user: UserResponse | None = None


class RegisterResponse(BaseModel):
    user: UserResponse


class RevocationResponse(BaseModel):
    sessions_revoked: int


class TotpEnrollResponse(BaseModel):
    secret: str
    otpauth_uri: str
    # Shown exactly once. Each code works a single time.
    recovery_codes: list[str]


class TotpStatusResponse(BaseModel):
    totp_enabled: bool
    recovery_codes_remaining: int


class SessionResponse(BaseModel):
    id: str
    created_at: str
    last_used_at: str
    expires_at: str
    ip: str
    user_agent: str
    current: bool


class SessionListResponse(BaseModel):
    sessions: list[SessionResponse]


class IntrospectResponse(BaseModel):
    active: bool
    user_id: str | None = None
    email: str | None = None
    roles: list[str] | None = None
    session_id: str | None = None
    jti: str | None = None
    issued_at: int | None = None
    expires_at: int | None = None
    inactive_reason: str | None = None


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
