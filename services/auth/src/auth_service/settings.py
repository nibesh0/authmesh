from __future__ import annotations

from pydantic import Field, field_validator, model_validator

from authmesh_common.config import BaseServiceSettings


class AuthServiceSettings(BaseServiceSettings):
    service_name: str = "authmesh-auth"
    grpc_port: int = 50051
    metrics_port: int = 9101

    # -- downstreams -------------------------------------------------------
    user_service_target: str = "localhost:50052"
    user_service_timeout_seconds: float = 3.0
    redis_url: str = "redis://localhost:6379/0"
    redis_key_prefix: str = "am"
    redis_socket_timeout_seconds: float = 1.5
    redis_connect_timeout_seconds: float = 1.5
    redis_max_connections: int = 50

    # -- tokens ------------------------------------------------------------
    jwt_algorithm: str = "HS256"
    jwt_secret: str = Field(default="", repr=False)
    # Set during a secret rotation: new tokens are signed with `jwt_secret`
    # while tokens signed with the previous secret keep validating until they
    # expire, so rotation needs no downtime and no forced logout.
    jwt_secret_previous: str = Field(default="", repr=False)
    jwt_issuer: str = "authmesh"
    jwt_audience: str = "authmesh-api"
    access_token_ttl_seconds: int = 900          # 15 min
    refresh_token_ttl_seconds: int = 1_209_600   # 14 days
    # Hard ceiling on a session regardless of how often it is refreshed.
    session_absolute_ttl_seconds: int = 2_592_000  # 30 days
    mfa_challenge_ttl_seconds: int = 300
    max_sessions_per_user: int = 10

    # -- password hashing --------------------------------------------------
    bcrypt_rounds: int = 12
    password_min_length: int = 12
    password_max_length: int = 256
    password_require_mixed_case: bool = True
    password_require_digit: bool = True
    password_require_symbol: bool = False

    # -- 2FA ---------------------------------------------------------------
    # urlsafe-base64 32-byte Fernet key used to encrypt TOTP secrets at rest.
    totp_encryption_key: str = Field(default="", repr=False)
    # Keyed hash for recovery codes (they are high-entropy, so HMAC is enough).
    recovery_code_pepper: str = Field(default="", repr=False)
    totp_issuer_name: str = "authmesh"
    totp_digits: int = 6
    totp_interval_seconds: int = 30
    # Accept codes one step either side of now to tolerate clock skew.
    totp_valid_window: int = 1
    recovery_code_count: int = 10

    # -- abuse controls ----------------------------------------------------
    rate_limit_enabled: bool = True
    login_rate_limit_per_ip: int = 20
    login_rate_limit_window_seconds: int = 60
    login_rate_limit_per_account: int = 10
    register_rate_limit_per_ip: int = 5
    register_rate_limit_window_seconds: int = 300
    refresh_rate_limit_per_session: int = 60
    refresh_rate_limit_window_seconds: int = 60
    mfa_rate_limit_per_account: int = 10
    mfa_rate_limit_window_seconds: int = 300

    lockout_enabled: bool = True
    lockout_threshold: int = 5
    lockout_window_seconds: int = 900
    lockout_duration_seconds: int = 900

    @field_validator("jwt_algorithm")
    @classmethod
    def _supported_algorithm(cls, value: str) -> str:
        if value not in {"HS256", "HS384", "HS512"}:
            raise ValueError(
                "only HMAC algorithms are supported; asymmetric signing needs a key pair"
            )
        return value

    @model_validator(mode="after")
    def _require_secrets(self) -> "AuthServiceSettings":
        if len(self.jwt_secret) < 32:
            raise ValueError(
                "JWT_SECRET must be set to at least 32 characters "
                "(generate with: openssl rand -base64 48)"
            )
        if not self.totp_encryption_key:
            raise ValueError(
                "TOTP_ENCRYPTION_KEY must be set "
                "(generate with: python -c \"from cryptography.fernet import Fernet;"
                " print(Fernet.generate_key().decode())\")"
            )
        if len(self.recovery_code_pepper) < 16:
            raise ValueError("RECOVERY_CODE_PEPPER must be set to at least 16 characters")
        if self.refresh_token_ttl_seconds <= self.access_token_ttl_seconds:
            raise ValueError("refresh token TTL must exceed access token TTL")
        if self.session_absolute_ttl_seconds < self.refresh_token_ttl_seconds:
            raise ValueError("session absolute TTL must be >= refresh token TTL")
        return self
