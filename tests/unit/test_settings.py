"""Configuration validation.

A service that boots with a placeholder signing secret is worse than one that
refuses to boot, so the settings model fails loudly on unsafe values.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from auth_service.settings import AuthServiceSettings
from gateway.settings import GatewaySettings
from user_service.settings import UserServiceSettings

from .conftest import TEST_FERNET_KEY, TEST_JWT_SECRET, TEST_PEPPER, build_settings

REQUIRED = dict(
    jwt_secret=TEST_JWT_SECRET,
    totp_encryption_key=TEST_FERNET_KEY,
    recovery_code_pepper=TEST_PEPPER,
)


def test_valid_settings_load() -> None:
    settings = build_settings()
    assert settings.service_name == "authmesh-auth"
    assert settings.grpc_port == 50051


def test_short_jwt_secret_is_rejected() -> None:
    with pytest.raises(ValidationError, match="JWT_SECRET"):
        AuthServiceSettings(**{**REQUIRED, "jwt_secret": "too-short"})


def test_missing_totp_key_is_rejected() -> None:
    with pytest.raises(ValidationError, match="TOTP_ENCRYPTION_KEY"):
        AuthServiceSettings(**{**REQUIRED, "totp_encryption_key": ""})


def test_missing_recovery_pepper_is_rejected() -> None:
    with pytest.raises(ValidationError, match="RECOVERY_CODE_PEPPER"):
        AuthServiceSettings(**{**REQUIRED, "recovery_code_pepper": "short"})


def test_refresh_ttl_must_exceed_access_ttl() -> None:
    """Otherwise the refresh token expires first and no session can be renewed."""
    with pytest.raises(ValidationError, match="refresh token TTL"):
        AuthServiceSettings(
            **REQUIRED, access_token_ttl_seconds=3600, refresh_token_ttl_seconds=900
        )


def test_absolute_session_ttl_must_cover_the_refresh_window() -> None:
    with pytest.raises(ValidationError, match="absolute TTL"):
        AuthServiceSettings(
            **REQUIRED,
            refresh_token_ttl_seconds=1_209_600,
            session_absolute_ttl_seconds=3600,
        )


def test_asymmetric_algorithms_are_rejected() -> None:
    with pytest.raises(ValidationError, match="HMAC"):
        AuthServiceSettings(**REQUIRED, jwt_algorithm="RS256")


def test_invalid_log_level_is_rejected() -> None:
    with pytest.raises(ValidationError, match="invalid log level"):
        AuthServiceSettings(**REQUIRED, log_level="chatty")


def test_log_level_is_normalised() -> None:
    assert build_settings(log_level="debug").log_level == "DEBUG"


def test_gateway_prefix_must_be_absolute() -> None:
    with pytest.raises(ValidationError, match="api_prefix"):
        GatewaySettings(api_prefix="api/v1")


def test_gateway_prefix_trailing_slash_is_stripped() -> None:
    assert GatewaySettings(api_prefix="/api/v2/").api_prefix == "/api/v2"


def test_user_service_defaults() -> None:
    settings = UserServiceSettings()
    assert settings.grpc_port == 50052
    assert settings.mongo_database == "authmesh"
    # A page size ceiling stops a caller from asking for the whole collection.
    assert settings.max_page_size >= settings.default_page_size


def test_secrets_are_not_printed_in_the_repr() -> None:
    """`repr=False` on the secret fields keeps them out of tracebacks and any
    accidental log of the settings object."""
    rendered = repr(build_settings())
    assert TEST_JWT_SECRET not in rendered
    assert TEST_PEPPER not in rendered
