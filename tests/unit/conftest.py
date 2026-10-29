"""Fixtures for the unit suite.

Settings are constructed with explicit keyword arguments so the tests are
independent of the developer's .env file: init kwargs take precedence over both
environment variables and the dotenv file in pydantic-settings.
"""

from __future__ import annotations

import base64

import pytest

from auth_service.settings import AuthServiceSettings
from auth_service.tokens import TokenService
from auth_service.totp import TotpService

TEST_JWT_SECRET = "unit-test-secret-0123456789abcdefghijklmnopqrstuvwxyz"
# Fernet requires exactly 32 bytes, base64 encoded.
TEST_FERNET_KEY = base64.urlsafe_b64encode(b"unit-test-fernet-key-32-bytes!!!").decode()
TEST_PEPPER = "unit-test-recovery-code-pepper-value"


def build_settings(**overrides) -> AuthServiceSettings:
    defaults = dict(
        jwt_secret=TEST_JWT_SECRET,
        totp_encryption_key=TEST_FERNET_KEY,
        recovery_code_pepper=TEST_PEPPER,
        # Keep hashing cheap: these tests are about behaviour, not work factor.
        bcrypt_rounds=4,
        access_token_ttl_seconds=900,
        refresh_token_ttl_seconds=3600,
        session_absolute_ttl_seconds=7200,
    )
    defaults.update(overrides)
    return AuthServiceSettings(**defaults)


@pytest.fixture
def settings() -> AuthServiceSettings:
    return build_settings()


@pytest.fixture
def tokens(settings: AuthServiceSettings) -> TokenService:
    return TokenService(settings)


@pytest.fixture
def totp(settings: AuthServiceSettings) -> TotpService:
    return TotpService(settings)
