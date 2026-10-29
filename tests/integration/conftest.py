"""Fixtures for the integration suite.

These tests run against the live Compose stack (`make dev-up`) from a container
attached to the same network, so `redis`, `auth-service`, `user-service` and
`gateway` resolve by service name.

Every test gets its own Redis key prefix, which keeps parallel or repeated runs
from colliding and means a failed test cannot poison the next one.
"""

from __future__ import annotations

import base64
import os
import uuid

import pytest
import pytest_asyncio

from auth_service.settings import AuthServiceSettings
from auth_service.store import SecurityStore

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://gateway:8080")
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
AUTH_TARGET = os.environ.get("AUTH_SERVICE_TARGET", "auth-service:50051")
USER_TARGET = os.environ.get("USER_SERVICE_TARGET", "user-service:50052")

TEST_FERNET_KEY = base64.urlsafe_b64encode(b"integration-fernet-key-32-bytes!").decode()


def integration_settings(**overrides) -> AuthServiceSettings:
    defaults = dict(
        jwt_secret="integration-test-secret-0123456789abcdefghijkl",
        totp_encryption_key=TEST_FERNET_KEY,
        recovery_code_pepper="integration-recovery-pepper-value",
        redis_url=REDIS_URL,
        # Unique per store instance so tests never share keys.
        redis_key_prefix=f"itest-{uuid.uuid4().hex[:8]}",
        bcrypt_rounds=4,
    )
    defaults.update(overrides)
    return AuthServiceSettings(**defaults)


@pytest.fixture
def settings() -> AuthServiceSettings:
    return integration_settings()


@pytest_asyncio.fixture
async def store(settings: AuthServiceSettings):
    store = SecurityStore(settings)
    await store.connect()
    if not await store.ping():
        pytest.skip(f"redis is not reachable at {settings.redis_url}")
    try:
        yield store
    finally:
        # Drop everything this test wrote; the prefix is unique to it.
        client = store.client
        keys = [key async for key in client.scan_iter(f"{settings.redis_key_prefix}:*")]
        if keys:
            await client.delete(*keys)
        await store.close()


@pytest.fixture(scope="session")
def gateway_url() -> str:
    return GATEWAY_URL.rstrip("/")


@pytest.fixture(scope="session")
def api_url(gateway_url: str) -> str:
    return f"{gateway_url}/api/v1"


def unique_email(tag: str) -> str:
    # example.com is reserved for documentation; .test would be rejected by
    # email-validator's special-use domain list.
    return f"itest-{tag}-{uuid.uuid4().hex[:10]}@example.com"
