"""Gateway HTTP contract.

The full user journey is covered by scripts/smoke_test.py. These tests focus on
the HTTP surface itself: the error envelope, correlation headers, hardening
headers, OpenAPI completeness and input validation.
"""

from __future__ import annotations

import httpx
import pytest

from .conftest import unique_email

pytestmark = [pytest.mark.integration]

PASSWORD = "Integration-Passphrase-4471"


@pytest.fixture
async def client(gateway_url: str):
    async with httpx.AsyncClient(base_url=gateway_url, timeout=15.0) as client:
        try:
            response = await client.get("/readyz")
        except httpx.HTTPError:
            pytest.skip(f"gateway is not reachable at {gateway_url}")
        if response.status_code != 200:
            pytest.skip("gateway is not ready")
        yield client


async def register_and_login(client: httpx.AsyncClient, tag: str) -> dict:
    email = unique_email(tag)
    registered = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": PASSWORD, "display_name": "Integration"},
    )
    assert registered.status_code == 201, registered.text

    logged_in = await client.post(
        "/api/v1/auth/login", json={"email": email, "password": PASSWORD}
    )
    assert logged_in.status_code == 200, logged_in.text
    body = logged_in.json()
    return {"email": email, "user": body["user"], **body["tokens"]}


# -- operational endpoints --------------------------------------------------


async def test_healthz_does_not_depend_on_downstreams(client: httpx.AsyncClient) -> None:
    response = await client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "authmesh-gateway"


async def test_readyz_reports_dependencies(client: httpx.AsyncClient) -> None:
    response = await client.get("/readyz")
    assert response.status_code == 200
    assert response.json()["dependencies"]["auth-service"] is True


async def test_metrics_endpoint_exposes_prometheus_text(client: httpx.AsyncClient) -> None:
    response = await client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    body = response.text
    assert "http_requests_total" in body
    assert "grpc_client_handled_total" in body


async def test_probe_endpoints_are_not_in_the_public_schema(client: httpx.AsyncClient) -> None:
    schema = (await client.get("/openapi.json")).json()
    assert "/healthz" not in schema["paths"]
    assert "/metrics" not in schema["paths"]


async def test_openapi_documents_every_public_route(client: httpx.AsyncClient) -> None:
    paths = (await client.get("/openapi.json")).json()["paths"]
    for expected in (
        "/api/v1/auth/register",
        "/api/v1/auth/login",
        "/api/v1/auth/mfa/verify",
        "/api/v1/auth/refresh",
        "/api/v1/auth/logout",
        "/api/v1/me",
        "/api/v1/me/password",
        "/api/v1/me/2fa/enroll",
        "/api/v1/me/sessions",
    ):
        assert expected in paths, f"{expected} is missing from the OpenAPI document"


# -- correlation and hardening ---------------------------------------------


async def test_request_id_is_generated_when_absent(client: httpx.AsyncClient) -> None:
    response = await client.get("/healthz")
    request_id = response.headers.get("x-request-id")
    assert request_id and len(request_id) == 32


async def test_supplied_request_id_is_preserved(client: httpx.AsyncClient) -> None:
    response = await client.get("/healthz", headers={"x-request-id": "abc123def456"})
    assert response.headers["x-request-id"] == "abc123def456"


async def test_suspicious_request_id_is_replaced(client: httpx.AsyncClient) -> None:
    """A caller-supplied id ends up in log fields, so anything that is not a plain
    token is discarded rather than echoed."""
    response = await client.get("/healthz", headers={"x-request-id": 'evil" ,"level":"INFO'})
    assert response.headers["x-request-id"] != 'evil" ,"level":"INFO'


async def test_security_headers_are_set(client: httpx.AsyncClient) -> None:
    response = await client.get("/healthz")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'none'" in response.headers["content-security-policy"]


async def test_token_responses_are_not_cacheable(client: httpx.AsyncClient) -> None:
    session = await register_and_login(client, "cache")
    response = await client.get(
        "/api/v1/me", headers={"authorization": f"Bearer {session['access_token']}"}
    )
    assert response.headers.get("cache-control") == "no-store"


async def test_server_header_is_not_advertised(client: httpx.AsyncClient) -> None:
    response = await client.get("/healthz")
    assert "server" not in {key.lower() for key in response.headers}


# -- error envelope ---------------------------------------------------------


async def test_validation_errors_use_the_standard_envelope(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/register", json={"email": "not-an-email", "password": "x"}
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "invalid_argument"
    assert error["request_id"]
    assert any(field["field"] == "email" for field in error["details"]["fields"])


async def test_validation_errors_do_not_echo_the_submitted_password(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "not-an-email", "password": "SuperSecret-Value-1234"},
    )
    assert "SuperSecret-Value-1234" not in response.text


async def test_unknown_route_returns_the_envelope(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/does-not-exist")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


async def test_wrong_method_returns_the_envelope(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/auth/login")
    assert response.status_code == 405
    assert response.json()["error"]["code"] == "method_not_allowed"


async def test_oversized_body_is_rejected(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "a@example.com", "password": "x" * 200_000},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"


async def test_malformed_json_is_rejected(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        content=b"{not json",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_argument"


# -- authentication surface ------------------------------------------------


async def test_bearer_token_is_required(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/me")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"


async def test_non_bearer_scheme_is_rejected(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/me", headers={"authorization": "Basic dXNlcjpwYXNz"})
    assert response.status_code == 401


async def test_login_returns_a_complete_token_response(client: httpx.AsyncClient) -> None:
    session = await register_and_login(client, "tokens")
    assert session["token_type"] == "Bearer"
    assert session["expires_in"] > 0
    assert session["refresh_expires_in"] > session["expires_in"]
    assert session["session_id"]
    assert session["access_token"] != session["refresh_token"]


async def test_profile_exposes_no_credential_fields(client: httpx.AsyncClient) -> None:
    session = await register_and_login(client, "profile")
    response = await client.get(
        "/api/v1/me", headers={"authorization": f"Bearer {session['access_token']}"}
    )
    body = response.json()

    assert set(body) == {
        "id",
        "email",
        "display_name",
        "roles",
        "totp_enabled",
        "disabled",
        "created_at",
        "updated_at",
    }
    assert body["roles"] == ["user"]


async def test_introspection_of_a_revoked_token(client: httpx.AsyncClient) -> None:
    session = await register_and_login(client, "revoke")
    headers = {"authorization": f"Bearer {session['access_token']}"}

    active = await client.post(
        "/api/v1/auth/introspect", json={"access_token": session["access_token"]}
    )
    assert active.json()["active"] is True

    logout = await client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": session["refresh_token"]},
        headers=headers,
    )
    assert logout.status_code == 204

    after = await client.post(
        "/api/v1/auth/introspect", json={"access_token": session["access_token"]}
    )
    body = after.json()
    assert body["active"] is False
    assert body["inactive_reason"] == "token_revoked"


async def test_refresh_token_cannot_be_used_as_a_bearer_token(
    client: httpx.AsyncClient,
) -> None:
    session = await register_and_login(client, "confusion")
    response = await client.get(
        "/api/v1/me", headers={"authorization": f"Bearer {session['refresh_token']}"}
    )
    assert response.status_code == 401


async def test_root_endpoint_advertises_the_api(client: httpx.AsyncClient) -> None:
    body = (await client.get("/")).json()
    assert body["service"] == "authmesh-gateway"
    assert body["api"] == "/api/v1"
