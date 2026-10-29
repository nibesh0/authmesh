from __future__ import annotations

from pydantic import Field, field_validator

from authmesh_common.config import BaseServiceSettings


class GatewaySettings(BaseServiceSettings):
    service_name: str = "authmesh-gateway"
    http_port: int = 8080
    metrics_port: int = 9100

    auth_service_target: str = "localhost:50051"
    auth_service_timeout_seconds: float = 5.0

    api_prefix: str = "/api/v1"
    docs_enabled: bool = True

    # Number of proxy hops in front of the gateway. The client IP is taken from
    # X-Forwarded-For at this depth from the right; with 0 the header is ignored
    # entirely. Trusting the header blindly would let a caller spoof its IP and
    # bypass per-IP rate limiting.
    trusted_proxy_hops: int = 0

    cors_allow_origins: list[str] = Field(default_factory=list)
    cors_allow_credentials: bool = True

    # Sent on every response; the API returns JSON only, so a restrictive CSP is
    # safe and blocks rendering of anything injected into an error message.
    security_headers_enabled: bool = True

    # Cap request bodies: the endpoints only ever take small JSON documents.
    max_request_body_bytes: int = 64 * 1024

    @field_validator("api_prefix")
    @classmethod
    def _normalize_prefix(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("api_prefix must start with '/'")
        return value.rstrip("/")
