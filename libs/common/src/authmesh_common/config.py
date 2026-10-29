"""Configuration base class.

Settings come from the environment only: a ConfigMap supplies the plain values
and a Secret supplies the sensitive ones, which keeps the same image usable in
compose and in Kubernetes without a config file baked in.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class BaseServiceSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    service_name: str = "authmesh-service"
    environment: str = Field(default="development")
    version: str = Field(default="0.1.0")

    log_level: str = Field(default="INFO")
    log_format: Literal["json", "console"] = Field(default="json")

    metrics_enabled: bool = True
    metrics_port: int = 9100

    # Seconds a gRPC server / HTTP app gets to drain in-flight work on SIGTERM.
    # Must stay below the pod's terminationGracePeriodSeconds.
    shutdown_grace_seconds: float = 15.0

    # How often background dependency probes run to drive the readiness signal.
    health_check_interval_seconds: float = 10.0

    @field_validator("log_level")
    @classmethod
    def _upper(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}:
            raise ValueError(f"invalid log level: {value}")
        return normalized

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"prod", "production"}
