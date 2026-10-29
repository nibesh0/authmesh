from __future__ import annotations

from pydantic import Field

from authmesh_common.config import BaseServiceSettings


class UserServiceSettings(BaseServiceSettings):
    service_name: str = "authmesh-user"
    grpc_port: int = 50052
    metrics_port: int = 9102

    mongo_uri: str = Field(default="mongodb://localhost:27017")
    mongo_database: str = "authmesh"
    # Keep this well under the gRPC client deadline so a Mongo failover surfaces
    # as a fast UNAVAILABLE instead of piling up requests.
    mongo_server_selection_timeout_ms: int = 3_000
    mongo_connect_timeout_ms: int = 3_000
    mongo_socket_timeout_ms: int = 5_000
    mongo_max_pool_size: int = 50
    mongo_min_pool_size: int = 2

    # 0 disables the TTL index and keeps audit events forever.
    audit_retention_days: int = 90

    default_page_size: int = 50
    max_page_size: int = 200

    # Skips index creation on boot; useful when a migration job owns schema.
    ensure_indexes: bool = True
