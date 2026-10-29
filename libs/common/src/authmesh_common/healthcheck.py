"""Command-line gRPC health probe.

Kubernetes can dial grpc.health.v1 natively, but Docker Compose healthchecks
cannot, and neither can a shell. This module gives both a dependency-free way to
ask a gRPC service how it is doing:

    python -m authmesh_common.healthcheck --port 50051 --service ready

Exits 0 when SERVING, 1 otherwise, so it drops straight into a HEALTHCHECK.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc


async def check(host: str, port: int, service: str, timeout: float) -> int:
    async with grpc.aio.insecure_channel(f"{host}:{port}") as channel:
        stub = health_pb2_grpc.HealthStub(channel)
        try:
            response = await stub.Check(
                health_pb2.HealthCheckRequest(service=service), timeout=timeout
            )
        except grpc.aio.AioRpcError as exc:
            print(f"unhealthy: {exc.code().name} {exc.details()}", file=sys.stderr)
            return 1

    status_name = health_pb2.HealthCheckResponse.ServingStatus.Name(response.status)
    if response.status == health_pb2.HealthCheckResponse.SERVING:
        print(f"{service or '<overall>'}: {status_name}")
        return 0
    print(f"unhealthy: {service or '<overall>'} is {status_name}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="gRPC health probe")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument(
        "--service",
        default="",
        help="health service name; '' for liveness, 'ready' for readiness",
    )
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()

    return asyncio.run(check(args.host, args.port, args.service, args.timeout))


if __name__ == "__main__":
    raise SystemExit(main())
