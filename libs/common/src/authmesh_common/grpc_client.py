"""Channel factory for service-to-service calls.

Two details matter in Kubernetes:

* `dns:///` + `round_robin` - gRPC keeps one long-lived HTTP/2 connection per
  channel, so the default `pick_first` policy would pin every caller to a single
  replica and make the HPA useless. Resolving via DNS and load balancing across
  all resolved addresses spreads calls over the ReplicaSet.
* built-in retries - a rolling update briefly refuses connections; retrying
  UNAVAILABLE absorbs that instead of surfacing 503s to users.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import grpc

from .interceptors import ClientContextInterceptor

MAX_MESSAGE_BYTES = 4 * 1024 * 1024

_RETRY_SERVICE_CONFIG: dict[str, Any] = {
    "methodConfig": [
        {
            # Empty name matches every method on every service.
            "name": [{}],
            "retryPolicy": {
                "maxAttempts": 4,
                "initialBackoff": "0.1s",
                "maxBackoff": "1s",
                "backoffMultiplier": 2.0,
                # Deliberately narrow: UNAVAILABLE means "never reached the
                # server", so replaying a non-idempotent call such as Register is
                # still safe. Retrying anything else could double-apply writes.
                "retryableStatusCodes": ["UNAVAILABLE"],
            },
        }
    ]
}


def normalize_target(target: str) -> str:
    """Force the DNS resolver so round_robin sees every pod address."""
    if "://" in target or target.startswith(("dns:", "unix:", "ipv4:", "ipv6:")):
        return target
    return f"dns:///{target}"


def channel_options(
    *, load_balancing_policy: str = "round_robin", enable_retries: bool = True
) -> list[tuple[str, Any]]:
    options: list[tuple[str, Any]] = [
        ("grpc.lb_policy_name", load_balancing_policy),
        ("grpc.max_receive_message_length", MAX_MESSAGE_BYTES),
        ("grpc.max_send_message_length", MAX_MESSAGE_BYTES),
        # Detect dead peers (node failure, NAT timeout) without waiting for TCP.
        ("grpc.keepalive_time_ms", 30_000),
        ("grpc.keepalive_timeout_ms", 10_000),
        ("grpc.keepalive_permit_without_calls", 1),
        ("grpc.http2.max_pings_without_data", 0),
        # Pick up new endpoints promptly during a rollout.
        ("grpc.dns_min_time_between_resolutions_ms", 2_000),
    ]
    if enable_retries:
        options.append(("grpc.enable_retries", 1))
        options.append(("grpc.service_config", json.dumps(_RETRY_SERVICE_CONFIG)))
    return options


def create_channel(
    target: str,
    *,
    enable_retries: bool = True,
    interceptors: list[grpc.aio.ClientInterceptor] | None = None,
) -> grpc.aio.Channel:
    return grpc.aio.insecure_channel(
        normalize_target(target),
        options=channel_options(enable_retries=enable_retries),
        interceptors=interceptors
        if interceptors is not None
        else [ClientContextInterceptor()],
    )


async def channel_is_ready(channel: grpc.aio.Channel, timeout: float = 2.0) -> bool:
    """Dependency probe: has the channel got a usable connection?

    Also nudges an IDLE channel into connecting so the first real request does
    not pay the handshake cost.
    """
    state = channel.get_state(try_to_connect=True)
    if state is grpc.ChannelConnectivity.READY:
        return True
    try:
        await asyncio.wait_for(channel.channel_ready(), timeout=timeout)
    except (asyncio.TimeoutError, Exception):
        return False
    return channel.get_state(try_to_connect=False) is grpc.ChannelConnectivity.READY
