"""Auth-specific Prometheus metrics.

These are the series the Grafana dashboard and any alerting rules are built on:
they answer "is someone attacking us?" and "is the token pipeline healthy?",
which the generic RPC metrics cannot.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge

LOGIN_ATTEMPTS = Counter(
    "authmesh_login_attempts_total",
    "Login attempts by outcome.",
    # outcome: success | invalid_password | unknown_user | locked | disabled |
    #          mfa_required | rate_limited
    ["outcome"],
)

REGISTRATIONS = Counter(
    "authmesh_registrations_total",
    "Registration attempts by outcome.",
    ["outcome"],
)

TOKENS_ISSUED = Counter(
    "authmesh_tokens_issued_total",
    "Tokens minted, by type.",
    ["token_type"],
)

REFRESH_OPERATIONS = Counter(
    "authmesh_refresh_operations_total",
    "Refresh attempts by outcome (rotated, reused, unknown, expired...).",
    ["outcome"],
)

# The signal that a refresh token leaked. Should be flat at zero; any sustained
# non-zero rate warrants investigation.
TOKEN_REUSE_DETECTED = Counter(
    "authmesh_token_reuse_detected_total",
    "Refresh tokens presented after having been rotated away.",
)

SESSIONS_REVOKED = Counter(
    "authmesh_sessions_revoked_total",
    "Sessions revoked, by reason.",
    ["reason"],
)

ACCOUNT_LOCKOUTS = Counter(
    "authmesh_account_lockouts_total",
    "Accounts locked after consecutive failed logins.",
)

RATE_LIMIT_BLOCKS = Counter(
    "authmesh_rate_limit_blocks_total",
    "Requests rejected by the rate limiter, by scope.",
    ["scope"],
)

MFA_VERIFICATIONS = Counter(
    "authmesh_mfa_verifications_total",
    "Second-factor verification attempts by method and outcome.",
    ["method", "outcome"],
)

MFA_ENROLLMENTS = Counter(
    "authmesh_mfa_enrollments_total",
    "TOTP enrollment lifecycle events.",
    ["event"],
)

INTROSPECTIONS = Counter(
    "authmesh_introspections_total",
    "Access token introspections by result.",
    ["result"],
)

STORE_ERRORS = Counter(
    "authmesh_store_errors_total",
    "Redis operations that failed, by logical operation.",
    ["operation"],
)

ACTIVE_SESSIONS_OBSERVED = Gauge(
    "authmesh_active_sessions_last_listed",
    "Sessions returned by the most recent ListSessions call (sampling gauge).",
)
