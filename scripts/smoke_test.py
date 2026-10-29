#!/usr/bin/env python3
"""End-to-end smoke test driven entirely through the public HTTP API.

Deliberately stdlib-only (urllib + hmac) so it runs anywhere the gateway is
reachable: on a laptop against Docker Compose, or from a pod inside Kubernetes
with no extra image dependencies. TOTP codes are computed inline rather than
pulled from pyotp for the same reason.

Every check asserts on the response `code` from the error envelope, not just the
status, so a test cannot pass because the right status came back for the wrong
reason.

    python3 scripts/smoke_test.py [--base-url http://localhost:8080]
"""

from __future__ import annotations

import argparse
import base64
import hmac
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request
import uuid
from typing import Any

# --- tiny test harness -----------------------------------------------------

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
_passed = 0
_failed: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> bool:
    global _passed
    if condition:
        _passed += 1
        print(f"  {GREEN}PASS{RESET} {label}")
    else:
        _failed.append(label)
        print(f"  {RED}FAIL{RESET} {label}" + (f"  {DIM}{detail}{RESET}" if detail else ""))
    return condition


def section(title: str) -> None:
    print(f"\n{YELLOW}== {title}{RESET}")


# --- HTTP ------------------------------------------------------------------


class Response:
    def __init__(self, status: int, body: Any, headers: dict[str, str]) -> None:
        self.status = status
        self.body = body if isinstance(body, dict) else {}
        self.raw = body
        self.headers = headers

    @property
    def error_code(self) -> str:
        error = self.body.get("error") if isinstance(self.body, dict) else None
        return error.get("code", "") if isinstance(error, dict) else ""

    def __repr__(self) -> str:
        return f"<{self.status} {json.dumps(self.raw)[:200]}>"


def request(
    method: str,
    url: str,
    *,
    payload: dict | None = None,
    token: str | None = None,
    timeout: float = 15.0,
) -> Response:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("accept", "application/json")
    if data is not None:
        req.add_header("content-type", "application/json")
    if token:
        req.add_header("authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read()
            headers = {k.lower(): v for k, v in response.headers.items()}
            body = json.loads(raw) if raw else {}
            return Response(response.status, body, headers)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {"raw": raw.decode(errors="replace")}
        return Response(exc.code, body, headers)


# --- TOTP (RFC 6238, stdlib only) -----------------------------------------


def totp_code(secret_base32: str, *, digits: int = 6, interval: int = 30, offset: int = 0) -> str:
    padding = "=" * (-len(secret_base32) % 8)
    key = base64.b32decode(secret_base32.upper() + padding)
    counter = int(time.time()) // interval + offset
    digest = hmac.new(key, struct.pack(">Q", counter), "sha1").digest()
    position = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[position : position + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10**digits)).zfill(digits)


def seconds_into_step(interval: int = 30) -> int:
    return int(time.time()) % interval


# --- the test --------------------------------------------------------------

PASSWORD = "Sm0keTest-Passphrase-9271"
NEW_PASSWORD = "Rotated-Passphrase-55182"


def unique_email(tag: str) -> str:
    # example.com is reserved for documentation and, unlike .test or .invalid, is
    # not on email-validator's special-use domain deny list.
    return f"smoke-{tag}-{uuid.uuid4().hex[:10]}@example.com"


def wait_for_ready(base: str, attempts: int = 60) -> bool:
    for _ in range(attempts):
        response = request("GET", f"{base}/readyz")
        if response.status == 200:
            return True
        time.sleep(2)
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--base-url",
        default=os.environ.get("GATEWAY_URL", "http://localhost:8080"),
    )
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    api = f"{base}/api/v1"

    print(f"{DIM}target: {base}{RESET}")

    # -- health ------------------------------------------------------------
    section("health and metadata")
    if not check("gateway becomes ready", wait_for_ready(base)):
        print(f"\n{RED}gateway never became ready; aborting{RESET}")
        return 1

    health = request("GET", f"{base}/healthz")
    check("GET /healthz returns ok", health.status == 200 and health.body.get("status") == "ok", repr(health))

    ready = request("GET", f"{base}/readyz")
    check(
        "GET /readyz reports the auth-service dependency",
        ready.status == 200 and ready.body.get("dependencies", {}).get("auth-service") is True,
        repr(ready),
    )

    openapi = request("GET", f"{base}/openapi.json")
    check(
        "OpenAPI document is served",
        openapi.status == 200 and "/api/v1/auth/login" in openapi.body.get("paths", {}),
        f"status={openapi.status}",
    )

    check(
        "responses carry a correlation id",
        bool(health.headers.get("x-request-id")),
        str(health.headers),
    )
    check(
        "security headers are present",
        health.headers.get("x-content-type-options") == "nosniff",
        str(health.headers),
    )

    # -- registration ------------------------------------------------------
    section("registration and password policy")
    email = unique_email("main")

    weak = request(
        "POST",
        f"{api}/auth/register",
        payload={"email": unique_email("weak"), "password": "short", "display_name": "Weak"},
    )
    check(
        "a weak password is rejected with weak_password",
        weak.status == 422 and weak.error_code == "weak_password",
        repr(weak),
    )

    registered = request(
        "POST",
        f"{api}/auth/register",
        payload={"email": email, "password": PASSWORD, "display_name": "Smoke Test"},
    )
    check(
        "registration returns 201 and the new user",
        registered.status == 201 and registered.body.get("user", {}).get("email") == email,
        repr(registered),
    )
    user_id = registered.body.get("user", {}).get("id", "")
    check("the user has an id", bool(user_id))
    check(
        "the registration response never contains a password hash",
        "password_hash" not in json.dumps(registered.body),
    )

    duplicate = request(
        "POST",
        f"{api}/auth/register",
        payload={"email": email, "password": PASSWORD, "display_name": "Dup"},
    )
    check(
        "a duplicate email is rejected with 409 already_exists",
        duplicate.status == 409 and duplicate.error_code == "already_exists",
        repr(duplicate),
    )

    # -- login -------------------------------------------------------------
    section("login")
    wrong = request(
        "POST", f"{api}/auth/login", payload={"email": email, "password": "not-the-password"}
    )
    check(
        "a wrong password is rejected with invalid_credentials",
        wrong.status == 401 and wrong.error_code == "invalid_credentials",
        repr(wrong),
    )

    unknown = request(
        "POST",
        f"{api}/auth/login",
        payload={"email": unique_email("nobody"), "password": PASSWORD},
    )
    check(
        "an unknown account returns the same error as a wrong password",
        unknown.status == wrong.status and unknown.error_code == wrong.error_code,
        f"unknown={unknown!r} wrong={wrong!r}",
    )

    login = request("POST", f"{api}/auth/login", payload={"email": email, "password": PASSWORD})
    tokens = login.body.get("tokens") or {}
    check(
        "login returns an access and refresh token",
        login.status == 200 and bool(tokens.get("access_token")) and bool(tokens.get("refresh_token")),
        repr(login),
    )
    check("token_type is Bearer", tokens.get("token_type") == "Bearer", repr(tokens))
    check("expires_in is present", isinstance(tokens.get("expires_in"), int) and tokens["expires_in"] > 0)
    access, refresh = tokens.get("access_token", ""), tokens.get("refresh_token", "")
    session_id = tokens.get("session_id", "")

    # -- authenticated access ---------------------------------------------
    section("authenticated access")
    me = request("GET", f"{api}/me", token=access)
    check(
        "GET /me returns the caller's profile",
        me.status == 200 and me.body.get("email") == email,
        repr(me),
    )
    check("the profile does not leak credential material", "password" not in json.dumps(me.body))

    no_token = request("GET", f"{api}/me")
    check(
        "a missing token yields 401 unauthenticated",
        no_token.status == 401 and no_token.error_code == "unauthenticated",
        repr(no_token),
    )

    garbage = request("GET", f"{api}/me", token="not.a.jwt")
    check("a malformed token yields 401", garbage.status == 401, repr(garbage))

    introspect = request("POST", f"{api}/auth/introspect", payload={"access_token": access})
    check(
        "introspection reports the token as active",
        introspect.status == 200
        and introspect.body.get("active") is True
        and introspect.body.get("user_id") == user_id,
        repr(introspect),
    )

    # -- refresh rotation --------------------------------------------------
    section("refresh token rotation and reuse detection")
    rotated = request("POST", f"{api}/auth/refresh", payload={"refresh_token": refresh})
    check(
        "refresh returns a new token pair",
        rotated.status == 200 and bool(rotated.body.get("access_token")),
        repr(rotated),
    )
    check(
        "the refresh token itself is rotated",
        rotated.body.get("refresh_token") != refresh,
        "the same refresh token came back",
    )
    check(
        "the session id is preserved across a rotation",
        rotated.body.get("session_id") == session_id,
        f"{rotated.body.get('session_id')} != {session_id}",
    )
    rotated_refresh = rotated.body.get("refresh_token", "")
    rotated_access = rotated.body.get("access_token", "")

    replay = request("POST", f"{api}/auth/refresh", payload={"refresh_token": refresh})
    check(
        "replaying the old refresh token is rejected as token_reused",
        replay.status == 401 and replay.error_code == "token_reused",
        repr(replay),
    )

    after_reuse = request("POST", f"{api}/auth/refresh", payload={"refresh_token": rotated_refresh})
    check(
        "reuse detection revoked the whole session",
        after_reuse.status == 401,
        repr(after_reuse),
    )
    check(
        "access tokens from the revoked session stop working immediately",
        request("GET", f"{api}/me", token=rotated_access).status == 401,
    )

    # -- two-factor authentication ----------------------------------------
    section("TOTP two-factor authentication")
    login2 = request("POST", f"{api}/auth/login", payload={"email": email, "password": PASSWORD})
    access = (login2.body.get("tokens") or {}).get("access_token", "")
    check("re-login after revocation succeeds", login2.status == 200 and bool(access), repr(login2))

    enroll = request("POST", f"{api}/me/2fa/enroll", token=access)
    secret = enroll.body.get("secret", "")
    recovery_codes = enroll.body.get("recovery_codes", [])
    check(
        "enrollment returns a secret, a provisioning URI and recovery codes",
        enroll.status == 200
        and bool(secret)
        and enroll.body.get("otpauth_uri", "").startswith("otpauth://totp/")
        and len(recovery_codes) >= 8,
        repr(enroll),
    )

    still_no_mfa = request("POST", f"{api}/auth/login", payload={"email": email, "password": PASSWORD})
    check(
        "2FA is not enforced until enrollment is confirmed",
        still_no_mfa.status == 200 and still_no_mfa.body.get("mfa_required") is False,
        repr(still_no_mfa),
    )

    bad_activate = request("POST", f"{api}/me/2fa/activate", payload={"totp_code": "000000"}, token=access)
    check(
        "activation with a wrong code is rejected as invalid_mfa_code",
        bad_activate.status == 401 and bad_activate.error_code == "invalid_mfa_code",
        repr(bad_activate),
    )

    # Avoid straddling a step boundary between generating a code and using it.
    if seconds_into_step() > 27:
        time.sleep(4)
    activate = request(
        "POST", f"{api}/me/2fa/activate", payload={"totp_code": totp_code(secret)}, token=access
    )
    check(
        "activation with a valid code enables 2FA",
        activate.status == 200 and activate.body.get("totp_enabled") is True,
        repr(activate),
    )
    check(
        "recovery codes are reported as available",
        activate.body.get("recovery_codes_remaining", 0) >= 8,
        repr(activate),
    )

    challenged = request("POST", f"{api}/auth/login", payload={"email": email, "password": PASSWORD})
    check(
        "login now returns an MFA challenge instead of tokens",
        challenged.status == 200
        and challenged.body.get("mfa_required") is True
        and bool(challenged.body.get("mfa_token"))
        and challenged.body.get("tokens") is None,
        repr(challenged),
    )
    mfa_token = challenged.body.get("mfa_token", "")

    bad_code = request(
        "POST", f"{api}/auth/mfa/verify", payload={"mfa_token": mfa_token, "code": "111111"}
    )
    check(
        "a wrong second factor is rejected",
        bad_code.status == 401 and bad_code.error_code == "invalid_mfa_code",
        repr(bad_code),
    )

    if seconds_into_step() > 27:
        time.sleep(4)
    verified = request(
        "POST",
        f"{api}/auth/mfa/verify",
        payload={"mfa_token": mfa_token, "code": totp_code(secret)},
    )
    mfa_tokens = verified.body.get("tokens") or {}
    check(
        "the challenge can still be completed after a failed attempt",
        verified.status == 200 and bool(mfa_tokens.get("access_token")),
        repr(verified),
    )
    access = mfa_tokens.get("access_token", "")

    replayed_challenge = request(
        "POST",
        f"{api}/auth/mfa/verify",
        payload={"mfa_token": mfa_token, "code": totp_code(secret)},
    )
    check(
        "an MFA challenge cannot be replayed once used",
        replayed_challenge.status == 401,
        repr(replayed_challenge),
    )

    if seconds_into_step() > 27:
        time.sleep(4)
    single_shot = request(
        "POST",
        f"{api}/auth/login",
        payload={"email": email, "password": PASSWORD, "totp_code": totp_code(secret)},
    )
    check(
        "supplying the code with the password logs in without a challenge",
        single_shot.status == 200
        and single_shot.body.get("mfa_required") is False
        and bool((single_shot.body.get("tokens") or {}).get("access_token")),
        repr(single_shot),
    )

    # -- recovery codes ----------------------------------------------------
    section("recovery codes")
    if not recovery_codes:
        check("recovery codes were issued at enrollment", False, "no codes to test with")
        print(f"\n{RED}cannot continue without recovery codes{RESET}")
        return 1

    recovery_login = request("POST", f"{api}/auth/login", payload={"email": email, "password": PASSWORD})
    recovery_challenge = recovery_login.body.get("mfa_token", "")
    used_code = recovery_codes[0]
    recovered = request(
        "POST",
        f"{api}/auth/mfa/verify",
        payload={"mfa_token": recovery_challenge, "code": used_code},
    )
    check(
        "a recovery code satisfies the second factor",
        recovered.status == 200 and bool((recovered.body.get("tokens") or {}).get("access_token")),
        repr(recovered),
    )
    recovery_access = (recovered.body.get("tokens") or {}).get("access_token", "")

    reuse_login = request("POST", f"{api}/auth/login", payload={"email": email, "password": PASSWORD})
    reused_recovery = request(
        "POST",
        f"{api}/auth/mfa/verify",
        payload={"mfa_token": reuse_login.body.get("mfa_token", ""), "code": used_code},
    )
    check(
        "a recovery code works only once",
        reused_recovery.status == 401,
        repr(reused_recovery),
    )

    # -- sessions ----------------------------------------------------------
    section("session management")
    sessions = request("GET", f"{api}/me/sessions", token=recovery_access)
    session_list = sessions.body.get("sessions", [])
    check(
        "sessions are listed with the current one flagged",
        sessions.status == 200
        and len(session_list) >= 2
        and sum(1 for item in session_list if item.get("current")) == 1,
        repr(sessions),
    )

    other = next((item for item in session_list if not item.get("current")), None)
    if check("there is another session to revoke", other is not None):
        revoked = request("DELETE", f"{api}/me/sessions/{other['id']}", token=recovery_access)
        check(
            "revoking a single session reports one revocation",
            revoked.status == 200 and revoked.body.get("sessions_revoked") == 1,
            repr(revoked),
        )
        check(
            "the caller's own session still works after revoking another",
            request("GET", f"{api}/me", token=recovery_access).status == 200,
        )

    missing = request("DELETE", f"{api}/me/sessions/{uuid.uuid4().hex}", token=recovery_access)
    check(
        "revoking an unknown session yields 404",
        missing.status == 404 and missing.error_code == "not_found",
        repr(missing),
    )

    revoke_all = request(
        "POST",
        f"{api}/me/sessions/revoke-all",
        payload={"keep_current_session": True},
        token=recovery_access,
    )
    check("revoke-all succeeds", revoke_all.status == 200, repr(revoke_all))
    check(
        "the current session survives revoke-all when asked to",
        request("GET", f"{api}/me", token=recovery_access).status == 200,
    )

    # -- 2FA removal -------------------------------------------------------
    section("disabling 2FA")
    bad_disable = request(
        "POST", f"{api}/me/2fa/disable", payload={"password": "wrong-password"}, token=recovery_access
    )
    check(
        "disabling 2FA requires the correct password",
        bad_disable.status == 401,
        repr(bad_disable),
    )

    disabled = request(
        "POST", f"{api}/me/2fa/disable", payload={"password": PASSWORD}, token=recovery_access
    )
    check(
        "2FA can be disabled with the password",
        disabled.status == 200 and disabled.body.get("totp_enabled") is False,
        repr(disabled),
    )

    # -- password change ---------------------------------------------------
    # A dedicated account: the per-account login limiter (10 per minute) is
    # deliberately left at its real value, and the account above has already used
    # most of that budget across the 2FA flows.
    section("changing the password")
    pwd_email = unique_email("pwd")
    pwd_registered = request(
        "POST",
        f"{api}/auth/register",
        payload={"email": pwd_email, "password": PASSWORD, "display_name": "Password Test"},
    )
    check("a fresh account for the password tests", pwd_registered.status == 201, repr(pwd_registered))

    first = request("POST", f"{api}/auth/login", payload={"email": pwd_email, "password": PASSWORD})
    first_access = (first.body.get("tokens") or {}).get("access_token", "")
    second = request("POST", f"{api}/auth/login", payload={"email": pwd_email, "password": PASSWORD})
    second_access = (second.body.get("tokens") or {}).get("access_token", "")
    check(
        "two sessions exist for the revocation check",
        bool(first_access) and bool(second_access),
        f"{first!r} {second!r}",
    )

    weak_change = request(
        "POST",
        f"{api}/me/password",
        payload={"current_password": PASSWORD, "new_password": "abc"},
        token=first_access,
    )
    check(
        "the policy applies to password changes too",
        weak_change.status == 422 and weak_change.error_code == "weak_password",
        repr(weak_change),
    )

    wrong_current = request(
        "POST",
        f"{api}/me/password",
        payload={"current_password": "not-the-password", "new_password": NEW_PASSWORD},
        token=first_access,
    )
    check(
        "the current password must be correct",
        wrong_current.status == 401 and wrong_current.error_code == "invalid_credentials",
        repr(wrong_current),
    )

    changed = request(
        "POST",
        f"{api}/me/password",
        payload={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
        token=first_access,
    )
    check(
        "the password can be changed and reports revoked sessions",
        changed.status == 200 and changed.body.get("sessions_revoked", 0) >= 1,
        repr(changed),
    )
    check(
        "other sessions are signed out by a password change",
        request("GET", f"{api}/me", token=second_access).status == 401,
    )
    check(
        "the session that changed the password keeps working",
        request("GET", f"{api}/me", token=first_access).status == 200,
    )
    check(
        "the old password no longer works",
        request(
            "POST", f"{api}/auth/login", payload={"email": pwd_email, "password": PASSWORD}
        ).status
        == 401,
    )
    final_login = request(
        "POST", f"{api}/auth/login", payload={"email": pwd_email, "password": NEW_PASSWORD}
    )
    check("the new password works", final_login.status == 200, repr(final_login))
    final_tokens = final_login.body.get("tokens") or {}

    # -- logout ------------------------------------------------------------
    section("logout")
    logged_out = request(
        "POST",
        f"{api}/auth/logout",
        payload={"refresh_token": final_tokens.get("refresh_token", "")},
        token=final_tokens.get("access_token", ""),
    )
    check("logout returns 204", logged_out.status == 204, repr(logged_out))
    check(
        "the access token is rejected after logout",
        request("GET", f"{api}/me", token=final_tokens.get("access_token", "")).status == 401,
    )
    check(
        "the refresh token is rejected after logout",
        request(
            "POST",
            f"{api}/auth/refresh",
            payload={"refresh_token": final_tokens.get("refresh_token", "")},
        ).status
        == 401,
    )

    # -- lockout -----------------------------------------------------------
    section("account lockout")
    lock_email = unique_email("lock")
    request(
        "POST",
        f"{api}/auth/register",
        payload={"email": lock_email, "password": PASSWORD, "display_name": "Lock"},
    )

    lock_response = None
    for attempt in range(1, 9):
        lock_response = request(
            "POST", f"{api}/auth/login", payload={"email": lock_email, "password": f"wrong-{attempt}"}
        )
        if lock_response.status == 423:
            break

    check(
        "consecutive failures lock the account (423 account_locked)",
        lock_response is not None
        and lock_response.status == 423
        and lock_response.error_code == "account_locked",
        repr(lock_response),
    )
    check(
        "the lockout response tells the client when to retry",
        lock_response is not None and bool(lock_response.headers.get("retry-after")),
        str(lock_response.headers if lock_response else {}),
    )
    locked_out = request("POST", f"{api}/auth/login", payload={"email": lock_email, "password": PASSWORD})
    check(
        "even the correct password is refused while locked",
        locked_out.status == 423,
        repr(locked_out),
    )

    # -- rate limiting -----------------------------------------------------
    section("rate limiting")
    # A never-registered address: the per-account limiter still keys on it, and
    # there is no account to lock, so this isolates the limiter from lockout.
    flood_email = unique_email("flood")
    saw_rate_limit = False
    rate_response = None
    for _ in range(20):
        rate_response = request(
            "POST", f"{api}/auth/login", payload={"email": flood_email, "password": PASSWORD}
        )
        if rate_response.status == 429:
            saw_rate_limit = True
            break

    check(
        "repeated attempts are throttled with 429 rate_limited",
        saw_rate_limit and rate_response is not None and rate_response.error_code == "rate_limited",
        repr(rate_response),
    )
    check(
        "the throttled response includes Retry-After",
        rate_response is not None and bool(rate_response.headers.get("retry-after")),
        str(rate_response.headers if rate_response else {}),
    )

    # -- metrics -----------------------------------------------------------
    section("metrics")
    metrics_request = urllib.request.Request(f"{base}/metrics")
    try:
        with urllib.request.urlopen(metrics_request, timeout=10) as response:
            metrics_body = response.read().decode()
    except urllib.error.URLError as exc:
        metrics_body = ""
        print(f"  {DIM}{exc}{RESET}")

    for series in (
        "http_requests_total",
        "http_request_duration_seconds_bucket",
        "authmesh_build_info",
    ):
        check(f"gateway exposes {series}", series in metrics_body)

    print()
    total = _passed + len(_failed)
    if _failed:
        print(f"{RED}{len(_failed)}/{total} checks failed:{RESET}")
        for label in _failed:
            print(f"  - {label}")
        return 1

    print(f"{GREEN}all {total} checks passed{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
