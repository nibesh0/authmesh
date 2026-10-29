"""Token minting and verification.

The properties under test are the ones an attacker would probe: can a token of
one type be used as another, does an expired or tampered token still validate,
and does a signing-key rotation keep old tokens working without accepting
forgeries.
"""

from __future__ import annotations

import time

import jwt
import pytest

from authmesh_common.errors import AppError, ErrorCode
from auth_service.tokens import TYPE_ACCESS, TYPE_REFRESH, TokenService

from .conftest import TEST_JWT_SECRET, build_settings


def test_access_token_round_trip(tokens: TokenService) -> None:
    issued = tokens.issue_access_token(
        user_id="user-1", email="a@example.com", roles=["user", "admin"], session_id="sess-1"
    )
    claims = tokens.verify_access_token(issued.token)

    assert claims.user_id == "user-1"
    assert claims.email == "a@example.com"
    assert claims.roles == ["user", "admin"]
    assert claims.session_id == "sess-1"
    assert claims.jti == issued.jti
    assert claims.expires_at > claims.issued_at


def test_refresh_token_carries_session_and_family(tokens: TokenService) -> None:
    issued = tokens.issue_refresh_token(
        user_id="user-1", session_id="sess-1", family="fam-1"
    )
    claims = tokens.verify_refresh_token(issued.token)

    assert claims.session_id == "sess-1"
    assert claims.family == "fam-1"
    assert claims.jti == issued.jti


def test_refresh_token_rejected_where_access_expected(tokens: TokenService) -> None:
    """The `typ` claim is what stops a long-lived refresh token being used as a
    bearer credential."""
    refresh = tokens.issue_refresh_token(
        user_id="user-1", session_id="sess-1", family="fam-1"
    )

    with pytest.raises(AppError) as exc_info:
        tokens.verify_access_token(refresh.token)

    assert exc_info.value.code is ErrorCode.UNAUTHENTICATED
    assert exc_info.value.details.get("expected_type") == TYPE_ACCESS
    assert exc_info.value.details.get("actual_type") == TYPE_REFRESH


def test_access_token_rejected_where_refresh_expected(tokens: TokenService) -> None:
    access = tokens.issue_access_token(
        user_id="user-1", email="a@example.com", roles=[], session_id="sess-1"
    )
    with pytest.raises(AppError):
        tokens.verify_refresh_token(access.token)


def test_mfa_token_is_not_an_access_token(tokens: TokenService) -> None:
    challenge = tokens.issue_mfa_token(user_id="user-1")
    with pytest.raises(AppError):
        tokens.verify_access_token(challenge.token)
    # ...but it does verify as itself.
    assert tokens.verify_mfa_token(challenge.token).user_id == "user-1"


def test_expired_token_reports_token_expired() -> None:
    service = TokenService(build_settings(access_token_ttl_seconds=1))
    issued = service.issue_access_token(
        user_id="user-1", email="a@example.com", roles=[], session_id="sess-1"
    )

    # The verifier allows 10s of clock skew, so the token has to be well past due.
    time.sleep(0)
    forged = jwt.encode(
        {
            **jwt.decode(issued.token, options={"verify_signature": False}),
            "exp": int(time.time()) - 3600,
            "iat": int(time.time()) - 7200,
            "nbf": int(time.time()) - 7200,
        },
        TEST_JWT_SECRET,
        algorithm="HS256",
    )

    with pytest.raises(AppError) as exc_info:
        service.verify_access_token(forged)
    assert exc_info.value.code is ErrorCode.TOKEN_EXPIRED


def test_token_signed_with_another_key_is_rejected(tokens: TokenService) -> None:
    other = TokenService(build_settings(jwt_secret="a-completely-different-secret-0123456789"))
    foreign = other.issue_access_token(
        user_id="attacker", email="e@example.com", roles=["admin"], session_id="s"
    )

    with pytest.raises(AppError) as exc_info:
        tokens.verify_access_token(foreign.token)
    assert exc_info.value.code is ErrorCode.UNAUTHENTICATED


def test_tampered_payload_is_rejected(tokens: TokenService) -> None:
    issued = tokens.issue_access_token(
        user_id="user-1", email="a@example.com", roles=["user"], session_id="sess-1"
    )
    # Re-sign an escalated payload with the wrong key: the signature must fail.
    payload = jwt.decode(issued.token, options={"verify_signature": False})
    payload["roles"] = ["admin"]
    tampered = jwt.encode(payload, "not-the-signing-key", algorithm="HS256")

    with pytest.raises(AppError):
        tokens.verify_access_token(tampered)


def test_wrong_audience_is_rejected(tokens: TokenService) -> None:
    other = TokenService(build_settings(jwt_audience="some-other-api"))
    foreign = other.issue_access_token(
        user_id="user-1", email="a@example.com", roles=[], session_id="s"
    )
    with pytest.raises(AppError):
        tokens.verify_access_token(foreign.token)


def test_secret_rotation_keeps_old_tokens_valid() -> None:
    """During a rotation the previous secret stays in the verify set, so nobody is
    signed out; new tokens are signed with the new secret only."""
    old = TokenService(build_settings(jwt_secret=TEST_JWT_SECRET))
    old_token = old.issue_access_token(
        user_id="user-1", email="a@example.com", roles=[], session_id="s"
    ).token

    rotated = TokenService(
        build_settings(
            jwt_secret="the-new-signing-secret-0123456789abcdefgh",
            jwt_secret_previous=TEST_JWT_SECRET,
        )
    )
    assert rotated.verify_access_token(old_token).user_id == "user-1"

    new_token = rotated.issue_access_token(
        user_id="user-1", email="a@example.com", roles=[], session_id="s"
    ).token
    # The pre-rotation service must not accept a token signed with the new key.
    with pytest.raises(AppError):
        old.verify_access_token(new_token)


def test_rotation_does_not_accept_arbitrary_keys() -> None:
    rotated = TokenService(
        build_settings(
            jwt_secret="the-new-signing-secret-0123456789abcdefgh",
            jwt_secret_previous=TEST_JWT_SECRET,
        )
    )
    forged = jwt.encode({"sub": "x", "typ": "access"}, "unrelated", algorithm="HS256")
    with pytest.raises(AppError):
        rotated.verify_access_token(forged)


def test_empty_token_is_rejected(tokens: TokenService) -> None:
    with pytest.raises(AppError):
        tokens.verify_access_token("")


def test_garbage_token_is_rejected(tokens: TokenService) -> None:
    with pytest.raises(AppError):
        tokens.verify_access_token("not-a-jwt-at-all")


def test_peek_expiry_reads_unverified_exp(tokens: TokenService) -> None:
    issued = tokens.issue_access_token(
        user_id="user-1", email="a@example.com", roles=[], session_id="s"
    )
    assert TokenService.peek_expiry(issued.token) == int(issued.expires_at.timestamp())
    assert TokenService.peek_expiry("garbage") is None


def test_jti_is_unique_per_token(tokens: TokenService) -> None:
    seen = {
        tokens.issue_access_token(
            user_id="u", email="e@example.com", roles=[], session_id="s"
        ).jti
        for _ in range(50)
    }
    assert len(seen) == 50
