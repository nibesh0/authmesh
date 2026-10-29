"""TOTP secret handling and code verification."""

from __future__ import annotations

import base64
import time

import pytest

from authmesh_common.errors import AppError, ErrorCode
from auth_service.totp import TotpService

from .conftest import build_settings


def test_secret_is_base32_and_long_enough(totp: TotpService) -> None:
    secret = totp.generate_secret()
    assert len(secret) == 32
    # Must decode as base32 or no authenticator app will accept it.
    base64.b32decode(secret + "=" * (-len(secret) % 8))


def test_secrets_are_unique(totp: TotpService) -> None:
    assert len({totp.generate_secret() for _ in range(100)}) == 100


def test_secret_encryption_round_trip(totp: TotpService) -> None:
    secret = totp.generate_secret()
    encrypted = totp.encrypt_secret(secret)

    assert encrypted != secret
    assert secret not in encrypted, "the plaintext secret must not be recoverable by eye"
    assert totp.decrypt_secret(encrypted) == secret


def test_encryption_is_non_deterministic(totp: TotpService) -> None:
    """Fernet includes a random IV, so the same secret encrypts differently each
    time and two users with the same secret are not detectable from ciphertext."""
    secret = totp.generate_secret()
    assert totp.encrypt_secret(secret) != totp.encrypt_secret(secret)


def test_decrypting_with_the_wrong_key_fails_cleanly(totp: TotpService) -> None:
    encrypted = totp.encrypt_secret(totp.generate_secret())

    other_key = base64.urlsafe_b64encode(b"another-fernet-key-32-bytes!!!!!").decode()
    other = TotpService(build_settings(totp_encryption_key=other_key))

    with pytest.raises(AppError) as exc_info:
        other.decrypt_secret(encrypted)
    # Not a 500: the account needs to re-enroll, and the message says so.
    assert exc_info.value.code is ErrorCode.FAILED_PRECONDITION


def test_tampered_ciphertext_is_rejected(totp: TotpService) -> None:
    encrypted = totp.encrypt_secret(totp.generate_secret())
    tampered = encrypted[:-4] + ("AAAA" if not encrypted.endswith("AAAA") else "BBBB")
    with pytest.raises(AppError):
        totp.decrypt_secret(tampered)


def test_current_code_verifies(totp: TotpService) -> None:
    secret = totp.generate_secret()
    assert totp.verify_code(secret, totp.current_code(secret))


def test_wrong_code_is_rejected(totp: TotpService) -> None:
    secret = totp.generate_secret()
    current = totp.current_code(secret)
    wrong = "000000" if current != "000000" else "111111"
    assert not totp.verify_code(secret, wrong)


def test_code_from_a_different_secret_is_rejected(totp: TotpService) -> None:
    mine, theirs = totp.generate_secret(), totp.generate_secret()
    assert not totp.verify_code(mine, totp.current_code(theirs))


@pytest.mark.parametrize("candidate", ["", "12345", "1234567", "abcdef", "12 34 56", None])
def test_malformed_codes_are_rejected(totp: TotpService, candidate) -> None:
    secret = totp.generate_secret()
    assert not totp.verify_code(secret, candidate)


def test_previous_step_is_accepted_within_the_skew_window(totp: TotpService) -> None:
    """A user who types the code as it rolls over should not be rejected."""
    import pyotp

    secret = totp.generate_secret()
    previous = pyotp.TOTP(secret).at(time.time() - 30)
    assert totp.verify_code(secret, previous)


def test_codes_outside_the_window_are_rejected(totp: TotpService) -> None:
    import pyotp

    secret = totp.generate_secret()
    stale = pyotp.TOTP(secret).at(time.time() - 300)
    assert not totp.verify_code(secret, stale)


def test_provisioning_uri_contains_issuer_and_account(totp: TotpService) -> None:
    uri = totp.provisioning_uri(totp.generate_secret(), "user@example.com")
    assert uri.startswith("otpauth://totp/")
    assert "issuer=authmesh" in uri
    assert "user%40example.com" in uri or "user@example.com" in uri


def test_recovery_code_generation_count(totp: TotpService) -> None:
    codes = totp.generate_recovery_codes()
    assert len(codes) == 10
    assert len(set(codes)) == 10


def test_recovery_code_detection() -> None:
    assert TotpService.looks_like_recovery_code("abcde-fghij")
    assert not TotpService.looks_like_recovery_code("123456")
    # A hyphenated numeric string is not a recovery code; it is a mistyped TOTP.
    assert not TotpService.looks_like_recovery_code("123-456")


def test_invalid_fernet_key_fails_at_construction() -> None:
    with pytest.raises(ValueError, match="Fernet key"):
        TotpService(build_settings(totp_encryption_key="not-a-valid-key"))
