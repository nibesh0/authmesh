"""Password hashing, policy enforcement and recovery codes."""

from __future__ import annotations

import pytest

from authmesh_common.errors import AppError, ErrorCode
from auth_service import passwords

from .conftest import TEST_PEPPER

POLICY = dict(
    min_length=12,
    max_length=256,
    require_mixed_case=True,
    require_digit=True,
    require_symbol=False,
)


def test_hash_is_salted_and_verifiable() -> None:
    first = passwords.hash_password_sync("Correct-Horse-42", rounds=4)
    second = passwords.hash_password_sync("Correct-Horse-42", rounds=4)

    assert first != second, "identical passwords must not produce identical hashes"
    assert passwords.verify_password_sync("Correct-Horse-42", first)
    assert passwords.verify_password_sync("Correct-Horse-42", second)
    assert not passwords.verify_password_sync("Correct-Horse-43", first)


def test_hash_records_its_scheme() -> None:
    hashed = passwords.hash_password_sync("Correct-Horse-42", rounds=4)
    assert hashed.startswith(passwords.SCHEME_PREFIX)


def test_long_passphrases_are_not_truncated() -> None:
    """bcrypt ignores input past 72 bytes. Pre-hashing with SHA-256 means two
    passphrases that share a 72-byte prefix still produce different hashes."""
    prefix = "A1" + "x" * 80
    hashed = passwords.hash_password_sync(prefix + "-ending-one", rounds=4)

    assert passwords.verify_password_sync(prefix + "-ending-one", hashed)
    assert not passwords.verify_password_sync(prefix + "-ending-two", hashed)


def test_verify_tolerates_malformed_stored_hash() -> None:
    assert not passwords.verify_password_sync("anything", "")
    assert not passwords.verify_password_sync("anything", "not-a-bcrypt-hash")


@pytest.mark.parametrize(
    ("password", "expected_fragment"),
    [
        ("Short1", "at least 12"),
        ("alllowercase123", "upper and lower"),
        ("NoDigitsInHere", "must contain a digit"),
        ("password123", "too common"),
    ],
)
def test_policy_rejects_weak_passwords(password: str, expected_fragment: str) -> None:
    with pytest.raises(AppError) as exc_info:
        passwords.validate_password_policy(password, **POLICY)

    assert exc_info.value.code is ErrorCode.WEAK_PASSWORD
    violations = " ".join(exc_info.value.details["violations"])
    assert expected_fragment in violations


def test_policy_reports_every_violation_at_once() -> None:
    with pytest.raises(AppError) as exc_info:
        passwords.validate_password_policy("short", **POLICY)

    violations = exc_info.value.details["violations"]
    # Too short, no upper case, no digit: the user should not have to guess three
    # times.
    assert len(violations) >= 3


def test_policy_rejects_password_containing_the_email() -> None:
    with pytest.raises(AppError):
        passwords.validate_password_policy(
            "Marcos-Is-My-Password1", email="marcos@example.com", **POLICY
        )


def test_policy_accepts_a_reasonable_passphrase() -> None:
    passwords.validate_password_policy(
        "Tangerine-Ladder-77", email="user@example.com", **POLICY
    )


def test_symbol_requirement_is_optional() -> None:
    policy = {**POLICY, "require_symbol": True}
    with pytest.raises(AppError):
        passwords.validate_password_policy("NoSymbolsHere123", **policy)
    passwords.validate_password_policy("With-Symbols123", **policy)


def test_max_length_is_enforced() -> None:
    with pytest.raises(AppError):
        passwords.validate_password_policy("Aa1" + "x" * 300, **POLICY)


# -- recovery codes ---------------------------------------------------------


def test_recovery_code_format() -> None:
    code = passwords.generate_recovery_code()
    left, _, right = code.partition("-")
    assert len(left) == 5 and len(right) == 5
    # Look-alike characters are excluded so a code can be read off a screen.
    assert not set(code) & set("ilo01")


def test_recovery_codes_are_unique() -> None:
    codes = {passwords.generate_recovery_code() for _ in range(200)}
    assert len(codes) == 200


def test_recovery_code_hash_is_deterministic_and_keyed() -> None:
    code = "abcde-fghij"
    assert passwords.hash_recovery_code(code, TEST_PEPPER) == passwords.hash_recovery_code(
        code, TEST_PEPPER
    )
    assert passwords.hash_recovery_code(code, TEST_PEPPER) != passwords.hash_recovery_code(
        code, "a-different-pepper"
    )


def test_recovery_code_matching_is_case_and_space_insensitive() -> None:
    codes = ["abcde-fghij", "kmnpq-rstuv"]
    hashes = [passwords.hash_recovery_code(code, TEST_PEPPER) for code in codes]

    assert passwords.find_matching_recovery_code(" ABCDE-FGHIJ ", hashes, TEST_PEPPER) == 0
    assert passwords.find_matching_recovery_code("kmnpq-rstuv", hashes, TEST_PEPPER) == 1
    assert passwords.find_matching_recovery_code("zzzzz-zzzzz", hashes, TEST_PEPPER) is None


def test_recovery_code_lookup_on_empty_list() -> None:
    assert passwords.find_matching_recovery_code("abcde-fghij", [], TEST_PEPPER) is None
