"""Password hashing and policy.

Two implementation notes that matter:

* bcrypt silently truncates input at 72 bytes, so a long passphrase would have
  its tail ignored. Passwords are pre-hashed with SHA-256 and base64-encoded
  (44 bytes) before bcrypt sees them, which removes the truncation issue and the
  NUL-byte issue in one step. The scheme is recorded in the stored hash prefix so
  a future migration can tell the formats apart.
* bcrypt is CPU-bound by design. Calling it on the event loop would stall every
  other in-flight RPC for the duration, so hashing and verification are pushed to
  a worker thread.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import re
import secrets

import bcrypt

from authmesh_common.errors import AppError, ErrorCode

# Marks hashes produced by the sha256-then-bcrypt scheme described above.
SCHEME_PREFIX = "bs256$"


def _prepare(password: str) -> bytes:
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password_sync(password: str, rounds: int = 12) -> str:
    hashed = bcrypt.hashpw(_prepare(password), bcrypt.gensalt(rounds=rounds))
    return SCHEME_PREFIX + hashed.decode("ascii")


def verify_password_sync(password: str, stored: str) -> bool:
    if not stored:
        return False
    if stored.startswith(SCHEME_PREFIX):
        candidate = _prepare(password)
        encoded = stored[len(SCHEME_PREFIX) :].encode("ascii")
    else:
        # Legacy/raw bcrypt hash (e.g. imported from another system).
        candidate = password.encode("utf-8")[:72]
        encoded = stored.encode("ascii")
    try:
        return bcrypt.checkpw(candidate, encoded)
    except ValueError:
        return False


async def hash_password(password: str, rounds: int = 12) -> str:
    return await asyncio.to_thread(hash_password_sync, password, rounds)


async def verify_password(password: str, stored: str) -> bool:
    return await asyncio.to_thread(verify_password_sync, password, stored)


# A hash of a value nobody can produce, used to keep the timing of "unknown
# email" indistinguishable from "wrong password".
_DUMMY_HASH = hash_password_sync(secrets.token_urlsafe(32), rounds=12)


async def waste_time_like_a_verification() -> None:
    """Burn a comparable amount of CPU when the account does not exist.

    Without this, an attacker can enumerate valid emails by timing: the
    non-existent case would return in microseconds while a real account pays for
    bcrypt.
    """
    await asyncio.to_thread(verify_password_sync, "not-the-password", _DUMMY_HASH)


_SYMBOL_RE = re.compile(r"[^A-Za-z0-9]")

# A small deny list of the passwords credential-stuffing tools try first. This is
# not a substitute for a breach corpus check, but it removes the worst offenders
# that still satisfy a length-and-classes policy.
_COMMON_PASSWORDS = frozenset(
    {
        "password",
        "password1",
        "password123",
        "passw0rd123",
        "123456789012",
        "qwertyuiop123",
        "letmein12345",
        "administrator",
        "welcome123456",
        "iloveyou1234",
        "changeme1234",
        "correcthorsebatterystaple",
    }
)


def validate_password_policy(
    password: str,
    *,
    min_length: int,
    max_length: int,
    require_mixed_case: bool,
    require_digit: bool,
    require_symbol: bool,
    email: str | None = None,
) -> None:
    """Raise `AppError(WEAK_PASSWORD)` with every failed rule listed."""
    problems: list[str] = []

    if len(password) < min_length:
        problems.append(f"must be at least {min_length} characters")
    if len(password) > max_length:
        problems.append(f"must be at most {max_length} characters")
    if require_mixed_case and (password.lower() == password or password.upper() == password):
        problems.append("must contain both upper and lower case letters")
    if require_digit and not any(ch.isdigit() for ch in password):
        problems.append("must contain a digit")
    if require_symbol and not _SYMBOL_RE.search(password):
        problems.append("must contain a symbol")
    if password.lower() in _COMMON_PASSWORDS:
        problems.append("is too common")
    if email:
        local_part = email.split("@", 1)[0].lower()
        if len(local_part) >= 3 and local_part in password.lower():
            problems.append("must not contain your email address")

    if problems:
        raise AppError(
            ErrorCode.WEAK_PASSWORD,
            "password does not meet the policy: " + "; ".join(problems),
            details={"violations": problems},
        )


# -- recovery codes ---------------------------------------------------------

_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no look-alike characters


def generate_recovery_code() -> str:
    part = lambda: "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(5))  # noqa: E731
    return f"{part()}-{part()}"


def hash_recovery_code(code: str, pepper: str) -> str:
    """Keyed hash of a recovery code.

    Recovery codes are generated with ~50 bits of entropy, so they are not
    brute-forceable from a stolen hash the way a human-chosen password is. A
    single HMAC-SHA256 is therefore sufficient and lets us check a code against
    all ten stored hashes without ten bcrypt evaluations.
    """
    normalized = code.strip().lower().replace(" ", "")
    return hmac.new(pepper.encode(), normalized.encode(), hashlib.sha256).hexdigest()


def find_matching_recovery_code(code: str, hashes: list[str], pepper: str) -> int | None:
    """Index of the matching hash, or None. Compares in constant time per entry."""
    candidate = hash_recovery_code(code, pepper)
    match_index: int | None = None
    for index, stored in enumerate(hashes):
        if hmac.compare_digest(candidate, stored) and match_index is None:
            match_index = index
    return match_index
