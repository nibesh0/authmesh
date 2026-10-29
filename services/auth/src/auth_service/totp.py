"""TOTP second factor.

The shared secret is the whole ballgame: anyone who reads it can generate valid
codes forever. It is therefore encrypted with Fernet (AES-128-CBC + HMAC) before
it is handed to the user-service, so a Mongo backup or a read-only database
compromise does not yield working second factors. The key lives only in the
auth-service's Secret.

Enrollment is two-phase - `EnrollTotp` returns a secret that is stored but marked
inactive, and only a correct code in `ActivateTotp` flips `totp_enabled`. That
prevents a user from locking themselves out with a mistyped authenticator setup.
"""

from __future__ import annotations

import asyncio
import secrets

import pyotp
from cryptography.fernet import Fernet, InvalidToken

from authmesh_common.errors import AppError, ErrorCode
from authmesh_common.logging import get_logger

from .settings import AuthServiceSettings

log = get_logger(__name__)


class TotpService:
    def __init__(self, settings: AuthServiceSettings) -> None:
        self._settings = settings
        try:
            self._fernet = Fernet(settings.totp_encryption_key.encode())
        except (ValueError, TypeError) as exc:
            raise ValueError(
                "TOTP_ENCRYPTION_KEY is not a valid Fernet key; generate one with "
                "python -c \"from cryptography.fernet import Fernet; "
                "print(Fernet.generate_key().decode())\""
            ) from exc

    # -- secret handling ---------------------------------------------------

    @staticmethod
    def generate_secret() -> str:
        # 32 base32 chars = 160 bits, the length RFC 6238 recommends for SHA-1.
        return pyotp.random_base32(length=32)

    def encrypt_secret(self, secret: str) -> str:
        return self._fernet.encrypt(secret.encode()).decode()

    def decrypt_secret(self, encrypted: str) -> str:
        try:
            return self._fernet.decrypt(encrypted.encode()).decode()
        except (InvalidToken, ValueError) as exc:
            # Almost always a key rotation without re-encryption. Surfacing this
            # as "2FA is broken for this account" is better than a 500 loop.
            log.error("failed to decrypt totp secret")
            raise AppError(
                ErrorCode.FAILED_PRECONDITION,
                "stored second factor cannot be read; re-enroll is required",
            ) from exc

    # -- codes -------------------------------------------------------------

    def _totp(self, secret: str) -> pyotp.TOTP:
        return pyotp.TOTP(
            secret,
            digits=self._settings.totp_digits,
            interval=self._settings.totp_interval_seconds,
        )

    def provisioning_uri(self, secret: str, account_name: str) -> str:
        return self._totp(secret).provisioning_uri(
            name=account_name, issuer_name=self._settings.totp_issuer_name
        )

    def verify_code(self, secret: str, code: str) -> bool:
        normalized = (code or "").strip().replace(" ", "")
        if not normalized.isdigit() or len(normalized) != self._settings.totp_digits:
            return False
        return self._totp(secret).verify(
            normalized, valid_window=self._settings.totp_valid_window
        )

    async def verify_encrypted(self, encrypted_secret: str, code: str) -> bool:
        secret = self.decrypt_secret(encrypted_secret)
        # Cheap, but decrypt + HMAC in a thread keeps the loop free under load.
        return await asyncio.to_thread(self.verify_code, secret, code)

    def current_code(self, secret: str) -> str:
        """Only used by tests and the local smoke script."""
        return self._totp(secret).now()

    # -- recovery codes ----------------------------------------------------

    def generate_recovery_codes(self) -> list[str]:
        from .passwords import generate_recovery_code

        return [
            generate_recovery_code() for _ in range(self._settings.recovery_code_count)
        ]

    @staticmethod
    def looks_like_recovery_code(value: str) -> bool:
        candidate = (value or "").strip().lower()
        return "-" in candidate and not candidate.replace("-", "").isdigit()


def constant_time_token() -> str:
    return secrets.token_urlsafe(16)
