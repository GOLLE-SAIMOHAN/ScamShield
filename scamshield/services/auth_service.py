"""Authentication business logic."""

from datetime import datetime, timezone
from uuid import uuid4

from flask import current_app, session

from scamshield.middleware.rate_limiting import (
    check_login_rate_limit,
    record_failed_login,
    reset_login_attempts,
)
from scamshield.repositories.exceptions import DuplicateRecordError
from scamshield.repositories.revoked_token_repository import RevokedTokenRepository
from scamshield.repositories.user_repository import UserRepository
from scamshield.security.jwt_tokens import (
    ExpiredTokenError,
    TokenError,
    decode_access_token,
    decode_password_reset_token,
    decode_refresh_token,
    generate_access_token,
    generate_password_reset_token,
    generate_refresh_token,
)
from scamshield.security.passwords import hash_password, verify_password
from scamshield.utils.email import send_password_reset_email


class AuthenticationError(ValueError):
    """Raised when authentication fails."""


class TooManyLoginAttemptsError(ValueError):
    """Raised when login attempts exceed the configured limit."""


class AuthService:
    """Authentication service for JWT users and legacy demo sessions."""

    @staticmethod
    def is_authenticated() -> bool:
        """Return whether the current legacy session is authenticated."""
        return bool(session.get("authenticated"))

    @classmethod
    def status(cls) -> dict:
        """Return legacy session authentication details."""
        return {"authenticated": cls.is_authenticated(), "user": session.get("user")}

    @staticmethod
    def login(payload: dict) -> tuple[dict, int]:
        """Validate demo credentials and create a legacy session."""
        email = (payload.get("email") or "").strip().lower()
        password = (payload.get("password") or "").strip()

        if (
            email == current_app.config["DEMO_EMAIL"]
            and password == current_app.config["DEMO_PASSWORD"]
        ):
            session["authenticated"] = True
            session["user"] = {"email": email, "name": "Demo Analyst", "role": "admin"}
            return {"success": True, "message": "Signed in successfully"}, 200

        current_app.logger.warning(
            "legacy_failed_login email=%s", email or "<empty>"
        )
        return {"error": "Invalid credentials"}, 401

    @staticmethod
    def logout() -> dict:
        """Clear the current legacy session."""
        session.clear()
        return {"success": True}

    @classmethod
    def register(cls, payload: dict) -> dict:
        """Register a new active user and return an access token."""
        password_hash = cls.hash_password(payload["password"])
        user = UserRepository.create(
            {
                "user_id": f"user-{uuid4()}",
                "username": payload["username"],
                "email": payload["email"],
                "password_hash": password_hash,
                "role": "user",
                "is_active": True,
                "last_login": None,
            }
        )
        token = cls.generate_access_token(user)
        refresh_token = generate_refresh_token(user)
        current_app.logger.info("user_registered user_id=%s", user["user_id"])
        return {
            "success": True,
            "message": "Registration successful",
            "data": {
                "user": cls._public_user(user),
                "access_token": token,
                "refresh_token": refresh_token,
            },
        }

    @classmethod
    def login_with_password(cls, payload: dict) -> dict:
        """Authenticate a user with email and password."""
        try:
            check_login_rate_limit(payload["email"])
        except ValueError as error:
            raise TooManyLoginAttemptsError(str(error)) from error

        user = UserRepository.find_by_email(payload["email"])
        if not user:
            cls._record_failed_login(payload["email"])
            raise AuthenticationError("Invalid email or password")

        if not user.get("is_active", True):
            current_app.logger.warning("inactive_user_login user_id=%s", user["user_id"])
            raise AuthenticationError("User account is inactive")

        if not cls.verify_password(payload["password"], user.get("password_hash", "")):
            cls._record_failed_login(payload["email"])
            raise AuthenticationError("Invalid email or password")

        reset_login_attempts(payload["email"])
        user["last_login"] = UserRepository.update_last_login(user["user_id"])
        token = cls.generate_access_token(user)
        refresh_token = generate_refresh_token(user)
        current_app.logger.info(
            "user_login_success user_id=%s email=%s",
            user["user_id"],
            user["email"],
        )
        return {
            "success": True,
            "message": "Login successful",
            "data": {
                "user": cls._public_user(user),
                "access_token": token,
                "refresh_token": refresh_token,
            },
        }

    @classmethod
    def refresh(cls, refresh_token: str) -> dict:
        """Exchange a valid refresh token for a new access token."""
        try:
            payload = decode_refresh_token(refresh_token)
        except ExpiredTokenError as error:
            raise AuthenticationError("Refresh token has expired") from error
        except TokenError as error:
            raise AuthenticationError("Invalid refresh token") from error

        if RevokedTokenRepository.is_revoked(payload["jti"]):
            raise AuthenticationError("Refresh token has been revoked")

        user = UserRepository.find_by_id(payload["sub"])
        if not user or not user.get("is_active", True):
            raise AuthenticationError("User not found or inactive")

        new_access_token = cls.generate_access_token(user)
        current_app.logger.info("access_token_refreshed user_id=%s", user["user_id"])
        return {
            "success": True,
            "message": "Token refreshed",
            "data": {"access_token": new_access_token},
        }

    @classmethod
    def request_password_reset(cls, email: str) -> dict:
        """Send a password reset link if the email belongs to a user.

        Always returns the same success response regardless of whether the
        account exists, so this endpoint can't be used to enumerate
        registered emails.
        """
        user = UserRepository.find_by_email(email)
        if user and user.get("is_active", True):
            reset_token = generate_password_reset_token(user)
            reset_link = (
                f"{current_app.config['FRONTEND_BASE_URL']}"
                f"/reset-password?token={reset_token}"
            )
            send_password_reset_email(user["email"], reset_link)
            current_app.logger.info(
                "password_reset_requested user_id=%s", user["user_id"]
            )
        else:
            current_app.logger.info("password_reset_requested_unknown_email")

        return {
            "success": True,
            "message": (
                "If an account with that email exists, a password reset "
                "link has been sent."
            ),
            "data": {},
        }

    @classmethod
    def confirm_password_reset(cls, token: str, new_password: str) -> dict:
        """Validate a reset token and set the account's new password."""
        try:
            payload = decode_password_reset_token(token)
        except ExpiredTokenError as error:
            raise AuthenticationError("Reset link has expired") from error
        except TokenError as error:
            raise AuthenticationError("Invalid reset link") from error

        if RevokedTokenRepository.is_revoked(payload["jti"]):
            raise AuthenticationError("Reset link has already been used")

        user = UserRepository.find_by_id(payload["sub"])
        if not user or not user.get("is_active", True):
            raise AuthenticationError("User not found or inactive")

        UserRepository.update_password(user["user_id"], cls.hash_password(new_password))

        # Single-use: revoke the reset token's jti immediately after success.
        expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        RevokedTokenRepository.revoke(payload["jti"], expires_at)

        current_app.logger.info("password_reset_completed user_id=%s", user["user_id"])
        return {
            "success": True,
            "message": "Password has been reset successfully.",
            "data": {},
        }

    @staticmethod
    def verify_token(token: str) -> dict:
        """Verify an access token and return its payload."""
        return decode_access_token(token)

    @classmethod
    def get_current_user(cls, token: str) -> dict:
        """Return the active user represented by a token."""
        payload = cls.verify_token(token)
        if RevokedTokenRepository.is_revoked(payload["jti"]):
            raise AuthenticationError("Token has been revoked")
        user = UserRepository.find_by_id(payload["sub"])
        if not user:
            raise AuthenticationError("User not found")
        if not user.get("is_active", True):
            raise AuthenticationError("User account is inactive")
        return cls._public_user(user)

    @staticmethod
    def generate_access_token(user: dict) -> str:
        """Generate a JWT access token for a user."""
        return generate_access_token(user)

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a plaintext password."""
        return hash_password(password)

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify a plaintext password against a stored hash."""
        return verify_password(password, password_hash)

    @classmethod
    def logout_token(cls, token: str, refresh_token: str | None = None) -> dict:
        """Revoke the presented access token and optional refresh token so they can no longer be used."""
        try:
            payload = cls.verify_token(token)
            expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
            RevokedTokenRepository.revoke(payload["jti"], expires_at)
            current_app.logger.info("access_token_revoked user_id=%s", payload["sub"])
        except TokenError:
            # Token was already invalid/expired; nothing to revoke.
            pass

        if refresh_token:
            try:
                ref_payload = decode_refresh_token(refresh_token)
                ref_expires_at = datetime.fromtimestamp(ref_payload["exp"], tz=timezone.utc)
                RevokedTokenRepository.revoke(ref_payload["jti"], ref_expires_at)
                current_app.logger.info("refresh_token_revoked user_id=%s", ref_payload["sub"])
            except TokenError:
                pass

        return {"success": True, "message": "Logged out successfully", "data": {}}

    @staticmethod
    def duplicate_response(error: DuplicateRecordError) -> tuple[dict, int]:
        """Return a structured duplicate registration response."""
        return {
            "success": False,
            "error": str(error),
            "details": {},
        }, 409

    @staticmethod
    def _public_user(user: dict) -> dict:
        """Return user fields safe for API responses."""
        return {
            "user_id": user["user_id"],
            "username": user["username"],
            "email": user["email"],
            "role": user.get("role", "user"),
            "is_active": user.get("is_active", True),
            "created_at": user.get("created_at"),
            "updated_at": user.get("updated_at"),
            "last_login": user.get("last_login"),
        }

    @staticmethod
    def _record_failed_login(email: str) -> None:
        """Record and log a failed login attempt."""
        record_failed_login(email)
        current_app.logger.warning("failed_login email=%s", email)


__all__ = [
    "AuthService",
    "AuthenticationError",
    "DuplicateRecordError",
    "ExpiredTokenError",
    "TooManyLoginAttemptsError",
    "TokenError",
]
