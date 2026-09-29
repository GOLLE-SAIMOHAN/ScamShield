"""HTTP controllers for authentication."""

from flask import current_app, g, jsonify, request

from scamshield.repositories.exceptions import DuplicateRecordError
from scamshield.services.auth_service import (
    AuthService,
    AuthenticationError,
    TooManyLoginAttemptsError,
)
from scamshield.validators.auth_validator import (
    validate_login_payload,
    validate_password_reset_confirm_payload,
    validate_password_reset_request_payload,
    validate_registration_payload,
)


def _set_refresh_cookie(response, refresh_token_value: str):
    """Attach HttpOnly refresh token cookie to response."""
    if refresh_token_value:
        response.set_cookie(
            "refresh_token",
            refresh_token_value,
            httponly=True,
            secure=not current_app.config.get("DEBUG", False),
            samesite="Lax",
            path="/api/auth",
        )
    return response


def auth_status():
    """Return the current session authentication state."""
    return jsonify(AuthService.status())


def login():
    """Authenticate a demo analyst session."""
    payload = request.get_json(silent=True) or {}
    result, status_code = AuthService.login(payload)
    return jsonify(result), status_code


def logout():
    """Clear the active session."""
    return jsonify(AuthService.logout())


def register_user():
    """Register a new JWT-authenticated user."""
    payload = validate_registration_payload(request.get_json(silent=True) or {})
    try:
        result = AuthService.register(payload)
        refresh_val = result.pop("_refresh_token", "")
        response = jsonify(result)
        return _set_refresh_cookie(response, refresh_val), 201
    except DuplicateRecordError as error:
        response, status_code = AuthService.duplicate_response(error)
        return jsonify(response), status_code


def login_user():
    """Authenticate a JWT user with email and password."""
    payload = validate_login_payload(request.get_json(silent=True) or {})
    try:
        result = AuthService.login_with_password(payload)
        refresh_val = result.pop("_refresh_token", "")
        response = jsonify(result)
        return _set_refresh_cookie(response, refresh_val)
    except TooManyLoginAttemptsError:
        return (
            jsonify(
                {
                    "success": False,
                    "error": "Too many login attempts. Please try again later.",
                }
            ),
            429,
        )
    except AuthenticationError as error:
        return jsonify({"success": False, "error": str(error), "details": {}}), 401


def current_user():
    """Return the authenticated user loaded by middleware."""
    return jsonify(
        {
            "success": True,
            "message": "Current user loaded",
            "data": {"user": g.current_user},
        }
    )


def logout_user():
    """Revoke the presented JWT access token and refresh token."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip()
    cookie_refresh = request.cookies.get("refresh_token")
    result = AuthService.logout_token(token, refresh_token=cookie_refresh)
    response = jsonify(result)
    response.delete_cookie("refresh_token", path="/api/auth")
    return response


def refresh_token():
    """Exchange a refresh token for a new access token."""
    payload = request.get_json(silent=True) or {}
    token = (
        payload.get("refresh_token")
        or request.cookies.get("refresh_token")
        or ""
    ).strip()
    if not token:
        return (
            jsonify(
                {"success": False, "error": "refresh_token is required", "details": {}}
            ),
            400,
        )
    try:
        result = AuthService.refresh(token)
        response = jsonify(result)
        return response
    except AuthenticationError as error:
        return jsonify({"success": False, "error": str(error), "details": {}}), 401


def request_password_reset():
    """Request a password reset link for an email address."""
    payload = validate_password_reset_request_payload(request.get_json(silent=True) or {})
    return jsonify(AuthService.request_password_reset(payload["email"]))


def confirm_password_reset():
    """Confirm a password reset using a token and new password."""
    payload = validate_password_reset_confirm_payload(request.get_json(silent=True) or {})
    try:
        return jsonify(
            AuthService.confirm_password_reset(payload["token"], payload["new_password"])
        )
    except AuthenticationError as error:
        return jsonify({"success": False, "error": str(error), "details": {}}), 401


def admin_check():
    """Return a simple RBAC verification response for admins."""
    return jsonify(
        {
            "success": True,
            "message": "Admin access granted",
            "data": {"user": g.current_user},
        }
    )
