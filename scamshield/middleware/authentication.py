"""Authentication and authorization decorators."""

from functools import wraps

from flask import g, jsonify, request, session

from scamshield.services.auth_service import (
    AuthService,
    AuthenticationError,
    ExpiredTokenError,
    TokenError,
)


def login_required(view_func):
    """Require a valid Bearer JWT."""

    @wraps(view_func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            log_unauthorized_access()
            return unauthorized("Authentication is required")

        token = auth_header.removeprefix("Bearer ").strip()
        if not token:
            log_unauthorized_access()
            return unauthorized("Authentication is required")

        try:
            g.current_user = AuthService.get_current_user(token)
        except ExpiredTokenError:
            current_logger().warning("expired_jwt path=%s", request.path)
            return unauthorized("Token has expired")
        except (TokenError, AuthenticationError):
            current_logger().warning("invalid_jwt path=%s", request.path)
            return unauthorized("Invalid token")

        return view_func(*args, **kwargs)

    return wrapper


def require_role(required_role: str):
    """Require an authenticated user with a specific role."""

    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def wrapper(*args, **kwargs):
            user = getattr(g, "current_user", {}) or {}
            if user.get("role") != required_role:
                current_logger().warning(
                    "permission_denied path=%s user_id=%s required_role=%s",
                    request.path,
                    user.get("user_id") or user.get("email"),
                    required_role,
                )
                return forbidden("Permission denied")
            return view_func(*args, **kwargs)

        return wrapper

    return decorator


require_authentication = login_required


def unauthorized(message: str):
    """Return a standard unauthorized response."""
    return jsonify({"success": False, "error": message, "details": {}}), 401


def forbidden(message: str):
    """Return a standard forbidden response."""
    return jsonify({"success": False, "error": message, "details": {}}), 403


def log_unauthorized_access() -> None:
    """Log a missing-credentials access attempt."""
    current_logger().warning("unauthorized_access path=%s", request.path)


def current_logger():
    """Return the current app logger lazily to avoid circular imports."""
    from flask import current_app

    return current_app.logger
