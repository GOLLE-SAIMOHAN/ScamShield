"""General-purpose IP-based rate limiting for the whole API.

This complements the login-specific rate limiter in rate_limiting.py.
Login attempts are limited per-email there; this module limits total
request volume per client IP across all /api/ routes, which protects
the more expensive endpoints (WHOIS lookups, SSL handshakes, media
analysis) from being hammered.

PRODUCTION DEPLOYMENT NOTE:
Rate-limiting state is held in-process using sliding-window timestamp logs.
For single-instance / single-worker deployments (e.g. Render / single Gunicorn worker),
this in-memory tracker provides lightweight, zero-dependency protection.
If scaling to multi-worker / load-balanced clusters in the future, migrate
`_request_log` storage to a shared Redis instance.
"""

from __future__ import annotations

from collections import defaultdict
from time import time

from flask import Flask, g, jsonify, request

# {ip: [timestamp, timestamp, ...]}
_request_log: dict[str, list[float]] = defaultdict(list)

# Paths that should never be rate limited (cheap, needed for uptime checks).
_EXEMPT_PATHS = {"/api/health"}


def register_api_rate_limiting(app: Flask) -> None:
    """Attach a before_request hook that enforces a per-IP request budget."""

    @app.before_request
    def enforce_rate_limit():
        if not request.path.startswith("/api/"):
            return None
        if request.path in _EXEMPT_PATHS:
            return None

        max_requests = app.config["API_RATE_LIMIT_MAX_REQUESTS"]
        window_seconds = app.config["API_RATE_LIMIT_WINDOW_SECONDS"]

        client_ip = _client_ip()
        now = time()
        cutoff = now - window_seconds

        recent = [t for t in _request_log[client_ip] if t >= cutoff]
        recent.append(now)
        _request_log[client_ip] = recent

        remaining = max(max_requests - len(recent), 0)
        g.rate_limit_remaining = remaining

        if len(recent) > max_requests:
            app.logger.warning(
                "api_rate_limited ip=%s path=%s count=%s",
                client_ip,
                request.path,
                len(recent),
            )
            response = jsonify(
                {
                    "success": False,
                    "error": "Too many requests. Please slow down and try again shortly.",
                    "details": {},
                }
            )
            response.status_code = 429
            response.headers["Retry-After"] = str(window_seconds)
            return response
        return None

    @app.after_request
    def add_rate_limit_headers(response):
        remaining = g.get("rate_limit_remaining")
        if remaining is not None:
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Limit"] = str(
                app.config["API_RATE_LIMIT_MAX_REQUESTS"]
            )
        return response


def _client_ip() -> str:
    """Return the best-effort client IP, honoring a single trusted proxy hop."""
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def reset_rate_limit_state() -> None:
    """Clear all tracked request history. Intended for use in tests."""
    _request_log.clear()
