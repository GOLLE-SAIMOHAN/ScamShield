"""Shared pytest fixtures for the ScamShield test suite."""

import os

import pytest

os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key")
os.environ.setdefault("MONGODB_URI", "")
os.environ.setdefault("API_RATE_LIMIT_MAX_REQUESTS", "1000")

from scamshield import create_app  # noqa: E402
from scamshield.middleware.api_rate_limiting import reset_rate_limit_state  # noqa: E402
from scamshield.repositories.database import reset_database_state  # noqa: E402


@pytest.fixture()
def app():
    """Provide a fresh Flask app with an isolated in-memory database per test."""
    reset_database_state()
    reset_rate_limit_state()
    application = create_app()
    application.config.update(TESTING=True)
    yield application
    reset_database_state()
    reset_rate_limit_state()


@pytest.fixture()
def client(app):
    """Provide a Flask test client bound to the isolated app."""
    return app.test_client()


@pytest.fixture()
def registered_user(client):
    """Register a user and return their credentials plus issued tokens."""
    import re

    payload = {
        "username": "testuser",
        "email": "testuser@example.com",
        "password": "StrongPass123",
    }
    response = client.post("/api/auth/register", json=payload)
    body = response.get_json()
    cookie_header = response.headers.get("Set-Cookie", "")
    match = re.search(r"refresh_token=([^;]+)", cookie_header)
    ref_token = match.group(1) if match else ""
    return {
        "email": payload["email"],
        "password": payload["password"],
        "access_token": body["data"]["access_token"],
        "refresh_token": ref_token,
        "user_id": body["data"]["user"]["user_id"],
    }


@pytest.fixture()
def auth_headers(registered_user):
    """Return Authorization headers for the registered test user."""
    return {"Authorization": f"Bearer {registered_user['access_token']}"}
