import re


def test_register_returns_access_token_and_cookie(client):
    response = client.post(
        "/api/auth/register",
        json={
            "username": "alice",
            "email": "alice@example.com",
            "password": "StrongPass123",
        },
    )
    assert response.status_code in (200, 201)
    body = response.get_json()
    assert body["success"] is True
    assert body["data"]["access_token"]
    assert "refresh_token" not in body["data"]
    assert "refresh_token=" in response.headers.get("Set-Cookie", "")
    assert body["data"]["user"]["email"] == "alice@example.com"
    assert "password_hash" not in body["data"]["user"]


def test_register_rejects_duplicate_email(client, registered_user):
    response = client.post(
        "/api/auth/register",
        json={
            "username": "someoneelse",
            "email": registered_user["email"],
            "password": "AnotherPass123",
        },
    )
    assert response.status_code >= 400
    assert response.get_json()["success"] is False


def test_register_rejects_weak_password(client):
    response = client.post(
        "/api/auth/register",
        json={"username": "bob", "email": "bob@example.com", "password": "123"},
    )
    assert response.status_code == 400


def test_login_with_correct_credentials_succeeds(client, registered_user):
    response = client.post(
        "/api/auth/login",
        json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        },
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["data"]["access_token"]
    assert "refresh_token" not in body["data"]
    assert "refresh_token=" in response.headers.get("Set-Cookie", "")


def test_login_with_wrong_password_fails(client, registered_user):
    response = client.post(
        "/api/auth/login",
        json={"email": registered_user["email"], "password": "WrongPassword1"},
    )
    assert response.status_code == 401
    assert response.get_json()["success"] is False


def test_me_requires_authentication(client):
    response = client.get("/api/auth/me")
    assert response.status_code == 401


def test_me_returns_current_user_with_valid_token(client, auth_headers):
    response = client.get("/api/auth/me", headers=auth_headers)
    assert response.status_code == 200
    body = response.get_json()
    assert body["data"]["user"]["email"] == "testuser@example.com"


def test_logout_revokes_the_access_token(client, auth_headers):
    # Token works before logout.
    assert client.get("/api/auth/me", headers=auth_headers).status_code == 200

    logout_response = client.post("/api/auth/logout", headers=auth_headers)
    assert logout_response.status_code == 200

    # Same token must now be rejected.
    response = client.get("/api/auth/me", headers=auth_headers)
    assert response.status_code == 401


def test_refresh_token_issues_a_new_access_token(client, registered_user):
    response = client.post(
        "/api/auth/refresh",
        json={"refresh_token": registered_user["refresh_token"]},
    )
    assert response.status_code == 200
    body = response.get_json()
    new_token = body["data"]["access_token"]
    assert new_token
    assert new_token != registered_user["access_token"]

    check = client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {new_token}"}
    )
    assert check.status_code == 200


def test_refresh_with_invalid_token_fails(client):
    response = client.post(
        "/api/auth/refresh", json={"refresh_token": "not-a-real-token"}
    )
    assert response.status_code == 401


def test_refresh_requires_refresh_token_field(client):
    response = client.post("/api/auth/refresh", json={})
    assert response.status_code == 400


def test_password_reset_request_never_leaks_account_existence(client, registered_user):
    known = client.post(
        "/api/auth/password-reset/request", json={"email": registered_user["email"]}
    )
    unknown = client.post(
        "/api/auth/password-reset/request", json={"email": "nobody@example.com"}
    )
    assert known.status_code == unknown.status_code == 200
    assert known.get_json()["message"] == unknown.get_json()["message"]


def test_password_reset_full_flow(client, registered_user, caplog):
    caplog.set_level("WARNING")
    client.post(
        "/api/auth/password-reset/request", json={"email": registered_user["email"]}
    )

    token = None
    for record in caplog.records:
        match = re.search(r"token=([\w\-.]+)", record.getMessage())
        if match:
            token = match.group(1)
    assert token, "expected the reset link to be logged since SMTP isn't configured"

    confirm = client.post(
        "/api/auth/password-reset/confirm",
        json={"token": token, "new_password": "BrandNewPass123"},
    )
    assert confirm.status_code == 200

    old_login = client.post(
        "/api/auth/login",
        json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        },
    )
    assert old_login.status_code == 401

    new_login = client.post(
        "/api/auth/login",
        json={"email": registered_user["email"], "password": "BrandNewPass123"},
    )
    assert new_login.status_code == 200

    # Reusing the same reset token must fail (single-use).
    reuse = client.post(
        "/api/auth/password-reset/confirm",
        json={"token": token, "new_password": "AnotherPass456"},
    )
    assert reuse.status_code == 401


def test_password_reset_confirm_rejects_short_password(client, registered_user):
    response = client.post(
        "/api/auth/password-reset/confirm",
        json={"token": "irrelevant", "new_password": "short"},
    )
    assert response.status_code == 400


def test_login_sets_httponly_refresh_cookie(client, registered_user):
    response = client.post(
        "/api/auth/login",
        json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        },
    )
    assert response.status_code == 200
    cookie = response.headers.get("Set-Cookie", "")
    assert "refresh_token=" in cookie
    assert "HttpOnly" in cookie


def test_refresh_token_from_cookie(client, registered_user):
    login_resp = client.post(
        "/api/auth/login",
        json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        },
    )
    assert login_resp.status_code == 200
    assert "refresh_token=" in login_resp.headers.get("Set-Cookie", "")

    refresh_resp = client.post("/api/auth/refresh")
    assert refresh_resp.status_code == 200
    assert refresh_resp.get_json()["data"]["access_token"]


def test_legacy_session_does_not_bypass_jwt(client):
    with client.session_transaction() as sess:
        sess["authenticated"] = True
        sess["user"] = {"email": "attacker@example.com", "role": "user"}

    response = client.get("/api/auth/me")
    assert response.status_code == 401


def test_scan_deletion_authorization_enforced(client, registered_user, auth_headers):
    # User A creates a scan via API
    create_resp = client.post(
        "/api/scan/url",
        json={"url": "http://suspicious-domain.com"},
        headers=auth_headers,
    )
    assert create_resp.status_code == 200
    scan_id = create_resp.get_json()["scan_id"]

    # Register user B
    user_b_resp = client.post(
        "/api/auth/register",
        json={
            "username": "userb",
            "email": "userb@example.com",
            "password": "StrongPass123",
        },
    )
    user_b_token = user_b_resp.get_json()["data"]["access_token"]
    user_b_headers = {"Authorization": f"Bearer {user_b_token}"}

    # User B attempting to delete User A's scan must fail with 403 Forbidden
    del_resp = client.delete(f"/api/scans/{scan_id}", headers=user_b_headers)
    assert del_resp.status_code == 403

    # User A deleting their own scan must succeed with 200 OK
    owner_del_resp = client.delete(f"/api/scans/{scan_id}", headers=auth_headers)
    assert owner_del_resp.status_code == 200


def test_admin_role_enforcement(client, auth_headers):
    # Regular user calling admin-check receives 403
    response = client.get("/api/auth/admin-check", headers=auth_headers)
    assert response.status_code == 403
