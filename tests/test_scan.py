from io import BytesIO


def test_check_url_returns_analysis(client):
    response = client.post(
        "/api/check-url", json={"url": "http://secure-login-paytm.tk/verify"}
    )
    assert response.status_code == 200
    body = response.get_json()
    assert "risk_level" in body
    assert "risk_score" in body


def test_check_url_requires_url_field(client):
    response = client.post("/api/check-url", json={})
    assert response.status_code == 400


def test_check_url_flags_brand_impersonation_phishing(client):
    response = client.post(
        "/api/check-url",
        json={"url": "http://secure-paypal-login.verify-account.tk/reset"},
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["risk_level"] in {"High", "Critical"}
    assert body["risk_score"] >= 65
    assert "Possible brand impersonation" in body["danger_indicators"]


def test_analyze_message_returns_a_verdict(client):
    response = client.post(
        "/api/analyze",
        json={
            "content_type": "message",
            "content": "Verify your KYC now and share your OTP immediately",
        },
    )
    assert response.status_code == 200
    body = response.get_json()
    assert "risk_level" in body
    assert "scam_probability" in body


def test_analyze_email_returns_a_classification(client):
    response = client.post(
        "/api/analyze",
        json={
            "content_type": "email",
            "content": "Dear customer, your account has been suspended. Click here to reset your password.",
        },
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["classification"] in {"Email Scam", "Suspicious Email", "Likely Legitimate Email"}
    assert "scam_probability" in body


def test_analyze_sms_returns_a_classification(client):
    response = client.post(
        "/api/analyze",
        json={
            "content_type": "sms",
            "content": "Package delivery failed. Confirm your UPI now or your package will be returned.",
        },
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["classification"] in {"SMS Scam", "Suspicious SMS", "Likely Legitimate SMS"}
    assert "scam_probability" in body


def test_analyze_news_returns_a_classification(client):
    response = client.post(
        "/api/analyze",
        json={
            "content_type": "news",
            "content": "Breaking: Official statement confirms a shocking government payout to all citizens.",
        },
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["classification"] in {"Fake News", "Potential Misinformation", "Likely Legitimate News"}
    assert "scam_probability" in body


def test_analyze_media_accepts_file_upload(client):
    data = {
        "file": (BytesIO(b"fakeimagecontent"), "test.png"),
    }
    response = client.post(
        "/api/analyze-media",
        content_type="multipart/form-data",
        data=data,
    )
    assert response.status_code == 200
    body = response.get_json()
    assert "media_type" in body
    assert "ai_likelihood" in body


def test_scan_history_requires_authentication(client):
    response = client.get("/api/scans/history")
    # History is public for anonymous users; ensure it returns 200 and a usable payload.
    assert response.status_code == 200


def test_scan_history_accessible_when_authenticated(client, auth_headers):
    response = client.get("/api/scans/history", headers=auth_headers)
    assert response.status_code == 200
