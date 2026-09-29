from io import BytesIO
from unittest.mock import patch


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


def test_analyze_news_fact_check_false_claim_overrides_keywords(client):
    fact_check = {
        "checked": True,
        "matches_found": True,
        "verdicts": [{
            "rating": "False",
            "publisher": "PolitiFact",
            "url": "https://factcheck.example/false",
        }],
        "error": None,
    }
    with patch(
        "scamshield.ai.detector.FactCheckService.search_claims",
        return_value=fact_check,
    ):
        response = client.post(
            "/api/analyze",
            json={"content_type": "news", "content": "A plain claim"},
        )

    body = response.get_json()
    assert body["classification"] == "Fake News"
    assert body["scam_probability"] >= 80
    assert any("Fact-check match" in item["name"] for item in body["indicators"])


def test_analyze_news_fact_check_true_claim_is_not_fake_news(client):
    fact_check = {
        "checked": True,
        "matches_found": True,
        "verdicts": [{
            "rating": "True",
            "publisher": "Reuters Fact Check",
            "url": "https://factcheck.example/true",
        }],
        "error": None,
    }
    with patch(
        "scamshield.ai.detector.FactCheckService.search_claims",
        return_value=fact_check,
    ):
        response = client.post(
            "/api/analyze",
            json={"content_type": "news", "content": "BREAKING SHOCKING"},
        )

    body = response.get_json()
    assert body["classification"] != "Fake News"
    assert body["scam_probability"] <= 15


def test_analyze_news_without_fact_check_match_keeps_keyword_score(client):
    fact_check = {
        "checked": True,
        "matches_found": False,
        "verdicts": [],
        "error": None,
    }
    with patch(
        "scamshield.ai.detector.FactCheckService.search_claims",
        return_value=fact_check,
    ):
        response = client.post(
            "/api/analyze",
            json={
                "content_type": "news",
                "content": "BREAKING EXCLUSIVE VIRAL SHOCKING MUST READ",
            },
        )

    body = response.get_json()
    assert body["classification"] == "Likely Legitimate News"
    assert body["scam_probability"] == 28
    assert any(item["name"] == "No independent fact-check found" for item in body["indicators"])


def test_analyze_media_accepts_file_upload(client):
    from PIL import Image
    buf = BytesIO()
    img = Image.new("RGB", (10, 10), color="blue")
    img.save(buf, format="PNG")
    buf.seek(0)

    data = {
        "file": (buf, "test.png"),
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


def test_authenticated_url_scan_is_saved_to_history(client, auth_headers):
    response = client.post(
        "/api/scan/url",
        json={"url": "https://account-security-paypal.example/login"},
        headers=auth_headers,
    )

    assert response.status_code == 200
    scan = response.get_json()
    assert scan["scan_id"].startswith("scan-")

    history_response = client.get("/api/scans/history", headers=auth_headers)
    assert history_response.status_code == 200
    history = history_response.get_json()["data"]
    assert any(item["scan_id"] == scan["scan_id"] for item in history["items"])


def test_strict_url_validation_accepts_valid_http_and_https(client):
    assert client.post("/api/check-url", json={"url": "https://example.com"}).status_code == 200
    assert client.post("/api/check-url", json={"url": "http://example.com"}).status_code == 200


def test_strict_url_validation_rejects_disallowed_schemes(client):
    disallowed = [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/hosts",
        "ftp://example.com",
        "gopher://example.com",
        "blob:https://example.com",
        "about:blank",
    ]
    for invalid_url in disallowed:
        response = client.post("/api/check-url", json={"url": invalid_url})
        assert response.status_code == 400
        assert "Unsupported URL scheme" in response.get_json()["message"]


def test_strict_url_validation_rejects_credentials_and_malformed_urls(client):
    invalid_urls = [
        "http://user:pass@example.com",
        "http://user@example.com",
        "http://",
        "https://",
    ]
    for invalid_url in invalid_urls:
        response = client.post("/api/check-url", json={"url": invalid_url})
        assert response.status_code == 400


def test_punycode_and_homograph_detection(client):
    from scamshield.detection.analyzers.domain_analyzer import DomainAnalyzer

    analyzer = DomainAnalyzer(whois_lookup=lambda d: None)

    # 1. Punycode (xn--) domain
    res_puny = analyzer.analyze("http://xn--pypal-4ve.com")
    assert any("Punycode" in f.reason for f in res_puny.findings)

    # 2. Unicode homograph (Cyrillic 'а')
    res_homo = analyzer.analyze("http://pаypal.com")
    assert any("homograph" in f.reason.lower() or "idn" in f.reason.lower() for f in res_homo.findings)

    # 3. Legitimate normal domain
    res_norm = analyzer.analyze("https://example.com")
    assert not any("brand" in f.reason.lower() or "homograph" in f.reason.lower() for f in res_norm.findings)

    # 4. Legitimate brand domain
    res_brand = analyzer.analyze("https://paypal.com")
    assert not any("impersonation" in f.reason.lower() for f in res_brand.findings)

    # 5. Obvious typosquat (paypa1.com)
    res_typo = analyzer.analyze("http://paypa1.com")
    assert any("typosquat" in f.reason.lower() or "similar" in f.reason.lower() for f in res_typo.findings)

    # 6. Nested brand impersonation (paypal.com.evil.example)
    res_nested = analyzer.analyze("http://paypal.com.evil.example")
    assert any("outside its official domain" in f.reason.lower() for f in res_nested.findings)
