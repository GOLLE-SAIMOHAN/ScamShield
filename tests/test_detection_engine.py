"""Regression tests for the modular URL detection engine."""

from scamshield.detection.engine import ScanEngine


def test_scan_engine_flags_brand_impersonation_in_subdomain():
    result = ScanEngine(whois_lookup=lambda domain: None).analyze_url(
        "http://secure-paypal-login.verify-account.tk/reset"
    )
    assert result["classification"] in {"High", "Malicious"}
    assert result["risk_score"] >= 65
    assert any("paypal" in reason.lower() for reason in result["reasons"])


def test_scan_engine_does_not_flag_the_brands_own_domain():
    result = ScanEngine(whois_lookup=lambda domain: None).analyze_url(
        "https://www.paypal.com/signin"
    )
    assert result["classification"] in {"Safe", "Low"}
    assert not any("brand" in reason.lower() for reason in result["reasons"])