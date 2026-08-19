"""Tests for the optional Google Fact Check Tools integration."""

from unittest.mock import Mock, patch

import requests

from scamshield.config import Config
from scamshield.services.fact_check_service import FactCheckService, _search_cached


def setup_function():
    _search_cached.cache_clear()


def test_search_claims_skips_http_without_api_key(monkeypatch):
    monkeypatch.setattr(Config, "GOOGLE_FACT_CHECK_API_KEY", "")
    with patch("scamshield.services.fact_check_service.requests.get") as get:
        result = FactCheckService().search_claims("A claim")

    assert result == {
        "checked": False,
        "matches_found": False,
        "verdicts": [],
        "error": "not_configured",
    }
    get.assert_not_called()


def test_search_claims_parses_false_claim(monkeypatch):
    monkeypatch.setattr(Config, "GOOGLE_FACT_CHECK_API_KEY", "test-key")
    response = Mock()
    response.json.return_value = {
        "claims": [{
            "claimReview": [{
                "textualRating": "False",
                "url": "https://factcheck.example/false-claim",
                "publisher": {"name": "PolitiFact"},
            }],
        }],
    }
    with patch(
        "scamshield.services.fact_check_service.requests.get",
        return_value=response,
    ) as get:
        result = FactCheckService().search_claims("A claim. Extra context that should be omitted")

    assert result["checked"] is True
    assert result["matches_found"] is True
    assert result["verdicts"] == [{
        "rating": "False",
        "publisher": "PolitiFact",
        "url": "https://factcheck.example/false-claim",
    }]
    get.assert_called_once()
    assert get.call_args.kwargs["params"]["query"] == "A claim."


def test_search_claims_handles_timeout(monkeypatch):
    monkeypatch.setattr(Config, "GOOGLE_FACT_CHECK_API_KEY", "test-key-timeout")
    with patch(
        "scamshield.services.fact_check_service.requests.get",
        side_effect=requests.Timeout("timed out"),
    ):
        result = FactCheckService().search_claims("A timeout claim")

    assert result["checked"] is False
    assert "timeout" in result["error"].lower()


def test_search_claims_handles_empty_claims(monkeypatch):
    monkeypatch.setattr(Config, "GOOGLE_FACT_CHECK_API_KEY", "test-key-empty")
    response = Mock()
    response.json.return_value = {"claims": []}
    with patch(
        "scamshield.services.fact_check_service.requests.get",
        return_value=response,
    ):
        result = FactCheckService().search_claims("No matching claim")

    assert result == {
        "checked": True,
        "matches_found": False,
        "verdicts": [],
        "error": None,
    }
