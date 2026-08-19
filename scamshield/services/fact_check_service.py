"""Google Fact Check Tools API integration."""

import re
from functools import lru_cache

import requests

from scamshield.config import Config

FACT_CHECK_URL = "https://factchecktools.googleapis.com/v1alpha1/claims:search"


def _normalize_query(query: str) -> str:
    """Reduce input to one short, claim-like query."""
    compact = re.sub(r"\s+", " ", (query or "").strip())
    if not compact:
        return ""
    first_sentence = re.split(r"(?<=[.!?])\s+", compact, maxsplit=1)[0]
    return min((first_sentence, compact[:120]), key=len)


def _empty_result(error=None) -> dict:
    return {
        "checked": False,
        "matches_found": False,
        "verdicts": [],
        "error": error,
    }


@lru_cache(maxsize=256)
def _search_cached(query: str, api_key: str) -> dict:
    """Perform one cached API lookup for a normalized query and key."""
    try:
        response = requests.get(
            FACT_CHECK_URL,
            params={"query": query, "key": api_key},
            timeout=5,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.Timeout:
        return _empty_result("request timeout")
    except requests.RequestException as exc:
        return _empty_result(str(exc)[:160] or "request failed")
    except (ValueError, TypeError):
        return _empty_result("invalid JSON response")

    claims = payload.get("claims", []) if isinstance(payload, dict) else []
    verdicts = []
    for claim in claims[:3]:
        for review in claim.get("claimReview", [])[:1]:
            rating = review.get("textualRating", "").strip()
            publisher = review.get("publisher", {}) or {}
            verdicts.append({
                "rating": rating,
                "publisher": publisher.get("name", "").strip(),
                "url": review.get("url", "").strip(),
            })
            if len(verdicts) == 3:
                break
        if len(verdicts) == 3:
            break

    return {
        "checked": True,
        "matches_found": bool(claims),
        "verdicts": verdicts,
        "error": None,
    }


class FactCheckService:
    """Look up claims using Google's optional fact-checking API."""

    def search_claims(self, query: str) -> dict:
        """Return normalized fact-check results without raising network errors."""
        api_key = Config.GOOGLE_FACT_CHECK_API_KEY
        if not api_key:
            return _empty_result("not_configured")

        normalized_query = _normalize_query(query)
        if not normalized_query:
            return _empty_result("empty_query")
        return _search_cached(normalized_query, api_key)
