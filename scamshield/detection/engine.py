"""Modular ScamShield scan engine."""

from urllib.parse import urlparse

from scamshield.detection.analyzers.domain_analyzer import DomainAnalyzer
from scamshield.detection.analyzers.keyword_analyzer import KeywordAnalyzer
from scamshield.detection.analyzers.reputation_analyzer import ReputationAnalyzer
from scamshield.detection.analyzers.ssl_analyzer import SslAnalyzer
from scamshield.detection.analyzers.url_analyzer import UrlAnalyzer
from scamshield.detection.scoring import score_results


class ScanEngine:
    """Coordinate URL analyzers and scoring."""

    def __init__(self, whois_lookup=None) -> None:
        self.analyzers = [
            UrlAnalyzer(),
            DomainAnalyzer(whois_lookup=whois_lookup),
            SslAnalyzer(),
            KeywordAnalyzer(),
            ReputationAnalyzer(),
        ]

    def analyze_url(self, url: str) -> dict:
        """Analyze a URL and return normalized risk output."""
        normalized_url = self._normalize_url(url)
        analyzer_results = [
            analyzer.analyze(normalized_url) for analyzer in self.analyzers
        ]
        result = score_results(normalized_url, analyzer_results)
        return {
            "url": result.url,
            "risk_score": result.risk_score,
            "classification": result.classification,
            "reasons": result.reasons,
            "confidence": result.confidence,
        }

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Ensure a URL has a scheme before analysis."""
        stripped = url.strip()
        parsed = urlparse(stripped)
        if parsed.scheme:
            return stripped
        return f"http://{stripped}"
