"""Local reputation analyzer foundation."""

from urllib.parse import urlparse

from scamshield.detection.models import AnalyzerFinding, AnalyzerResult

KNOWN_BAD_HOSTS = {
    "malware.test",
    "phishing.test",
}

class ReputationAnalyzer:
    """Analyze URL against local reputation indicators, including historical threat‑intelligence data."""

    name = "reputation"

    def analyze(self, url: str) -> AnalyzerResult:
        """Return local reputation findings, possibly enriched by historical data."""
        host = (urlparse(url).hostname or "").lower()
        findings = []
        if host in KNOWN_BAD_HOSTS:
            findings.append(
                AnalyzerFinding(
                    self.name,
                    "URL host appears in the local malicious reputation list.",
                    45,
                    confidence=95,
                )
            )
        # Historical threat‑intelligence check (conservative):
        # Only flag if a prior record exists with highest_risk >= 65.
        # Scan count alone does not trigger a finding.
        try:
            from scamshield.services.threat_intelligence_service import ThreatIntelligenceService
            record = ThreatIntelligenceService.get_domain(host)
            if (
                record
                and int(record.get("scan_count", 0)) > 1
                and record.get("highest_risk", 0) >= 65
            ):
                findings.append(
                    AnalyzerFinding(
                        self.name,
                        "Domain has historical high‑risk threat intelligence records.",
                        30,
                        confidence=80,
                    )
                )
        except Exception:
            # If service unavailable, ignore – do not fail the scan.
            pass
        return AnalyzerResult(self.name, findings)
