"""Domain reputation and age analyzer."""

from datetime import datetime, timezone
from difflib import SequenceMatcher
import ipaddress
from urllib.parse import urlparse

from scamshield.detection.brand_signals import (
    BRANDS,
    HIGH_RISK_TLDS,
    SUSPICIOUS_HOSTNAME_PREFIXES,
)
from scamshield.detection.models import AnalyzerFinding, AnalyzerResult

try:
    import whois
except ImportError:  # pragma: no cover - optional dependency.
    whois = None


class DomainAnalyzer:
    """Analyze domain age, TLD, and hostname impersonation signals."""

    name = "domain"

    def __init__(self, whois_lookup=None) -> None:
        self._whois_lookup = whois_lookup or _get_creation_date

    def analyze(self, url: str) -> AnalyzerResult:
        """Return domain-level findings."""
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().strip(".")
        findings: list[AnalyzerFinding] = []
        if not host:
            return AnalyzerResult(self.name, findings)
        if _is_ip_address(host):
            return AnalyzerResult(self.name, findings)

        labels = host.split(".")
        tld = labels[-1] if labels else ""
        registered_domain = ".".join(labels[-2:]) if len(labels) >= 2 else host
        domain_name = labels[-2] if len(labels) >= 2 else labels[0]

        if tld in HIGH_RISK_TLDS:
            findings.append(
                AnalyzerFinding(self.name, f"Domain uses higher-risk TLD .{tld}.", 14)
            )

        if any(term in host for term in SUSPICIOUS_HOSTNAME_PREFIXES):
            findings.append(
                AnalyzerFinding(self.name, "Hostname contains suspicious prefixes.", 12)
            )

        stuffed_brand = _brand_in_host(host, registered_domain)
        if stuffed_brand:
            findings.append(
                AnalyzerFinding(
                    self.name,
                    f"Hostname references brand '{stuffed_brand}' outside its official domain.",
                    18,
                    metadata={"brand": stuffed_brand},
                )
            )
        else:
            lookalike = _closest_brand(domain_name)
            if lookalike:
                findings.append(
                    AnalyzerFinding(
                        self.name,
                        f"Domain looks similar to {lookalike}.",
                        18,
                        metadata={"brand": lookalike},
                    )
                )

        creation_date = self._whois_lookup(registered_domain)
        if creation_date is None:
            findings.append(
                AnalyzerFinding(
                    self.name,
                    "Domain age could not be verified from WHOIS.",
                    4,
                    confidence=45,
                )
            )
        else:
            age_days = (datetime.now(timezone.utc) - creation_date).days
            if age_days < 30:
                findings.append(
                    AnalyzerFinding(
                        self.name,
                        "Domain appears newly registered.",
                        18,
                        metadata={"age_days": age_days},
                    )
                )

        return AnalyzerResult(self.name, findings)


def _get_creation_date(domain: str) -> datetime | None:
    if whois is None:
        return None
    try:
        record = whois.whois(domain)
        created = record.creation_date
        if isinstance(created, list):
            created = created[0] if created else None
        if isinstance(created, datetime):
            return created.replace(tzinfo=created.tzinfo or timezone.utc)
    except Exception:
        return None
    return None


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _brand_in_host(host: str, registered_domain: str) -> str | None:
    for brand in BRANDS:
        if brand in host and registered_domain != f"{brand}.com":
            return brand
    return None


def _closest_brand(domain_name: str) -> str | None:
    for brand in BRANDS:
        if domain_name == brand:
            return None
        ratio = SequenceMatcher(None, domain_name, brand).ratio()
        if ratio >= 0.78 and brand not in domain_name:
            return brand
    return None
