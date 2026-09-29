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

_HOMOGRAPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ѕ": "s", "б": "b",
    "1": "l", "0": "o", "5": "s", "3": "e", "@": "a", "$": "s",
}


def _normalize_homographs(name: str) -> str:
    """Convert confusable Unicode and digit substitutions to canonical ASCII."""
    return "".join(_HOMOGRAPH_MAP.get(char, char) for char in name.lower())


def _check_punycode_and_idn(host: str) -> tuple[str, bool, bool]:
    """Return (unicode_host, is_idn, is_punycode)."""
    is_punycode = "xn--" in host.lower()
    unicode_host = host
    if is_punycode:
        try:
            unicode_host = host.encode("ascii").decode("idna")
        except Exception:
            unicode_host = host
    is_idn = is_punycode or any(ord(char) > 127 for char in host)
    return unicode_host, is_idn, is_punycode


class DomainAnalyzer:
    """Analyze domain age, TLD, IDN/Punycode, and hostname impersonation signals."""

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

        unicode_host, is_idn, is_punycode = _check_punycode_and_idn(host)
        if is_punycode:
            findings.append(
                AnalyzerFinding(
                    self.name,
                    f"Domain uses Punycode encoding ({unicode_host}).",
                    16,
                    metadata={"punycode": host, "unicode": unicode_host},
                )
            )
        elif is_idn:
            findings.append(
                AnalyzerFinding(
                    self.name,
                    "Domain contains Internationalized (IDN) Unicode characters.",
                    14,
                    metadata={"unicode": host},
                )
            )

        # Inspect both ASCII host and decoded Unicode host
        eval_host = unicode_host if is_punycode else host
        labels = eval_host.split(".")
        tld = labels[-1] if labels else ""
        registered_domain = ".".join(labels[-2:]) if len(labels) >= 2 else eval_host
        domain_name = labels[-2] if len(labels) >= 2 else labels[0]

        if tld in HIGH_RISK_TLDS:
            findings.append(
                AnalyzerFinding(self.name, f"Domain uses higher-risk TLD .{tld}.", 14)
            )

        if any(term in eval_host for term in SUSPICIOUS_HOSTNAME_PREFIXES):
            findings.append(
                AnalyzerFinding(self.name, "Hostname contains suspicious prefixes.", 12)
            )

        stuffed_brand = _brand_in_host(eval_host, registered_domain)
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
            norm_name = _normalize_homographs(domain_name)
            if norm_name != domain_name and norm_name in BRANDS and registered_domain != f"{norm_name}.com":
                findings.append(
                    AnalyzerFinding(
                        self.name,
                        f"Domain uses homograph or typosquat character substitution for '{norm_name}'.",
                        20,
                        metadata={"brand": norm_name, "substituted": domain_name},
                    )
                )
            else:
                lookalike = _closest_brand(domain_name) or (
                    _closest_brand(norm_name) if norm_name != domain_name else None
                )
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
