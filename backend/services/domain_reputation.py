import re
import math
import logging
from typing import Dict, List
from urllib.parse import urlparse
import tldextract

logger = logging.getLogger(__name__)

# High-risk TLDs with risk scores
RISKY_TLDS = {
    "tk": 45, "ml": 45, "ga": 45, "cf": 45, "gq": 45,
    "xyz": 25, "top": 25, "club": 20, "online": 20, "site": 20,
    "work": 25, "racing": 30, "download": 35, "stream": 25,
    "review": 25, "trade": 25, "win": 30, "click": 30,
    "loan": 30, "date": 25, "party": 20, "science": 20,
    "accountant": 25, "cricket": 20, "faith": 20, "bid": 25,
}

# Trusted registrar patterns
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
    "linkedin.com", "microsoft.com", "apple.com", "amazon.com", "netflix.com",
    "github.com", "stackoverflow.com", "reddit.com", "wikipedia.org",
    "paypal.com", "ebay.com", "cloudflare.com", "mozilla.org", "w3.org",
    "twitter.com", "x.com", "tiktok.com", "discord.com", "slack.com",
}


class DomainReputationService:

    def __init__(self):
        self._known_patterns = self._compile_patterns()

    def _compile_patterns(self):
        return {
            "homograph": re.compile(r'[^\x00-\x7F]'),
            "ip_address": re.compile(r'^(\d{1,3}\.){3}\d{1,3}$'),
            "hex_encoding": re.compile(r'%[0-9a-fA-F]{2}'),
            "punycode": re.compile(r'xn--'),
            "excessive_hyphens": re.compile(r'-{2,}'),
            "numbers_in_domain": re.compile(r'\d{4,}'),
        }

    async def analyze(self, domain: str, url: str = "") -> Dict:
        signals = []
        risk_score = 0

        try:
            extracted = tldextract.extract(domain if "." in domain else url)
            root_domain = extracted.domain.lower()
            tld = extracted.suffix.lower() if extracted.suffix else ""
            subdomain = extracted.subdomain.lower() if extracted.subdomain else ""
            full_domain = f"{root_domain}.{tld}" if tld else root_domain

            # Whitelisted
            if full_domain in TRUSTED_DOMAINS:
                return {"risk_score": 0, "signals": [], "summary": "Trusted domain", "domain_age_risk": 0}

            # IP address as domain
            if self._known_patterns["ip_address"].match(extracted.netloc if hasattr(extracted, 'netloc') else root_domain):
                risk_score += 40
                signals.append("IP address used as domain")

            # Suspicious TLD
            tld_risk = RISKY_TLDS.get(tld, 0)
            if tld_risk > 0:
                risk_score += tld_risk
                signals.append(f"High-risk domain extension (.{tld})")

            # Excessive subdomains
            sub_count = len(subdomain.split(".")) if subdomain else 0
            if sub_count > 4:
                risk_score += 20
                signals.append(f"Excessive subdomains ({sub_count})")
            elif sub_count > 2:
                risk_score += 10

            # Punycode (IDN homograph)
            if self._known_patterns["punycode"].search(domain):
                risk_score += 30
                signals.append("Punycode/IDN encoding detected (possible homograph attack)")

            # Unicode characters
            if self._known_patterns["homograph"].search(root_domain):
                risk_score += 35
                signals.append("Non-ASCII characters in domain (homograph attack risk)")

            # Domain entropy (randomly generated)
            entropy = self._calc_entropy(root_domain)
            if entropy > 4.2:
                risk_score += 20
                signals.append("Domain appears randomly generated (DGA pattern)")
            elif entropy > 3.8:
                risk_score += 10

            # Excessive hyphens
            if self._known_patterns["excessive_hyphens"].search(root_domain):
                risk_score += 15
                signals.append("Excessive hyphens in domain name")
            elif root_domain.count("-") > 2:
                risk_score += 8

            # Numbers mixed into domain
            if self._known_patterns["numbers_in_domain"].search(root_domain):
                risk_score += 10
                signals.append("Suspicious numeric sequence in domain")

            # Domain length
            if len(root_domain) > 25:
                risk_score += 15
                signals.append(f"Unusually long domain name ({len(root_domain)} chars)")
            elif len(root_domain) > 18:
                risk_score += 8

            # Brand squatting detection
            brand_result = self._detect_brand_squatting(root_domain, tld)
            if brand_result:
                risk_score += 35
                signals.append(f"Possible brand squatting on '{brand_result}'")

            # Double-extension tricks
            if self._detect_double_extension(root_domain):
                risk_score += 20
                signals.append("Double-extension domain trick detected")

            summary = self._generate_summary(risk_score, signals)

        except Exception as e:
            logger.error(f"Domain reputation analysis error: {e}")
            summary = "Analysis error"

        return {
            "risk_score": min(100, risk_score),
            "signals": signals,
            "summary": summary,
            "domain_age_risk": 0,
        }

    def _calc_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        total = len(s)
        return -sum((v / total) * math.log2(v / total) for v in freq.values())

    def _detect_brand_squatting(self, domain: str, tld: str) -> str:
        brands = [
            "paypal", "amazon", "google", "microsoft", "apple", "facebook",
            "netflix", "instagram", "twitter", "linkedin", "chase", "wellsfargo",
            "bankofamerica", "citibank", "dropbox", "adobe", "yahoo", "ebay",
            "spotify", "youtube", "gmail", "outlook", "office", "coinbase",
            "binance", "metamask", "blockchain", "bitcoin", "ethereum",
        ]
        for brand in brands:
            if brand in domain and domain != brand:
                return brand
            # Typosquatting: 1 char substitution
            if self._levenshtein(domain, brand) == 1 and len(domain) >= 4:
                return brand
        return ""

    def _levenshtein(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def _detect_double_extension(self, domain: str) -> bool:
        extensions = [".exe", ".zip", ".pdf", ".doc", ".apk", ".dmg"]
        return any(ext in domain for ext in extensions)

    def _generate_summary(self, score: float, signals: List[str]) -> str:
        if score < 20:
            return "Domain appears legitimate"
        elif score < 40:
            return "Domain shows minor risk indicators"
        elif score < 60:
            return "Domain has multiple suspicious characteristics"
        elif score < 80:
            return "Domain has serious risk indicators"
        else:
            return "Domain is highly suspicious or malicious"
