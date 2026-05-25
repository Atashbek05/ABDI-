import re
import math
from urllib.parse import urlparse, parse_qs
from typing import List
import tldextract

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "online", "site",
                   "work", "racing", "download", "stream", "review", "trade", "win", "click"}

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "confirm", "secure",
    "banking", "payment", "password", "credential", "suspended", "unlock",
    "winner", "prize", "free", "bonus", "paypal", "amazon", "google",
    "microsoft", "apple", "facebook", "netflix", "bank",
]


class FeatureExtractor:

    def extract(self, url: str) -> List[float]:
        try:
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
        except Exception:
            return [0.0] * 30

        domain = extracted.domain or ""
        suffix = extracted.suffix or ""
        path = parsed.path or ""
        query = parsed.query or ""
        subdomain = extracted.subdomain or ""
        url_lower = url.lower()
        netloc = parsed.netloc or ""

        features = [
            len(url),
            len(domain),
            len(path),
            len(query),
            url.count("."),
            url.count("-"),
            url.count("_"),
            url.count("/"),
            url.count("@"),
            url.count("?"),
            url.count("="),
            url.count("%"),
            url.count("&"),
            1.0 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", netloc.split(":")[0]) else 0.0,
            1.0 if parsed.scheme == "https" else 0.0,
            len(subdomain.split(".")) if subdomain else 0,
            1.0 if suffix in SUSPICIOUS_TLDS else 0.0,
            self._entropy(domain),
            self._entropy(url),
            1.0 if parsed.port else 0.0,
            1.0 if any(ord(c) > 127 for c in url) else 0.0,
            len([p for p in path.split("/") if p]),
            len(parse_qs(query)),
            1.0 if "//" in path else 0.0,
            sum(url_lower.count(k) for k in ["redirect", "url=", "goto="]),
            sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower),
            domain.count("-"),
            len(domain),
            1.0 if re.search(r"(paypal|amazon|google|microsoft|apple|facebook)\d+", url_lower) else 0.0,
            1.0 if re.search(r"xn--", url_lower) else 0.0,
        ]

        return features

    def _entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        total = len(s)
        return -sum((v / total) * math.log2(v / total) for v in freq.values())

    @property
    def feature_count(self) -> int:
        return 30
