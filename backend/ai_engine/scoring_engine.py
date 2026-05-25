"""
ScoringEngine
=============
Translates the ensemble threat probability + URL features + page-content
signals into the specialised risk scores surfaced by the API:

    - overall_threat_score
    - phishing_probability
    - malware_probability
    - impersonation_risk
    - credential_theft_risk
    - redirect_abuse_risk
    - suspicious_behavior_score

Each score is a percentage (0..100). The scoring logic is intentionally
explicit so security analysts can read off *why* a particular vertical lit up
— it isn't a single black-box number.
"""
from __future__ import annotations

import re
import logging
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_MALWARE_KEYWORDS = (
    "download", "install", "setup.exe", "crack", "keygen", "patcher",
    "torrent", "warez", "loader", ".exe", ".apk", ".dmg", ".jar",
)
_IMPERSONATION_BRANDS = (
    "paypal", "amazon", "google", "microsoft", "apple", "facebook",
    "netflix", "instagram", "linkedin", "chase", "wellsfargo",
    "bankofamerica", "citibank", "dropbox", "adobe", "ebay", "spotify",
    "coinbase", "binance", "metamask",
)
_CREDENTIAL_KEYWORDS = (
    "login", "signin", "sign-in", "password", "credential", "auth",
    "account", "verify", "confirm", "secure", "validate",
)
_REDIRECT_KEYWORDS = ("redirect", "url=", "goto=", "next=", "return=", "out=", "ref=")


@dataclass
class RiskScores:
    overall_threat_score: float
    phishing_probability: float
    malware_probability: float
    impersonation_risk: float
    credential_theft_risk: float
    redirect_abuse_risk: float
    suspicious_behavior_score: float

    def to_dict(self) -> Dict[str, float]:
        return {k: round(float(v), 2) for k, v in asdict(self).items()}


class ScoringEngine:
    """Derive specialised risk verticals from the ensemble + context."""

    def score(
        self,
        url: str,
        ensemble_probability: float,
        url_features: Dict,
        domain_rep_score: float = 0.0,
        content_score: float = 0.0,
        dom_signals: Optional[Dict] = None,
        redirect_chain: Optional[List[str]] = None,
        heuristic_score: float = 0.0,
    ) -> RiskScores:
        url_l = (url or "").lower()
        dom = dom_signals or {}

        # ---- Overall threat: ensemble lifted by corroborating signals.
        base = ensemble_probability * 100.0
        corroboration = 0.0
        for s in (domain_rep_score, content_score, heuristic_score):
            if s > 60:
                corroboration += 6.0
            elif s > 35:
                corroboration += 3.0
        overall = self._clip(base + corroboration)

        # ---- Phishing probability: blend ensemble with credential/content hits.
        cred_hits = sum(1 for k in _CREDENTIAL_KEYWORDS if k in url_l)
        phishing = self._clip(
            base * 0.78
            + min(20.0, cred_hits * 5.0)
            + min(15.0, content_score * 0.15)
        )

        # ---- Malware probability: keyword & extension signals.
        malware_hits = sum(1 for k in _MALWARE_KEYWORDS if k in url_l)
        malware = self._clip(
            base * 0.35
            + min(45.0, malware_hits * 18.0)
            + (15.0 if re.search(r"\.(exe|apk|scr|bat|dmg|jar)(\?|$)", url_l) else 0.0)
        )

        # ---- Impersonation risk: brand-in-domain plus visual cloning.
        brand_hit = any(b in url_l for b in _IMPERSONATION_BRANDS)
        unicode_hit = bool(url_features.get("has_unicode"))
        impersonation = self._clip(
            base * 0.55
            + (30.0 if brand_hit else 0.0)
            + (15.0 if unicode_hit else 0.0)
            + float(dom.get("impersonation_risk", 0.0)) * 0.4
            + (12.0 if dom.get("cloned_page_detected") else 0.0)
        )

        # ---- Credential-theft risk: fake login forms, password fields.
        credential = self._clip(
            base * 0.5
            + float(dom.get("credential_theft_probability", 0.0)) * 0.6
            + (20.0 if dom.get("fake_login_detected") else 0.0)
            + min(15.0, cred_hits * 4.0)
        )

        # ---- Redirect abuse: URL params + chain length.
        redirect_hits = sum(url_l.count(k) for k in _REDIRECT_KEYWORDS)
        chain_len = len(redirect_chain or [])
        redirect = self._clip(
            min(45.0, redirect_hits * 12.0)
            + min(35.0, max(0, chain_len - 1) * 10.0)
            + (20.0 if url_features.get("has_double_slash") else 0.0)
            + base * 0.18
        )

        # ---- Suspicious behavior: catch-all for DOM/CSS tricks.
        suspicious = self._clip(
            float(dom.get("visual_risk_score", 0.0)) * 0.45
            + (12.0 if dom.get("css_tricks_detected") else 0.0)
            + min(15.0, int(dom.get("hidden_iframes", 0)) * 8.0)
            + min(15.0, int(dom.get("suspicious_overlays", 0)) * 6.0)
            + base * 0.25
        )

        return RiskScores(
            overall_threat_score=overall,
            phishing_probability=phishing,
            malware_probability=malware,
            impersonation_risk=impersonation,
            credential_theft_risk=credential,
            redirect_abuse_risk=redirect,
            suspicious_behavior_score=suspicious,
        )

    @staticmethod
    def _clip(v: float) -> float:
        return max(0.0, min(100.0, float(v)))

    @staticmethod
    def risk_level(overall_score: float) -> str:
        if overall_score < 20:
            return "safe"
        if overall_score < 40:
            return "low"
        if overall_score < 60:
            return "medium"
        if overall_score < 80:
            return "high"
        return "critical"
