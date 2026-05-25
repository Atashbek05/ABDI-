import re
import math
import time
import logging
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional
import tldextract
from services.domain_reputation import DomainReputationService
from services.content_analyzer import ContentAnalyzer
from services.dom_analyzer import DOMAnalyzer
from ai_engine import ThreatAnalyzer

logger = logging.getLogger(__name__)

PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "account", "verify", "verification",
    "update", "confirm", "secure", "security", "banking", "payment",
    "password", "credential", "authenticate", "validation", "validate",
    "suspended", "unlock", "recover", "restore", "reactivate",
    "alert", "warning", "urgent", "immediate", "limited", "expire",
    "winner", "prize", "reward", "free", "bonus", "paypal", "amazon",
    "google", "microsoft", "apple", "facebook", "netflix", "bank",
]

SUSPICIOUS_TLDS = {
    "tk": 40, "ml": 40, "ga": 40, "cf": 40, "gq": 40,
    "xyz": 22, "top": 22, "club": 18, "online": 18, "site": 18,
    "work": 22, "racing": 28, "download": 30, "stream": 22,
    "review": 22, "trade": 22, "win": 28, "click": 28, "loan": 28,
}

TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
    "linkedin.com", "microsoft.com", "apple.com", "amazon.com", "netflix.com",
    "github.com", "stackoverflow.com", "reddit.com", "wikipedia.org",
    "paypal.com", "ebay.com", "cloudflare.com", "mozilla.org", "discord.com",
    "twitch.tv", "tiktok.com", "x.com", "slack.com", "zoom.us",
}

BRAND_NAMES = [
    "paypal", "amazon", "google", "microsoft", "apple", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "chase", "wellsfargo",
    "bankofamerica", "citibank", "dropbox", "adobe", "yahoo", "ebay",
    "spotify", "tiktok", "youtube", "gmail", "outlook", "office",
    "coinbase", "binance", "blockchain", "metamask", "ethereum", "bitcoin",
]


class AIDetectionEngine:

    def __init__(self, db_session=None):
        self.db = db_session
        self.domain_rep = DomainReputationService()
        self.content_analyzer = ContentAnalyzer()
        self.dom_analyzer = DOMAnalyzer()
        # Multi-model ensemble facade (loads RF / XGBoost / MLP / LR bundle).
        self.threat_analyzer = ThreatAnalyzer()

    async def analyze(
        self,
        url: str,
        html_content: str = None,
        page_title: str = None,
        page_text: str = None,
        forms: list = None,
        scripts: list = None,
        redirects: list = None,
        dom_data: dict = None,
    ) -> Dict:
        start_time = time.time()

        try:
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
        except Exception as e:
            return self._error_response(url, str(e))

        domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain

        if await self._is_whitelisted(domain):
            return self._safe_response(url, domain, start_time)

        blacklisted = await self._check_blacklist(domain)
        if blacklisted:
            return self._blacklisted_response(url, domain, blacklisted, start_time)

        if domain in TRUSTED_DOMAINS:
            return self._safe_response(url, domain, start_time)

        url_features = self._extract_url_features(url, parsed, extracted)
        heuristic = self._run_heuristics(url, parsed, extracted, url_features)

        domain_rep = await self.domain_rep.analyze(domain, url)

        content = {"score": 0, "signals": [], "threat_indicators": []}
        if html_content or forms or scripts:
            content = await self.content_analyzer.analyze(
                html_content=html_content,
                page_title=page_title,
                page_text=page_text,
                forms=forms,
                scripts=scripts,
                url=url,
            )

        # DOM / visual analysis (runs when any page data is available)
        dom_result = {
            "score": 0, "visual_risk_score": 0.0, "login_risk": 0.0,
            "impersonation_risk": 0.0, "credential_theft_probability": 0.0,
            "fake_login_detected": False, "cloned_page_detected": False,
            "hidden_elements_found": 0, "suspicious_overlays": 0,
            "css_tricks_detected": False, "iframe_count": 0, "hidden_iframes": 0,
            "suspicious_buttons": [], "credential_harvesting_patterns": [],
            "impersonation_signals": [], "signals": [],
        }
        if html_content or forms or dom_data or page_title:
            dom_result = await self.dom_analyzer.analyze(
                html_content=html_content,
                page_title=page_title,
                page_text=page_text,
                forms=forms,
                dom_data=dom_data,
                url=url,
            )

        # Run the multi-model ensemble: RF + XGBoost + MLP + Logistic Regression.
        from ml.feature_extractor import FeatureExtractor
        features = FeatureExtractor().extract(url)
        ai_result = await self.threat_analyzer.analyze(
            url=url,
            features=features,
            url_features=url_features,
            domain_rep_score=domain_rep["risk_score"],
            content_score=content["score"],
            dom_signals=dom_result,
            redirect_chain=redirects,
            heuristic_score=heuristic["score"],
        )
        ml_score = ai_result["ensemble_probability"]

        has_content = bool(html_content or forms or scripts or dom_data)
        final_score = self._combine_scores(
            heuristic["score"],
            ml_score,
            domain_rep["risk_score"],
            content["score"],
            dom_result["score"],
            has_content=has_content,
        )

        # The scoring engine already provides a calibrated overall score —
        # blend it with our layered combined score so both viewpoints count.
        final_score = round(
            0.55 * final_score + 0.45 * ai_result["scores"]["overall_threat_score"],
            2,
        )

        if redirects and len(redirects) > 3:
            heuristic["reasons"].append(f"Suspicious redirect chain ({len(redirects)} hops)")
            final_score = min(100, final_score + 20)

        all_reasons = (
            heuristic["reasons"]
            + domain_rep.get("signals", [])
            + content.get("signals", [])
            + dom_result.get("signals", [])
        )

        threat_details = self._collect_threat_details(heuristic, domain_rep, content)
        threat_type = self._classify_threat(url, all_reasons, final_score, content)
        risk_level = self._get_risk_level(final_score)
        is_safe = final_score < 40
        explanation = self._generate_explanation(domain, is_safe, threat_type, final_score, all_reasons)

        # Construct PageAnalysis object for the response
        page_analysis = {
            "fake_login_detected": dom_result["fake_login_detected"],
            "cloned_page_detected": dom_result["cloned_page_detected"],
            "hidden_elements_found": dom_result["hidden_elements_found"],
            "suspicious_overlays": dom_result["suspicious_overlays"],
            "css_tricks_detected": dom_result["css_tricks_detected"],
            "iframe_count": dom_result["iframe_count"],
            "hidden_iframes": dom_result["hidden_iframes"],
            "suspicious_buttons": dom_result["suspicious_buttons"],
            "credential_harvesting_patterns": dom_result["credential_harvesting_patterns"],
            "impersonation_signals": dom_result["impersonation_signals"],
            "visual_risk_score": dom_result["visual_risk_score"],
            "login_risk": dom_result["login_risk"],
            "impersonation_risk": dom_result["impersonation_risk"],
            "credential_theft_probability": dom_result["credential_theft_probability"],
        }

        ai_confidence = ai_result["confidence"]
        # The "confidence" returned to the API is anchored on the ensemble's
        # decisiveness when the engine is in ML mode, else on the risk score.
        api_confidence = (
            round(min(99.9, max(0.1, ai_confidence if ai_result["engine_status"] == "ml" else final_score)), 2)
        )

        return {
            "url": url,
            "domain": domain,
            "is_safe": is_safe,
            "risk_level": risk_level,
            "threat_type": threat_type,
            "prediction": ai_result["prediction"],
            "confidence": api_confidence,
            "risk_score": round(final_score, 2),
            "reasons": all_reasons[:10],
            "threat_details": threat_details,
            "explanation": explanation,
            "scan_duration_ms": round((time.time() - start_time) * 1000, 2),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ai_model_score": round(ml_score, 2),
            "heuristic_score": round(heuristic["score"], 2),
            "domain_reputation_score": round(domain_rep["risk_score"], 2),
            "content_analysis_score": round(content["score"], 2),
            "cached": False,
            "visual_risk_score": round(dom_result["visual_risk_score"], 2),
            "fake_login_detected": dom_result["fake_login_detected"],
            "page_analysis": page_analysis,
            # --- Multi-model AI engine block ----------------------------------
            "models": ai_result["models"],
            "weighted_votes": ai_result["weighted_votes"],
            "model_weights": ai_result["model_weights"],
            "scores": ai_result["scores"],
            "ensemble": {
                "probability":  ai_result["ensemble_probability"],
                "confidence":   ai_result["confidence"],
                "agreement":    ai_result["agreement"],
                "engine_status": ai_result["engine_status"],
            },
        }

    def _extract_url_features(self, url: str, parsed, extracted) -> Dict:
        domain = extracted.domain or ""
        suffix = extracted.suffix or ""
        path = parsed.path or ""
        query = parsed.query or ""
        subdomain = extracted.subdomain or ""

        return {
            "url_length": len(url),
            "domain_length": len(domain),
            "path_length": len(path),
            "query_length": len(query),
            "num_dots": url.count("."),
            "num_hyphens": url.count("-"),
            "num_slashes": url.count("/"),
            "num_at": url.count("@"),
            "num_question": url.count("?"),
            "num_equal": url.count("="),
            "num_percent": url.count("%"),
            "num_ampersand": url.count("&"),
            "has_ip": bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed.netloc.split(":")[0])),
            "has_https": parsed.scheme == "https",
            "subdomain_count": len(subdomain.split(".")) if subdomain else 0,
            "tld": suffix,
            "suspicious_tld_score": SUSPICIOUS_TLDS.get(suffix, 0),
            "domain_entropy": self._entropy(domain),
            "url_entropy": self._entropy(url),
            "has_port": bool(parsed.port),
            "has_unicode": any(ord(c) > 127 for c in url),
            "path_depth": len([p for p in path.split("/") if p]),
            "query_param_count": len(parse_qs(query)),
            "has_double_slash": "//" in path,
            "num_redirects": sum(url.lower().count(k) for k in ["redirect", "url=", "goto=", "next="]),
        }

    def _run_heuristics(self, url: str, parsed, extracted, features: Dict) -> Dict:
        score = 0
        reasons = []
        url_lower = url.lower()
        domain = extracted.domain.lower() if extracted.domain else ""

        if features["has_ip"]:
            score += 38
            reasons.append("IP address used instead of a domain name")

        if not features["has_https"]:
            score += 18
            reasons.append("Not using secure HTTPS connection")

        if features["num_at"] > 0:
            score += 28
            reasons.append("@ symbol in URL — possible credential theft indicator")

        if features["subdomain_count"] > 4:
            score += 18
            reasons.append(f"Excessive subdomains ({features['subdomain_count']})")
        elif features["subdomain_count"] > 2:
            score += 8

        if features["url_length"] > 200:
            score += 15
            reasons.append(f"Abnormally long URL ({features['url_length']} chars)")
        elif features["url_length"] > 120:
            score += 7

        tld_score = features["suspicious_tld_score"]
        if tld_score > 0:
            score += tld_score
            reasons.append(f"High-risk domain extension (.{features['tld']})")

        if features["domain_entropy"] > 4.1:
            score += 18
            reasons.append("Domain name appears randomly generated")
        elif features["domain_entropy"] > 3.6:
            score += 8

        if features["has_double_slash"]:
            score += 18
            reasons.append("Double slash in URL path (redirect trick)")

        if features["has_port"]:
            score += 12
            reasons.append("Non-standard port number in URL")

        if features["num_redirects"] > 0:
            score += 16
            reasons.append("URL redirect parameters detected")

        if features["has_unicode"]:
            score += 22
            reasons.append("Unicode characters in URL (homograph attack risk)")

        brand_match = self._check_brand_impersonation(domain, features["tld"])
        if brand_match:
            score += 32
            reasons.append(f"Possible brand impersonation of '{brand_match}'")

        kw_hits = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
        if len(kw_hits) >= 3:
            score += 22
            reasons.append(f"Multiple phishing keywords: {', '.join(kw_hits[:4])}")
        elif len(kw_hits) >= 1:
            score += 8

        if features["query_param_count"] > 6:
            score += 10
            reasons.append(f"Excessive URL parameters ({features['query_param_count']})")

        hyphen_count = domain.count("-")
        if hyphen_count > 3:
            score += 16
            reasons.append(f"Many hyphens in domain ({hyphen_count})")
        elif hyphen_count > 1:
            score += 6

        if re.search(r"(paypal|amazon|google|microsoft|apple|facebook)\d+", url_lower):
            score += 28
            reasons.append("Brand name combined with numbers (phishing pattern)")

        suspicious_paths = ["admin", "login", "signin", "verify", "account", "update", "secure", "banking"]
        path_hits = [p for p in suspicious_paths if p in url_lower]
        if len(path_hits) >= 2:
            score += 16
            reasons.append(f"Suspicious path keywords: {', '.join(path_hits[:3])}")

        return {"score": min(100, score), "reasons": reasons}

    def _check_brand_impersonation(self, domain: str, tld: str) -> Optional[str]:
        for brand in BRAND_NAMES:
            if brand in domain and domain != brand:
                return brand
            if domain == brand and tld not in ["com", "net", "org", "io", "co"]:
                return brand
        return None

    def _entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq: Dict[str, int] = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        total = len(s)
        return -sum((v / total) * math.log2(v / total) for v in freq.values())

    def _combine_scores(
        self,
        heuristic: float,
        ml: float,
        domain_rep: float,
        content: float,
        dom: float = 0.0,
        has_content: bool = False,
    ) -> float:
        if has_content:
            # With page data: redistribute weight to include DOM analysis
            w = {"h": 0.25, "m": 0.20, "d": 0.20, "c": 0.18, "dom": 0.17}
        else:
            w = {"h": 0.40, "m": 0.30, "d": 0.30, "c": 0.0, "dom": 0.0}

        combined = (
            heuristic * w["h"]
            + ml * w["m"]
            + domain_rep * w["d"]
            + content * w["c"]
            + dom * w["dom"]
        )

        # Amplify if multiple layers agree threat is high
        high = sum(1 for s in [heuristic, ml, domain_rep, content, dom] if s > 60)
        if high >= 3:
            combined = min(100, combined * 1.15)

        return round(combined, 2)

    def _collect_threat_details(self, heuristic: Dict, domain_rep: Dict, content: Dict) -> List[Dict]:
        details = []
        if heuristic["score"] > 35:
            details.append({
                "category": "URL Analysis",
                "description": "URL structure shows phishing indicators",
                "severity": self._severity(heuristic["score"]),
                "confidence": heuristic["score"],
            })
        if domain_rep.get("risk_score", 0) > 35:
            details.append({
                "category": "Domain Reputation",
                "description": domain_rep.get("summary", "Suspicious domain"),
                "severity": self._severity(domain_rep["risk_score"]),
                "confidence": domain_rep["risk_score"],
            })
        for indicator in content.get("threat_indicators", [])[:3]:
            if content.get("score", 0) > 35:
                details.append({
                    "category": "Page Content",
                    "description": indicator,
                    "severity": self._severity(content["score"]),
                    "confidence": content["score"],
                })
        return details

    def _classify_threat(self, url: str, reasons: List[str], score: float, content: Dict) -> str:
        if score < 40:
            return "safe"
        text = (url + " ".join(reasons)).lower()
        if any(k in text for k in ["crypto", "bitcoin", "ethereum", "wallet", "blockchain"]):
            return "crypto_scam"
        if any(k in text for k in ["bank", "chase", "wellsfargo", "citibank"]):
            return "fake_banking"
        if any(k in text for k in ["payment", "checkout", "invoice", "purchase"]):
            return "fake_payment"
        if any(k in text for k in ["login", "signin", "password", "credential"]):
            return "fake_login"
        if any(k in text for k in ["download", "install", "crack", "keygen"]):
            return "malware"
        if any(k in text for k in ["winner", "prize", "congratulations", "free gift"]):
            return "scam"
        if any(k in text for k in ["redirect", "url=", "goto="]):
            return "suspicious_redirect"
        if score >= 65:
            return "phishing"
        return "suspicious"

    def _get_risk_level(self, score: float) -> str:
        if score < 20:
            return "safe"
        if score < 40:
            return "low"
        if score < 60:
            return "medium"
        if score < 80:
            return "high"
        return "critical"

    def _severity(self, score: float) -> str:
        if score < 40:
            return "low"
        if score < 60:
            return "medium"
        if score < 80:
            return "high"
        return "critical"

    def _generate_explanation(
        self, domain: str, is_safe: bool, threat_type: str, score: float, reasons: List[str]
    ) -> str:
        if is_safe:
            return (
                f"The website {domain} appears legitimate. "
                f"Our multi-layer AI analysis found no significant threats."
            )

        names = {
            "phishing": "phishing attack",
            "fake_login": "fake login page",
            "fake_banking": "fake banking site",
            "crypto_scam": "cryptocurrency scam",
            "fake_payment": "fake payment gateway",
            "malware": "malware distribution site",
            "scam": "online scam",
            "suspicious_redirect": "suspicious redirect chain",
            "suspicious": "suspicious site",
        }
        threat_name = names.get(threat_type, "security threat")
        level = self._get_risk_level(score)
        severity_text = {"low": "low", "medium": "moderate", "high": "high", "critical": "critical"}.get(level, "significant")

        explanation = (
            f"WARNING: This page appears to be a {threat_name}. "
            f"AI risk score: {score:.1f}/100 ({severity_text} severity). "
        )
        if reasons:
            explanation += f"Key indicators: {'; '.join(reasons[:3])}. "
        explanation += "We strongly recommend leaving this page immediately."
        return explanation

    async def _is_whitelisted(self, domain: str) -> bool:
        if self.db:
            from database import WhitelistEntry
            return self.db.query(WhitelistEntry).filter(WhitelistEntry.domain == domain).first() is not None
        return False

    async def _check_blacklist(self, domain: str) -> Optional[str]:
        if self.db:
            from database import BlacklistEntry
            entry = self.db.query(BlacklistEntry).filter(BlacklistEntry.domain == domain).first()
            if entry:
                return entry.reason or "Domain blacklisted"
        return None

    def _empty_page_analysis(self) -> Dict:
        return {
            "fake_login_detected": False, "cloned_page_detected": False,
            "hidden_elements_found": 0, "suspicious_overlays": 0,
            "css_tricks_detected": False, "iframe_count": 0, "hidden_iframes": 0,
            "suspicious_buttons": [], "credential_harvesting_patterns": [],
            "impersonation_signals": [], "visual_risk_score": 0.0,
            "login_risk": 0.0, "impersonation_risk": 0.0, "credential_theft_probability": 0.0,
        }

    def _empty_ai_block(self, p: float = 0.0, conf: float = 0.0) -> Dict:
        """Default values for the multi-model AI block (used by safe/blacklisted paths)."""
        models = {"random_forest": p, "xgboost": p, "neural_network": p, "logistic_regression": p}
        return {
            "models": models,
            "weighted_votes": {k: round(v * 0.25, 2) for k, v in models.items()},
            "model_weights": {"random_forest": 0.25, "xgboost": 0.25,
                              "neural_network": 0.25, "logistic_regression": 0.25},
            "scores": {
                "overall_threat_score": p,
                "phishing_probability": p,
                "malware_probability": p,
                "impersonation_risk": p,
                "credential_theft_risk": p,
                "redirect_abuse_risk": p,
                "suspicious_behavior_score": p,
            },
            "ensemble": {
                "probability": p, "confidence": conf, "agreement": 100.0,
                "engine_status": "shortcut",
            },
        }

    def _safe_response(self, url: str, domain: str, start_time: float) -> Dict:
        return {
            "url": url, "domain": domain, "is_safe": True, "risk_level": "safe",
            "threat_type": "safe", "prediction": "safe",
            "confidence": 1.5, "risk_score": 1.5,
            "reasons": [], "threat_details": [],
            "explanation": f"{domain} is safe. No threats detected.",
            "scan_duration_ms": round((time.time() - start_time) * 1000, 2),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ai_model_score": 0.0, "heuristic_score": 0.0,
            "domain_reputation_score": 0.0, "content_analysis_score": 0.0, "cached": False,
            "visual_risk_score": 0.0, "fake_login_detected": False,
            "page_analysis": self._empty_page_analysis(),
            **self._empty_ai_block(p=0.0, conf=99.0),
        }

    def _blacklisted_response(self, url: str, domain: str, reason: str, start_time: float) -> Dict:
        return {
            "url": url, "domain": domain, "is_safe": False, "risk_level": "critical",
            "threat_type": "phishing", "prediction": "phishing",
            "confidence": 99.0, "risk_score": 99.0,
            "reasons": [f"Domain in threat blacklist: {reason}"],
            "threat_details": [{"category": "Blacklist", "description": f"{domain} is blacklisted",
                                 "severity": "critical", "confidence": 99.0}],
            "explanation": f"DANGER: {domain} is listed in our threat database. {reason}",
            "scan_duration_ms": round((time.time() - start_time) * 1000, 2),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ai_model_score": 99.0, "heuristic_score": 99.0,
            "domain_reputation_score": 99.0, "content_analysis_score": 0.0, "cached": False,
            "visual_risk_score": 0.0, "fake_login_detected": False,
            "page_analysis": self._empty_page_analysis(),
            **self._empty_ai_block(p=99.0, conf=99.0),
        }

    def _error_response(self, url: str, error: str) -> Dict:
        return {
            "url": url, "domain": "unknown", "is_safe": True, "risk_level": "safe",
            "threat_type": "safe", "prediction": "safe",
            "confidence": 0.0, "risk_score": 0.0,
            "reasons": [f"Analysis error: {error}"], "threat_details": [],
            "explanation": "Could not analyze this URL.",
            "scan_duration_ms": 0.0,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ai_model_score": 0.0, "heuristic_score": 0.0,
            "domain_reputation_score": 0.0, "content_analysis_score": 0.0, "cached": False,
            "visual_risk_score": 0.0, "fake_login_detected": False,
            "page_analysis": self._empty_page_analysis(),
            **self._empty_ai_block(p=0.0, conf=0.0),
        }
