import re
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Social engineering text patterns
SOCIAL_ENGINEERING = [
    "your account has been suspended", "verify your identity", "update your information",
    "click here to confirm", "your password has expired", "unusual activity detected",
    "immediately verify", "account will be closed", "limited time offer",
    "you have been selected", "congratulations you won", "claim your prize",
    "your payment failed", "invoice attached", "urgent action required",
]

# Credential harvesting form indicators
CREDENTIAL_FORMS = [
    "password", "passwd", "pwd", "pin", "ssn", "social security",
    "credit card", "card number", "cvv", "expiry", "expiration",
    "bank account", "routing number", "date of birth", "mother maiden",
]

# Suspicious script patterns
MALICIOUS_JS_PATTERNS = [
    r'eval\s*\(',
    r'document\.write\s*\(',
    r'unescape\s*\(',
    r'String\.fromCharCode\s*\(',
    r'\\x[0-9a-fA-F]{2}',
    r'atob\s*\(',
    r'btoa\s*\(',
    r'window\.location\s*=',
    r'document\.cookie',
    r'localStorage\.getItem',
    r'sessionStorage\.setItem',
    r'new Function\s*\(',
    r'setTimeout\s*\(\s*[\'"]',
    r'setInterval\s*\(\s*[\'"]',
    r'XMLHttpRequest',
]


class ContentAnalyzer:

    def __init__(self):
        self._js_patterns = [re.compile(p, re.IGNORECASE) for p in MALICIOUS_JS_PATTERNS]

    async def analyze(
        self,
        html_content: str = None,
        page_title: str = None,
        page_text: str = None,
        forms: List[Dict] = None,
        scripts: List[str] = None,
        url: str = "",
    ) -> Dict:
        score = 0
        signals = []
        threat_indicators = []

        try:
            if forms:
                form_result = self._analyze_forms(forms)
                score += form_result["score"]
                signals.extend(form_result["signals"])
                threat_indicators.extend(form_result["indicators"])

            if scripts:
                script_result = self._analyze_scripts(scripts)
                score += script_result["score"]
                signals.extend(script_result["signals"])
                threat_indicators.extend(script_result["indicators"])

            if page_text:
                text_result = self._analyze_text(page_text)
                score += text_result["score"]
                signals.extend(text_result["signals"])

            if page_title:
                title_result = self._analyze_title(page_title, url)
                score += title_result["score"]
                signals.extend(title_result["signals"])

            if html_content:
                html_result = self._analyze_html(html_content)
                score += html_result["score"]
                signals.extend(html_result["signals"])
                threat_indicators.extend(html_result["indicators"])

        except Exception as e:
            logger.error(f"Content analysis error: {e}")

        return {
            "score": min(100, score),
            "signals": signals,
            "threat_indicators": threat_indicators,
        }

    def _analyze_forms(self, forms: List[Dict]) -> Dict:
        score = 0
        signals = []
        indicators = []

        for form in forms:
            action = str(form.get("action", "")).lower()
            method = str(form.get("method", "get")).lower()
            inputs = form.get("inputs", [])
            input_names = [str(i.get("name", "") + i.get("type", "")).lower() for i in inputs]
            combined = " ".join(input_names)

            # Password field present
            if any("password" in n or "passwd" in n for n in input_names):
                score += 20
                signals.append("Login form with password field detected")

            # Sensitive credential fields
            cred_hits = [c for c in CREDENTIAL_FORMS if c in combined]
            if len(cred_hits) >= 2:
                score += 25
                indicators.append(f"Credential harvesting form detected: {', '.join(cred_hits[:3])}")

            # Form submits to external domain
            if action.startswith("http") and "." in action:
                score += 15
                signals.append("Form submits to external URL")

            # Hidden iframes/forms
            if form.get("hidden") or form.get("type") == "hidden":
                score += 15
                signals.append("Hidden form element detected")

            # POST method with suspicious fields
            if method == "post" and any(c in combined for c in ["credit", "card", "cvv", "ssn"]):
                score += 30
                indicators.append("Payment credential form detected (possible fake payment page)")

        return {"score": score, "signals": signals, "indicators": indicators}

    def _analyze_scripts(self, scripts: List[str]) -> Dict:
        score = 0
        signals = []
        indicators = []

        for script in scripts[:20]:
            if not script:
                continue
            hit_patterns = []
            for pattern in self._js_patterns:
                if pattern.search(script):
                    hit_patterns.append(pattern.pattern[:30])

            if len(hit_patterns) >= 3:
                score += 25
                indicators.append(f"Suspicious JavaScript patterns: {len(hit_patterns)} obfuscation indicators")
            elif len(hit_patterns) >= 1:
                score += 10
                signals.append("Potentially suspicious JavaScript detected")

            # Keylogger patterns
            if "keydown" in script.lower() or "keypress" in script.lower():
                score += 15
                signals.append("Keyboard event listener detected (possible keylogger)")

            # Clipboard hijacking
            if "clipboard" in script.lower():
                score += 10
                signals.append("Clipboard access detected")

            # Crypto mining
            if any(k in script.lower() for k in ["coinhive", "cryptonight", "minero", "cryptoloot"]):
                score += 40
                indicators.append("Cryptocurrency mining script detected")

        return {"score": score, "signals": signals, "indicators": indicators}

    def _analyze_text(self, text: str) -> Dict:
        score = 0
        signals = []
        text_lower = text.lower()

        hits = [phrase for phrase in SOCIAL_ENGINEERING if phrase in text_lower]
        if len(hits) >= 3:
            score += 25
            signals.append(f"Multiple social engineering phrases: {len(hits)} detected")
        elif len(hits) >= 1:
            score += 10
            signals.append(f"Social engineering text: '{hits[0]}'")

        # Urgency/scarcity language
        urgency_words = ["urgent", "immediately", "expire", "limited time", "act now", "last chance"]
        urgency_hits = [w for w in urgency_words if w in text_lower]
        if len(urgency_hits) >= 2:
            score += 15
            signals.append("High-pressure urgency language detected")

        return {"score": score, "signals": signals}

    def _analyze_title(self, title: str, url: str) -> Dict:
        score = 0
        signals = []
        title_lower = title.lower()

        suspicious_titles = [
            "verify", "login", "sign in", "account suspended",
            "security alert", "password", "update required",
        ]
        hits = [t for t in suspicious_titles if t in title_lower]
        if hits:
            score += 10
            signals.append(f"Suspicious page title: '{title[:50]}'")

        # Title claims to be a brand that doesn't match domain
        brands = ["paypal", "amazon", "google", "microsoft", "apple", "facebook", "netflix", "bank"]
        for brand in brands:
            if brand in title_lower and brand not in url.lower():
                score += 20
                signals.append(f"Page title claims to be '{brand}' but domain doesn't match")
                break

        return {"score": score, "signals": signals}

    def _analyze_html(self, html: str) -> Dict:
        score = 0
        signals = []
        indicators = []
        html_lower = html.lower()

        # Hidden iframes
        iframe_count = html_lower.count("<iframe")
        hidden_iframes = len(re.findall(r'<iframe[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*["\']0|height\s*=\s*["\']0)[^>]*>', html_lower))
        if hidden_iframes > 0:
            score += 25
            indicators.append(f"{hidden_iframes} hidden iframe(s) detected")
        elif iframe_count > 3:
            score += 10
            signals.append(f"Multiple iframes detected ({iframe_count})")

        # Data URIs (obfuscation)
        if "data:text/html" in html_lower or "data:application/" in html_lower:
            score += 20
            signals.append("Data URI embedding detected (obfuscation technique)")

        # Meta refresh redirect
        if re.search(r'<meta[^>]*http-equiv[^>]*refresh', html_lower):
            score += 15
            signals.append("Automatic page redirect (meta refresh) detected")

        # Excessive pop-up triggers
        popup_count = html_lower.count("window.open(") + html_lower.count("alert(")
        if popup_count > 3:
            score += 15
            signals.append(f"Excessive popup triggers detected ({popup_count})")

        # Clickjacking elements
        if re.search(r'position\s*:\s*(?:fixed|absolute)[^;]*z-index\s*:\s*9{3,}', html_lower):
            score += 15
            signals.append("Potential clickjacking element detected")

        # Fake download buttons
        fake_download = re.findall(r'<(?:button|a)[^>]*>(?:[^<]*(?:download|install|update|click here)[^<]*)</(?:button|a)>', html_lower)
        if len(fake_download) > 2:
            score += 20
            indicators.append("Multiple fake download/install buttons detected")

        return {"score": score, "signals": signals, "indicators": indicators}
