import re
import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Banking and financial brand names that trigger cloned-page detection
BANKING_BRANDS = [
    "chase", "wellsfargo", "bankofamerica", "citibank", "capitalone",
    "barclays", "hsbc", "santander", "usbank", "tdbank", "pnc",
    "paypal", "stripe", "square", "venmo", "cashapp", "zelle",
    "visa", "mastercard", "amex", "americanexpress", "discover",
    "coinbase", "binance", "kraken", "gemini", "blockchain",
]

# Known trusted brands for impersonation detection
IMPERSONATION_BRANDS = [
    "google", "microsoft", "apple", "amazon", "facebook", "instagram",
    "twitter", "linkedin", "netflix", "spotify", "adobe", "dropbox",
    "github", "gitlab", "slack", "zoom", "paypal", "ebay", "walmart",
    "fedex", "ups", "dhl", "usps", "irs", "ssa", "medicare",
]

# Credential-harvesting input field names / types
CREDENTIAL_FIELD_NAMES = [
    "password", "passwd", "pwd", "pass", "pin", "secret", "token",
    "ssn", "social", "dob", "birthdate", "birthday",
    "cardnumber", "card_number", "cc", "ccnum", "cc_num",
    "cvv", "cvc", "cvv2", "csc", "security_code",
    "expiry", "expiration", "exp_date", "exp_month", "exp_year",
    "routing", "account_number", "bank_account",
]

# Suspicious submit button texts (credential harvesting)
SUSPICIOUS_BUTTON_TEXTS = [
    "verify account", "verify identity", "confirm identity", "verify now",
    "update payment", "update billing", "update card",
    "unlock account", "reactivate account", "restore access",
    "claim reward", "claim prize", "get reward",
    "login to continue", "sign in to verify", "continue to verify",
    "submit credentials", "send credentials",
]

# Suspicious overlay / modal CSS patterns in HTML
OVERLAY_PATTERNS = [
    r'position\s*:\s*fixed[^;]*(?:width\s*:\s*100|height\s*:\s*100)',
    r'position\s*:\s*absolute[^;]*(?:width\s*:\s*100|z-index\s*:\s*[89]\d{3,})',
    r'z-index\s*:\s*(?:99999|2147483|999999)',
]

# CSS tricks used to hide credential-stealing elements
CSS_HIDING_PATTERNS = [
    r'opacity\s*:\s*0(?:\s*;|!important)',
    r'display\s*:\s*none(?:\s*;|!important)',
    r'visibility\s*:\s*hidden(?:\s*;|!important)',
    r'left\s*:\s*-\d{3,}px',
    r'top\s*:\s*-\d{3,}px',
    r'clip\s*:\s*rect\s*\(\s*0\s*,\s*0\s*,\s*0\s*,\s*0\s*\)',
    r'font-size\s*:\s*0(?:px)?(?:\s*;|!important)',
]


class DOMAnalyzer:
    """
    Advanced visual and page-structure analysis module.
    Detects fake login pages, cloned banking sites, credential harvesting,
    hidden elements, CSS tricks, and impersonation patterns.
    """

    def __init__(self):
        self._overlay_patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in OVERLAY_PATTERNS]
        self._hide_patterns = [re.compile(p, re.IGNORECASE) for p in CSS_HIDING_PATTERNS]

    async def analyze(
        self,
        html_content: str = None,
        page_title: str = None,
        page_text: str = None,
        forms: List[Dict] = None,
        dom_data: Dict = None,
        url: str = "",
    ) -> Dict:
        """
        Run full DOM/visual analysis and return structured threat assessment.
        dom_data is the enhanced data dict sent by the content script.
        """
        result = {
            "score": 0,
            "visual_risk_score": 0.0,
            "login_risk": 0.0,
            "impersonation_risk": 0.0,
            "credential_theft_probability": 0.0,
            "fake_login_detected": False,
            "cloned_page_detected": False,
            "hidden_elements_found": 0,
            "suspicious_overlays": 0,
            "css_tricks_detected": False,
            "iframe_count": 0,
            "hidden_iframes": 0,
            "suspicious_buttons": [],
            "credential_harvesting_patterns": [],
            "impersonation_signals": [],
            "signals": [],
        }

        try:
            login_score = 0
            impersonation_score = 0
            cred_score = 0
            structural_score = 0

            # ── Forms & Credential Analysis ──────────────────────────────────
            if forms:
                fa = self._analyze_forms_advanced(forms, url)
                login_score += fa["login_score"]
                cred_score += fa["cred_score"]
                result["credential_harvesting_patterns"].extend(fa["cred_patterns"])
                result["suspicious_buttons"].extend(fa["suspicious_buttons"])
                result["signals"].extend(fa["signals"])

            # ── Enhanced DOM Data from Content Script ────────────────────────
            if dom_data:
                da = self._analyze_dom_data(dom_data, url)
                login_score += da["login_score"]
                cred_score += da["cred_score"]
                structural_score += da["structural_score"]
                result["hidden_elements_found"] += da["hidden_elements"]
                result["suspicious_overlays"] += da["overlays"]
                result["css_tricks_detected"] = result["css_tricks_detected"] or da["css_tricks"]
                result["iframe_count"] += da["iframe_count"]
                result["hidden_iframes"] += da["hidden_iframes"]
                result["suspicious_buttons"].extend(da["suspicious_buttons"])
                result["credential_harvesting_patterns"].extend(da["cred_patterns"])
                result["signals"].extend(da["signals"])

            # ── HTML Content Analysis ────────────────────────────────────────
            if html_content:
                ha = self._analyze_html_structure(html_content, url)
                login_score += ha["login_score"]
                impersonation_score += ha["impersonation_score"]
                cred_score += ha["cred_score"]
                structural_score += ha["structural_score"]
                result["hidden_elements_found"] += ha["hidden_elements"]
                result["suspicious_overlays"] += ha["overlays"]
                result["css_tricks_detected"] = result["css_tricks_detected"] or ha["css_tricks"]
                result["iframe_count"] += ha["iframe_count"]
                result["hidden_iframes"] += ha["hidden_iframes"]
                result["credential_harvesting_patterns"].extend(ha["cred_patterns"])
                result["impersonation_signals"].extend(ha["impersonation_signals"])
                result["signals"].extend(ha["signals"])

            # ── Page Title & Text Analysis ───────────────────────────────────
            if page_title or page_text:
                ta = self._analyze_page_content(page_title, page_text, url)
                login_score += ta["login_score"]
                impersonation_score += ta["impersonation_score"]
                result["impersonation_signals"].extend(ta["impersonation_signals"])
                result["signals"].extend(ta["signals"])

            # ── Cloned Page Detection ────────────────────────────────────────
            if impersonation_score >= 30 and (login_score >= 20 or cred_score >= 20):
                result["cloned_page_detected"] = True
                result["signals"].append("Page structure matches cloned banking/payment site pattern")

            # ── Fake Login Detection ─────────────────────────────────────────
            if login_score >= 40:
                result["fake_login_detected"] = True
                result["signals"].append("Fake login page detected: suspicious authentication form")

            # ── Compute Visual Risk Scores (0-100) ───────────────────────────
            result["login_risk"] = round(min(100.0, login_score), 1)
            result["impersonation_risk"] = round(min(100.0, impersonation_score), 1)
            result["credential_theft_probability"] = round(min(100.0, cred_score), 1)

            # Visual risk = weighted combination of the three sub-scores
            visual = (
                result["login_risk"] * 0.40
                + result["impersonation_risk"] * 0.35
                + result["credential_theft_probability"] * 0.25
            )
            # Add structural penalty
            visual = min(100.0, visual + structural_score * 0.15)
            result["visual_risk_score"] = round(visual, 1)

            # Overall DOM analysis score fed into the multi-layer engine
            result["score"] = round(min(100.0, visual + structural_score * 0.1), 1)

            # Deduplicate
            result["signals"] = list(dict.fromkeys(result["signals"]))[:12]
            result["credential_harvesting_patterns"] = list(dict.fromkeys(result["credential_harvesting_patterns"]))[:6]
            result["suspicious_buttons"] = list(dict.fromkeys(result["suspicious_buttons"]))[:6]
            result["impersonation_signals"] = list(dict.fromkeys(result["impersonation_signals"]))[:6]

        except Exception as e:
            logger.error(f"DOM analysis error: {e}")

        return result

    # ── Private Analysis Methods ─────────────────────────────────────────────

    def _analyze_forms_advanced(self, forms: List[Dict], url: str) -> Dict:
        login_score = 0
        cred_score = 0
        cred_patterns = []
        suspicious_buttons = []
        signals = []

        domain = self._extract_domain(url)

        for form in forms:
            action = str(form.get("action", "")).lower()
            inputs = form.get("inputs", [])
            input_types = [str(i.get("type", "text")).lower() for i in inputs]
            input_names = [str(i.get("name", "") + " " + i.get("placeholder", "")).lower() for i in inputs]
            combined = " ".join(input_names)

            has_password = "password" in input_types
            has_text_or_email = any(t in input_types for t in ["text", "email", "tel"])
            has_hidden_password = any(
                i.get("type") == "hidden" and any(k in str(i.get("name", "")).lower() for k in ["pass", "pwd"])
                for i in inputs
            )

            # Classic login form pattern
            if has_password and has_text_or_email:
                login_score += 30
                signals.append("Classic login form detected (username + password fields)")

            # Hidden password field — classic phishing trick
            if has_hidden_password:
                login_score += 25
                cred_score += 20
                cred_patterns.append("Hidden password field found in form")
                signals.append("Hidden password field detected (credential harvesting)")

            # External form submission
            if action.startswith("http") and domain and domain not in action:
                login_score += 20
                cred_score += 25
                signals.append(f"Login form submits to external domain")

            # Credential field analysis
            cred_hits = [name for name in CREDENTIAL_FIELD_NAMES if name in combined]
            if len(cred_hits) >= 3:
                cred_score += 35
                cred_patterns.append(f"Credential harvesting fields: {', '.join(cred_hits[:4])}")
            elif len(cred_hits) >= 1:
                cred_score += 15
                cred_patterns.append(f"Sensitive field detected: {cred_hits[0]}")

            # Suspicious submit button text in inputs (type=submit or button)
            for inp in inputs:
                btn_text = (str(inp.get("value", "")) + " " + str(inp.get("name", ""))).lower()
                for sus_text in SUSPICIOUS_BUTTON_TEXTS:
                    if sus_text in btn_text:
                        suspicious_buttons.append(btn_text.strip()[:60])
                        login_score += 10
                        break

        return {
            "login_score": login_score,
            "cred_score": cred_score,
            "cred_patterns": cred_patterns,
            "suspicious_buttons": suspicious_buttons,
            "signals": signals,
        }

    def _analyze_dom_data(self, dom_data: Dict, url: str) -> Dict:
        """Analyze enhanced DOM data collected by the content script."""
        login_score = 0
        cred_score = 0
        structural_score = 0
        hidden_elements = 0
        overlays = 0
        css_tricks = False
        iframe_count = 0
        hidden_iframes = 0
        suspicious_buttons = []
        cred_patterns = []
        signals = []

        # Hidden elements from content script
        hidden = dom_data.get("hiddenElements", {})
        hidden_passwords = hidden.get("passwordFields", 0)
        hidden_forms = hidden.get("forms", 0)
        hidden_inputs = hidden.get("inputs", 0)
        hidden_elements = hidden.get("count", 0)

        if hidden_passwords > 0:
            cred_score += 30
            cred_patterns.append(f"{hidden_passwords} hidden password field(s) detected")
            signals.append("Hidden password fields found (classic credential harvesting)")

        if hidden_forms > 0:
            structural_score += 20
            signals.append(f"{hidden_forms} hidden form(s) detected")

        # Overlay/modal analysis
        overlay_data = dom_data.get("overlays", {})
        fullscreen_overlays = overlay_data.get("fullscreen", 0)
        overlays = fullscreen_overlays
        if fullscreen_overlays > 0:
            structural_score += 15
            signals.append(f"{fullscreen_overlays} suspicious overlay/modal element(s) detected")

        # Suspicious buttons
        btn_list = dom_data.get("suspiciousButtons", [])
        for btn_text in btn_list[:6]:
            suspicious_buttons.append(btn_text[:60])
            login_score += 8
        if btn_list:
            signals.append(f"Suspicious button text: '{btn_list[0][:40]}'")

        # Iframe analysis
        iframe_data = dom_data.get("iframes", {})
        iframe_count = iframe_data.get("count", 0)
        hidden_iframes = iframe_data.get("hidden", 0)
        cross_origin = iframe_data.get("crossOrigin", 0)

        if hidden_iframes > 0:
            structural_score += 25
            signals.append(f"{hidden_iframes} hidden iframe(s) detected")

        if cross_origin > 0:
            structural_score += 10

        # CSS tricks
        css_trick_data = dom_data.get("cssTricks", {})
        css_tricks = css_trick_data.get("detected", False)
        offscreen_count = css_trick_data.get("offscreenElements", 0)
        zero_opacity = css_trick_data.get("zeroOpacity", 0)

        if css_tricks:
            structural_score += 15
            signals.append("CSS hiding tricks detected (off-screen or invisible elements)")

        if zero_opacity > 0:
            structural_score += 10

        # Input field analysis from content script
        input_fields = dom_data.get("inputFields", [])
        password_inputs = [f for f in input_fields if f.get("type") == "password"]
        hidden_inputs_list = [f for f in input_fields if f.get("type") == "hidden"]

        if len(password_inputs) >= 1 and len(input_fields) >= 2:
            login_score += 20

        # Check for cloned-page signature: many hidden inputs with credential names
        hidden_cred_inputs = [
            i for i in hidden_inputs_list
            if any(k in str(i.get("name", "")).lower() for k in CREDENTIAL_FIELD_NAMES)
        ]
        if hidden_cred_inputs:
            cred_score += 25
            cred_patterns.append(f"Hidden credential inputs: {', '.join(i.get('name','?') for i in hidden_cred_inputs[:3])}")

        return {
            "login_score": login_score,
            "cred_score": cred_score,
            "structural_score": structural_score,
            "hidden_elements": hidden_elements,
            "overlays": overlays,
            "css_tricks": css_tricks,
            "iframe_count": iframe_count,
            "hidden_iframes": hidden_iframes,
            "suspicious_buttons": suspicious_buttons,
            "cred_patterns": cred_patterns,
            "signals": signals,
        }

    def _analyze_html_structure(self, html: str, url: str) -> Dict:
        login_score = 0
        impersonation_score = 0
        cred_score = 0
        structural_score = 0
        hidden_elements = 0
        overlays = 0
        css_tricks = False
        iframe_count = 0
        hidden_iframes = 0
        cred_patterns = []
        impersonation_signals = []
        signals = []

        html_lower = html.lower()
        domain = self._extract_domain(url)

        # ── Fake Login Detection via HTML ────────────────────────────────────
        has_password_field = bool(re.search(r'<input[^>]*type\s*=\s*["\']password["\']', html_lower))
        has_text_field = bool(re.search(r'<input[^>]*type\s*=\s*["\'](?:text|email|tel)["\']', html_lower))
        has_login_label = bool(re.search(
            r'(?:username|email\s+address|phone\s+number|user\s+id|account\s+id)', html_lower
        ))

        if has_password_field and has_text_field:
            login_score += 25
        if has_password_field and has_login_label:
            login_score += 15
            signals.append("Login form labels detected alongside password field")

        # Hidden password fields via HTML
        hidden_pwd = len(re.findall(
            r'<input[^>]*type\s*=\s*["\']hidden["\'][^>]*name\s*=\s*["\'][^"\']*(?:pass|pwd|token)[^"\']*["\']',
            html_lower
        ))
        if hidden_pwd > 0:
            cred_score += 25
            hidden_elements += hidden_pwd
            cred_patterns.append(f"{hidden_pwd} hidden credential input(s) in HTML")
            signals.append("Hidden credential inputs found in HTML source")

        # ── Suspicious Overlays ──────────────────────────────────────────────
        overlay_count = 0
        for pattern in self._overlay_patterns:
            overlay_count += len(pattern.findall(html))
        overlays = min(overlay_count, 10)
        if overlays > 0:
            structural_score += min(25, overlays * 8)
            signals.append(f"{overlays} suspicious overlay/modal structure(s) in HTML")

        # ── CSS Tricks ───────────────────────────────────────────────────────
        css_trick_count = 0
        for pattern in self._hide_patterns:
            css_trick_count += len(pattern.findall(html))
        if css_trick_count >= 3:
            css_tricks = True
            structural_score += 20
            signals.append(f"CSS hiding techniques detected ({css_trick_count} instances)")
        elif css_trick_count >= 1:
            css_tricks = True
            structural_score += 8

        # ── Iframe Analysis ──────────────────────────────────────────────────
        iframe_count = html_lower.count("<iframe")
        hidden_iframe_matches = re.findall(
            r'<iframe[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|'
            r'width\s*=\s*["\']0["\']|height\s*=\s*["\']0["\']|'
            r'width\s*:\s*0|height\s*:\s*0)[^>]*>',
            html_lower
        )
        hidden_iframes = len(hidden_iframe_matches)
        if hidden_iframes > 0:
            structural_score += 30
            signals.append(f"{hidden_iframes} hidden iframe(s) found")

        # ── Banking / Impersonation Patterns ─────────────────────────────────
        for brand in BANKING_BRANDS:
            if brand in html_lower and (not domain or brand not in domain):
                impersonation_score += 15
                impersonation_signals.append(f"Banking brand '{brand}' referenced without matching domain")
                if impersonation_score >= 30:
                    break

        for brand in IMPERSONATION_BRANDS:
            if brand in html_lower and (not domain or brand not in domain):
                # Only flag if the brand appears in prominent places (title, h1, header)
                if re.search(rf'<(?:title|h1|h2|header)[^>]*>[^<]*{brand}[^<]*</', html_lower):
                    impersonation_score += 20
                    impersonation_signals.append(f"Brand '{brand}' in page headers but not in domain")

        # ── Fake Support Popups ──────────────────────────────────────────────
        support_popup = bool(re.search(
            r'(?:call\s+support|contact\s+us\s+now|support\s+hotline|tech\s+support)[^<]*'
            r'(?:\d{3}[-.\s]?\d{3}[-.\s]?\d{4})',
            html_lower
        ))
        if support_popup:
            structural_score += 20
            impersonation_score += 15
            signals.append("Fake tech support popup pattern detected")

        # ── Credential Harvesting: card number fields ────────────────────────
        card_field = bool(re.search(
            r'<input[^>]*(?:name|id|placeholder)\s*=\s*["\'][^"\']*(?:card.?num|cc.?num|creditcard)[^"\']*["\']',
            html_lower
        ))
        if card_field:
            cred_score += 30
            cred_patterns.append("Credit card number input field detected")
            signals.append("Credit card number field found — possible fake payment page")

        # ── Suspicious Submit Buttons in HTML ────────────────────────────────
        buttons = re.findall(r'<(?:button|input[^>]*type\s*=\s*["\']submit["\'])[^>]*>([^<]{3,60})<', html_lower)
        for btn_text in buttons:
            for sus_text in SUSPICIOUS_BUTTON_TEXTS:
                if sus_text in btn_text:
                    login_score += 10
                    signals.append(f"Suspicious submit button: '{btn_text.strip()[:50]}'")
                    break

        return {
            "login_score": login_score,
            "impersonation_score": impersonation_score,
            "cred_score": cred_score,
            "structural_score": structural_score,
            "hidden_elements": hidden_elements,
            "overlays": overlays,
            "css_tricks": css_tricks,
            "iframe_count": iframe_count,
            "hidden_iframes": hidden_iframes,
            "cred_patterns": cred_patterns,
            "impersonation_signals": impersonation_signals,
            "signals": signals,
        }

    def _analyze_page_content(
        self, page_title: Optional[str], page_text: Optional[str], url: str
    ) -> Dict:
        login_score = 0
        impersonation_score = 0
        impersonation_signals = []
        signals = []

        domain = self._extract_domain(url)
        title_lower = (page_title or "").lower()
        text_lower = (page_text or "").lower()

        # Login-themed page title
        login_title_patterns = [
            "log in", "login", "sign in", "signin", "account access",
            "verify your", "confirm your", "secure login", "member login",
            "customer login", "online banking", "account verification",
        ]
        for pattern in login_title_patterns:
            if pattern in title_lower:
                login_score += 20
                signals.append(f"Login-themed page title: '{page_title[:50]}'")
                break

        # Brand impersonation in title vs domain
        for brand in IMPERSONATION_BRANDS + BANKING_BRANDS:
            if brand in title_lower and domain and brand not in domain:
                impersonation_score += 25
                impersonation_signals.append(f"Title claims to be '{brand}' but URL domain is '{domain}'")
                break

        # Text-based impersonation (financial institution language)
        financial_phrases = [
            "your account has been limited", "verify your bank account",
            "unusual sign-in activity", "protect your account",
            "we noticed suspicious activity", "your account has been suspended",
            "confirm your billing information", "update your payment method",
            "enter your card details", "your card has been declined",
        ]
        hits = [p for p in financial_phrases if p in text_lower]
        if len(hits) >= 2:
            impersonation_score += 20
            login_score += 15
            signals.append(f"Financial/banking social engineering text detected ({len(hits)} patterns)")
        elif hits:
            impersonation_score += 10
            signals.append(f"Suspicious financial text: '{hits[0]}'")

        # "Official" language in non-official context
        official_claims = [
            "official website", "secure website", "verified by", "protected by",
            "100% secure", "your data is safe",
        ]
        official_hits = [p for p in official_claims if p in text_lower]
        if official_hits and domain and not any(b in domain for b in IMPERSONATION_BRANDS):
            impersonation_score += 15
            signals.append("Suspicious 'official/secure' claims on unrecognized domain")

        return {
            "login_score": login_score,
            "impersonation_score": impersonation_score,
            "impersonation_signals": impersonation_signals,
            "signals": signals,
        }

    def _extract_domain(self, url: str) -> str:
        try:
            return urlparse(url).netloc.lower().replace("www.", "")
        except Exception:
            return ""
