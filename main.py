"""
Phishing URL Detection — FastAPI Backend v3
Adds blacklist/whitelist management, advanced security detection, and page-signal analysis.

Run:    uvicorn main:app --reload
"""

import json
import os
import re
import sqlite3
import logging
from datetime import datetime, timezone
from typing import Literal, Optional
from urllib.parse import urlparse, parse_qs

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH   = os.path.join(SCRIPT_DIR, "..", "model", "model.pkl")
ENCODER_PATH = os.path.join(SCRIPT_DIR, "..", "model", "label_encoder.pkl")
DB_PATH      = os.path.join(SCRIPT_DIR, "scan_history.db")

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "account", "bank", "update",
    "confirm", "signin", "password", "webscr", "ebayisapi",
    "paypal", "credential", "authenticate", "wallet", "recover",
}

REDIRECT_PARAMS = {
    "redirect", "url", "return", "next", "goto", "redir",
    "redirect_uri", "redirect_url", "destination", "dest", "forward",
}

BRAND_NAMES = {
    "paypal", "apple", "microsoft", "google", "facebook", "amazon",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "chase",
    "wellsfargo", "bankofamerica", "citibank", "ebay", "steam", "discord",
    "binance", "coinbase", "blockchain",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".work", ".click", ".link", ".rest", ".pw", ".buzz",
}


# ── Database ──────────────────────────────────────────────────────────────────

def get_conn() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    conn = get_conn()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                url        TEXT    NOT NULL,
                prediction TEXT    NOT NULL,
                confidence REAL    NOT NULL,
                risk_level TEXT    NOT NULL,
                reasons    TEXT    NOT NULL,
                timestamp  TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS blacklist (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                domain     TEXT    NOT NULL UNIQUE,
                reason     TEXT    NOT NULL DEFAULT '',
                added_at   TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS whitelist (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                domain     TEXT    NOT NULL UNIQUE,
                added_at   TEXT    NOT NULL
            );
        """)
        conn.commit()
        log.info("Database ready at %s", DB_PATH)
    finally:
        conn.close()


def save_scan(url: str, prediction: str, confidence: float,
              risk_level: str, reasons: list[str]) -> None:
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO scans (url, prediction, confidence, risk_level, reasons, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (url, prediction, confidence, risk_level,
             json.dumps(reasons), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


def extract_domain(url: str) -> str:
    """Extract bare domain (no www., no port) from a URL string."""
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = (parsed.netloc or parsed.path).split(":")[0].lower().strip()
        return host[4:] if host.startswith("www.") else host
    except Exception:
        return url.lower().strip()


def is_blacklisted(url: str) -> tuple[bool, str]:
    domain = extract_domain(url)
    conn = get_conn()
    try:
        # Exact match OR the URL domain is a subdomain of a blacklisted domain
        row = conn.execute(
            "SELECT reason FROM blacklist WHERE domain = ? OR ? LIKE '%.' || domain",
            (domain, domain),
        ).fetchone()
        return (True, row[0]) if row else (False, "")
    finally:
        conn.close()


def is_whitelisted(url: str) -> bool:
    domain = extract_domain(url)
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT id FROM whitelist WHERE domain = ? OR ? LIKE '%.' || domain",
            (domain, domain),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


# ── Model Loading ─────────────────────────────────────────────────────────────

def load_artifacts():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model not found at: {MODEL_PATH}")
    if not os.path.exists(ENCODER_PATH):
        raise FileNotFoundError(f"Label encoder not found at: {ENCODER_PATH}")
    clf = joblib.load(MODEL_PATH)
    le  = joblib.load(ENCODER_PATH)
    log.info("Model loaded — classes: %s", list(le.classes_))
    return clf, le


try:
    MODEL, LABEL_ENCODER = load_artifacts()
    PHISHING_IDX = int(np.where(LABEL_ENCODER.classes_ == "phishing")[0][0]) \
        if "phishing" in LABEL_ENCODER.classes_ else 1
except Exception as exc:
    log.error("Failed to load model artifacts: %s", exc)
    MODEL, LABEL_ENCODER, PHISHING_IDX = None, None, 1


# ── Feature Extraction (mirrors train_model.py exactly) ──────────────────────

def _count_subdomains(parsed) -> int:
    host  = parsed.netloc or parsed.path
    host  = host.split(":")[0]
    parts = host.split(".")
    return max(0, len(parts) - 2)


def _is_ip_address(parsed) -> int:
    host = (parsed.netloc or parsed.path).split(":")[0]
    return int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)))


def _has_suspicious_keyword(url: str) -> int:
    url_lower = url.lower()
    return int(any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS))


def extract_features(url: str) -> dict:
    url = str(url).strip()
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        parsed = urlparse("")

    return {
        "url_length":        len(url),
        "num_dots":          url.count("."),
        "num_hyphens":       url.count("-"),
        "has_at_symbol":     int("@" in url),
        "has_https":         int(url.lower().startswith("https")),
        "num_digits":        sum(c.isdigit() for c in url),
        "num_subdomains":    _count_subdomains(parsed),
        "has_suspicious_kw": _has_suspicious_keyword(url),
        "uses_ip_address":   _is_ip_address(parsed),
        "num_slashes":       url.count("/"),
        "num_params":        len(parsed.query.split("&")) if parsed.query else 0,
        "url_depth":         len([p for p in parsed.path.split("/") if p]),
        "has_double_slash":  int("//" in parsed.path),
        "domain_length":     len(parsed.netloc),
    }


# ── Advanced Threat Pattern Regexes ──────────────────────────────────────────

FAKE_LOGIN_RE    = re.compile(r"[/?\-_](login|signin|account|verify|password)([/?\-_#]|$)", re.I)
JS_INJECTION_RE  = re.compile(r"javascript:|eval\s*\(|document\.cookie|<script", re.I)
REDIRECT_ABUSE_RE = re.compile(
    r"[?&](" + "|".join(re.escape(p) for p in REDIRECT_PARAMS) + r")=https?://", re.I
)
HOMOGLYPH_RE     = re.compile(r"[Ѐ-ӿͰ-Ͽ]")  # Cyrillic / Greek lookalikes
PUNYCODE_RE      = re.compile(r"xn--", re.I)
TYPOSQUAT_RE     = re.compile(r"\d+(paypal|apple|google|amazon|microsoft|facebook)", re.I)


# ── Risk Level ────────────────────────────────────────────────────────────────

def get_risk_level(confidence: float) -> Literal["safe", "suspicious", "high"]:
    if confidence < 40:
        return "safe"
    if confidence < 70:
        return "suspicious"
    return "high"


# ── Advanced Security Detection ───────────────────────────────────────────────

def detect_advanced_threats(url: str, features: dict,
                             page_signals: dict | None = None) -> list[str]:
    threats: list[str] = []
    url_lower = url.lower()

    # Open-redirect abuse
    if REDIRECT_ABUSE_RE.search(url):
        threats.append("Open redirect: URL passes external destination as parameter")

    # JavaScript injection in URL
    if JS_INJECTION_RE.search(url):
        threats.append("JavaScript injection pattern detected in URL")

    # Data URI
    if url_lower.startswith("data:"):
        threats.append("Data URI scheme — commonly used to bypass URL filters")

    # IDN / homoglyph spoofing
    if HOMOGLYPH_RE.search(url):
        threats.append("Unicode lookalike characters detected — possible homoglyph spoofing")

    if PUNYCODE_RE.search(url):
        threats.append("Punycode domain detected — possible internationalized domain spoofing")

    # Typosquatting (digit + brand name)
    if TYPOSQUAT_RE.search(url):
        threats.append("Digit-prefixed brand name detected — possible typosquatting domain")

    # Brand impersonation check
    try:
        parsed   = urlparse(url if "://" in url else "http://" + url)
        raw_host = (parsed.netloc or parsed.path).split(":")[0].lower()
        host     = raw_host[4:] if raw_host.startswith("www.") else raw_host
        parts    = host.split(".")
        domain_base = ".".join(parts[:-1]) if len(parts) > 1 else host
        for brand in BRAND_NAMES:
            if brand in domain_base and not (domain_base == brand or domain_base.endswith(f".{brand}")):
                threats.append(f"Brand impersonation: '{brand}' embedded in suspicious domain")
                break
    except Exception:
        pass

    # Excessive query parameters
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        params = parse_qs(parsed.query)
        if len(params) > 8:
            threats.append(f"Excessive query parameters ({len(params)}) — common in tracking/phishing")
    except Exception:
        pass

    # Suspicious free TLD
    for tld in SUSPICIOUS_TLDS:
        if (url_lower.endswith(tld)
                or f"{tld}/" in url_lower
                or f"{tld}?" in url_lower
                or f"{tld}#" in url_lower):
            threats.append(f"Suspicious top-level domain: {tld}")
            break

    # Page-level signals from content-script DOM analysis
    if page_signals:
        if page_signals.get("has_password_field") and page_signals.get("insecure_form_action"):
            threats.append("Login form submits credentials over an unencrypted connection")
        if page_signals.get("has_hidden_iframes"):
            threats.append("Hidden iframes detected — possible clickjacking or data-theft attempt")
        if page_signals.get("external_form_action"):
            threats.append("Form action targets an external domain — credentials may be harvested")
        if page_signals.get("suspicious_js_patterns"):
            threats.append("Obfuscated JavaScript detected on page — possible keylogger or data stealer")
        if page_signals.get("domain_mismatch"):
            threats.append("Page content references a brand that doesn't match the domain")

    return threats


# ── Reason Generation ─────────────────────────────────────────────────────────

def generate_reasons(url: str, features: dict, prediction: str,
                     page_signals: dict | None = None) -> list[str]:
    reasons: list[str] = []
    url_lower = url.lower()

    found_kws = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    for kw in list(found_kws)[:3]:
        reasons.append(f"Suspicious keyword detected: '{kw}'")

    if features["uses_ip_address"]:
        reasons.append("URL uses an IP address instead of a domain name")

    if features["num_subdomains"] >= 3:
        reasons.append(f"Excessive subdomains ({features['num_subdomains']}) — common in spoofing attacks")

    if features["url_length"] > 75:
        reasons.append(f"Unusually long URL ({features['url_length']} chars)")

    if not features["has_https"]:
        reasons.append("No HTTPS — connection is not encrypted")

    if features["num_digits"] > 10:
        reasons.append(f"Excessive digits in URL ({features['num_digits']})")

    if features["has_at_symbol"]:
        reasons.append("URL contains '@' — often used to disguise phishing links")

    if features["has_double_slash"]:
        reasons.append("Double slash in path — may indicate redirect abuse")

    if features["num_hyphens"] >= 3:
        reasons.append(f"Many hyphens ({features['num_hyphens']}) — common in fake domains")

    if features["num_dots"] >= 4:
        reasons.append(f"Excessive dots ({features['num_dots']}) — possible subdomain spoofing")

    if FAKE_LOGIN_RE.search(url) and not any("keyword" in r for r in reasons):
        reasons.append("URL path matches fake login-page patterns")

    # Advanced threat detection
    reasons.extend(detect_advanced_threats(url, features, page_signals))

    if not reasons:
        if features["has_https"]:
            reasons.append("Valid HTTPS connection")
        if features["num_subdomains"] <= 1:
            reasons.append("Normal subdomain structure")
        if features["url_length"] <= 75:
            reasons.append("Normal URL length")
        reasons.append("No suspicious patterns detected")

    return reasons


# ── Pydantic Models ───────────────────────────────────────────────────────────

class PageSignals(BaseModel):
    has_password_field:     bool = False
    insecure_form_action:   bool = False
    has_hidden_iframes:     bool = False
    external_form_action:   bool = False
    suspicious_js_patterns: bool = False
    domain_mismatch:        bool = False


class URLRequest(BaseModel):
    url: str
    page_signals: Optional[PageSignals] = None

    @field_validator("url")
    @classmethod
    def url_must_not_be_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("url must not be empty")
        return v


class PredictionResponse(BaseModel):
    prediction: Literal["phishing", "safe"]
    confidence: float
    risk_level: Literal["safe", "suspicious", "high"]
    reasons: list[str]
    source: str = "ai"   # "ai" | "blacklist" | "whitelist"


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    model_loaded: bool


class ScanRecord(BaseModel):
    id: int
    url: str
    prediction: str
    confidence: float
    risk_level: str
    reasons: list[str]
    timestamp: str


class HistoryResponse(BaseModel):
    scans: list[ScanRecord]
    total: int


class StatsResponse(BaseModel):
    total_scanned: int
    phishing_detected: int
    safe_detected: int
    suspicious_detected: int
    average_confidence: float
    most_common_threats: list[str]


class ListEntry(BaseModel):
    domain: str
    reason: str = ""

    @field_validator("domain")
    @classmethod
    def domain_must_not_be_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("domain must not be empty")
        return v


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Phishing URL Detector",
    description="AI-powered phishing detection with blacklist/whitelist, history, and analytics.",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE", "PUT"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    init_db()


# ── Meta ──────────────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["meta"])
def health():
    return HealthResponse(
        status="ok" if MODEL is not None else "degraded",
        model_loaded=MODEL is not None,
    )


# ── Detection ─────────────────────────────────────────────────────────────────

@app.post("/check", response_model=PredictionResponse, tags=["detection"])
def check_url(body: URLRequest):
    """Analyse a URL — checks whitelist, then blacklist, then runs AI scan."""
    log.info("Checking URL: %s", body.url)

    # 1. Whitelist — instant safe, no AI scan needed
    if is_whitelisted(body.url):
        log.info("Whitelisted: %s", body.url)
        reasons = ["Domain is in your trusted whitelist", "AI scan skipped — trusted source"]
        save_scan(body.url, "safe", 0.0, "safe", reasons)
        return PredictionResponse(prediction="safe", confidence=0.0,
                                  risk_level="safe", reasons=reasons, source="whitelist")

    # 2. Blacklist — instant block
    blacklisted, bl_reason = is_blacklisted(body.url)
    if blacklisted:
        log.info("Blacklisted: %s", body.url)
        reasons = ["Domain is on the known phishing blacklist"]
        if bl_reason:
            reasons.append(f"Reason: {bl_reason}")
        save_scan(body.url, "phishing", 100.0, "high", reasons)
        return PredictionResponse(prediction="phishing", confidence=100.0,
                                  risk_level="high", reasons=reasons, source="blacklist")

    # 3. AI scan
    if MODEL is None or LABEL_ENCODER is None:
        raise HTTPException(status_code=503, detail="Model not loaded. Check server logs.")

    try:
        features = extract_features(body.url)
        X = pd.DataFrame([features])
        proba = MODEL.predict_proba(X)[0]
        phishing_prob = float(proba[PHISHING_IDX])
    except Exception as exc:
        log.error("Prediction error for '%s': %s", body.url, exc)
        raise HTTPException(status_code=500, detail="Prediction failed.")

    confidence = round(phishing_prob * 100, 2)
    prediction: Literal["phishing", "safe"] = "phishing" if phishing_prob >= 0.5 else "safe"
    risk_level  = get_risk_level(confidence)
    signals     = body.page_signals.model_dump() if body.page_signals else None
    reasons     = generate_reasons(body.url, features, prediction, signals)

    log.info("Result → prediction=%s  confidence=%.2f%%  risk=%s  reasons=%d",
             prediction, confidence, risk_level, len(reasons))

    save_scan(body.url, prediction, confidence, risk_level, reasons)
    return PredictionResponse(prediction=prediction, confidence=confidence,
                              risk_level=risk_level, reasons=reasons, source="ai")


# ── History & Stats ───────────────────────────────────────────────────────────

@app.get("/history", response_model=HistoryResponse, tags=["analytics"])
def get_history(limit: int = Query(default=50, ge=1, le=500)):
    conn = get_conn()
    try:
        rows  = conn.execute(
            "SELECT id, url, prediction, confidence, risk_level, reasons, timestamp "
            "FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    finally:
        conn.close()

    scans = [
        ScanRecord(id=r[0], url=r[1], prediction=r[2], confidence=r[3],
                   risk_level=r[4], reasons=json.loads(r[5]), timestamp=r[6])
        for r in rows
    ]
    return HistoryResponse(scans=scans, total=total)


@app.get("/stats", response_model=StatsResponse, tags=["analytics"])
def get_stats():
    conn = get_conn()
    try:
        total      = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        phishing   = conn.execute("SELECT COUNT(*) FROM scans WHERE prediction='phishing'").fetchone()[0]
        safe       = conn.execute("SELECT COUNT(*) FROM scans WHERE prediction='safe'").fetchone()[0]
        suspicious = conn.execute("SELECT COUNT(*) FROM scans WHERE risk_level='suspicious'").fetchone()[0]
        avg_row    = conn.execute("SELECT AVG(confidence) FROM scans").fetchone()[0]
        avg_conf   = round(float(avg_row), 2) if avg_row is not None else 0.0
        ph_reasons = conn.execute("SELECT reasons FROM scans WHERE prediction='phishing'").fetchall()
    finally:
        conn.close()

    counts: dict[str, int] = {}
    for (raw,) in ph_reasons:
        for reason in json.loads(raw):
            counts[reason] = counts.get(reason, 0) + 1
    top5 = sorted(counts, key=counts.get, reverse=True)[:5]  # type: ignore[arg-type]

    return StatsResponse(
        total_scanned=total, phishing_detected=phishing, safe_detected=safe,
        suspicious_detected=suspicious, average_confidence=avg_conf,
        most_common_threats=top5,
    )


@app.delete("/history", tags=["analytics"])
def delete_history():
    conn = get_conn()
    try:
        conn.execute("DELETE FROM scans")
        conn.commit()
    finally:
        conn.close()
    log.info("Scan history cleared")
    return {"ok": True, "message": "History cleared"}


# ── Blacklist ─────────────────────────────────────────────────────────────────

@app.post("/blacklist/add", tags=["blacklist"])
def blacklist_add(entry: ListEntry):
    domain = entry.domain.strip().lower()
    if "://" in domain:
        domain = extract_domain(domain)
    conn = get_conn()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO blacklist (domain, reason, added_at) VALUES (?, ?, ?)",
            (domain, entry.reason, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    finally:
        conn.close()
    log.info("Blacklisted domain: %s", domain)
    return {"ok": True, "domain": domain}


@app.get("/blacklist", tags=["blacklist"])
def blacklist_get():
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, domain, reason, added_at FROM blacklist ORDER BY id DESC"
        ).fetchall()
    finally:
        conn.close()
    return {"entries": [{"id": r[0], "domain": r[1], "reason": r[2], "added_at": r[3]} for r in rows]}


@app.delete("/blacklist/{entry_id}", tags=["blacklist"])
def blacklist_delete(entry_id: int):
    conn = get_conn()
    try:
        conn.execute("DELETE FROM blacklist WHERE id = ?", (entry_id,))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


# ── Whitelist ─────────────────────────────────────────────────────────────────

@app.post("/whitelist/add", tags=["whitelist"])
def whitelist_add(entry: ListEntry):
    domain = entry.domain.strip().lower()
    if "://" in domain:
        domain = extract_domain(domain)
    conn = get_conn()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO whitelist (domain, added_at) VALUES (?, ?)",
            (domain, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    finally:
        conn.close()
    log.info("Whitelisted domain: %s", domain)
    return {"ok": True, "domain": domain}


@app.get("/whitelist", tags=["whitelist"])
def whitelist_get():
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, domain, added_at FROM whitelist ORDER BY id DESC"
        ).fetchall()
    finally:
        conn.close()
    return {"entries": [{"id": r[0], "domain": r[1], "added_at": r[2]} for r in rows]}


@app.delete("/whitelist/{entry_id}", tags=["whitelist"])
def whitelist_delete(entry_id: int):
    conn = get_conn()
    try:
        conn.execute("DELETE FROM whitelist WHERE id = ?", (entry_id,))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}
