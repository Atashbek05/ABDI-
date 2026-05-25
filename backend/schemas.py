from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class ScanRequest(BaseModel):
    url: str
    html_content: Optional[str] = None
    page_title: Optional[str] = None
    page_text: Optional[str] = None
    forms: Optional[List[Dict]] = None
    scripts: Optional[List[str]] = None
    redirects: Optional[List[str]] = None
    dom_data: Optional[Dict] = None  # Enhanced DOM data from content script


class ThreatDetail(BaseModel):
    category: str
    description: str
    severity: str
    confidence: float


class PageAnalysis(BaseModel):
    """Detailed visual and DOM structure analysis results."""
    fake_login_detected: bool = False
    cloned_page_detected: bool = False
    hidden_elements_found: int = 0
    suspicious_overlays: int = 0
    css_tricks_detected: bool = False
    iframe_count: int = 0
    hidden_iframes: int = 0
    suspicious_buttons: List[str] = []
    credential_harvesting_patterns: List[str] = []
    impersonation_signals: List[str] = []
    visual_risk_score: float = 0.0
    login_risk: float = 0.0
    impersonation_risk: float = 0.0
    credential_theft_probability: float = 0.0


class RiskScoreBreakdown(BaseModel):
    """Specialised risk verticals returned by the multi-model scoring engine."""
    overall_threat_score: float = 0.0
    phishing_probability: float = 0.0
    malware_probability: float = 0.0
    impersonation_risk: float = 0.0
    credential_theft_risk: float = 0.0
    redirect_abuse_risk: float = 0.0
    suspicious_behavior_score: float = 0.0


class EnsembleInfo(BaseModel):
    """Aggregate ensemble decision metadata."""
    probability: float = 0.0
    confidence: float = 0.0
    agreement: float = 0.0
    engine_status: str = "ml"


class ScanResponse(BaseModel):
    url: str
    domain: str
    is_safe: bool
    risk_level: str
    threat_type: str
    prediction: str = "safe"
    confidence: float
    risk_score: float
    reasons: List[str]
    threat_details: List[ThreatDetail]
    explanation: str
    scan_duration_ms: float
    timestamp: str
    ai_model_score: float
    heuristic_score: float
    domain_reputation_score: float
    content_analysis_score: float
    cached: bool = False
    # Visual / DOM analysis fields
    visual_risk_score: float = 0.0
    fake_login_detected: bool = False
    page_analysis: Optional[PageAnalysis] = None
    # Multi-model AI engine fields
    models: Dict[str, float] = {}
    weighted_votes: Dict[str, float] = {}
    model_weights: Dict[str, float] = {}
    scores: Optional[RiskScoreBreakdown] = None
    ensemble: Optional[EnsembleInfo] = None


class ScanHistoryItem(BaseModel):
    id: int
    url: str
    domain: str
    is_safe: bool
    threat_type: Optional[str]
    risk_level: Optional[str]
    confidence: float
    risk_score: float
    scan_duration_ms: float
    timestamp: str
    blocked: bool

    class Config:
        from_attributes = True


class BlacklistAdd(BaseModel):
    domain: str
    reason: Optional[str] = None
    threat_type: Optional[str] = None


class WhitelistAdd(BaseModel):
    domain: str
    reason: Optional[str] = None


class SettingUpdate(BaseModel):
    value: str


class AnalyticsResponse(BaseModel):
    total_scans: int
    threats_detected: int
    safe_sites: int
    blocked_count: int
    detection_rate: float
    avg_confidence: float
    avg_scan_duration: float
    threat_distribution: Dict[str, int]
    risk_level_distribution: Dict[str, int]
    daily_scans: List[Dict]
    top_threats: List[Dict]
    recent_threats: List[Dict]
