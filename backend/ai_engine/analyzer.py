"""
ThreatAnalyzer
==============
High-level facade. Used by the AIDetectionEngine to perform a single,
production-grade ML pass:

    features ──► PredictionCache?─► EnsemblePredictor ─► ScoringEngine ─► result

The result includes:
    - models:       per-model phishing probabilities (0..100)
    - weighted_votes: each model's contribution to the ensemble decision
    - ensemble:     aggregate probability, confidence, agreement
    - scores:       RiskScores dict (overall / phishing / malware / ...)
    - risk_level:   safe | low | medium | high | critical
    - prediction:   the dominant threat label (phishing / malware / safe / ...)
"""
from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Optional

from .model_manager import get_model_manager
from .ensemble_predictor import EnsemblePredictor
from .scoring_engine import ScoringEngine
from .prediction_cache import prediction_cache

logger = logging.getLogger(__name__)


class ThreatAnalyzer:
    """Glue layer between feature extraction and final scoring."""

    def __init__(
        self,
        model_manager=None,
        ensemble: Optional[EnsemblePredictor] = None,
        scoring: Optional[ScoringEngine] = None,
        cache=prediction_cache,
    ):
        self.mm = model_manager or get_model_manager()
        self.ensemble = ensemble or EnsemblePredictor(self.mm)
        self.scoring = scoring or ScoringEngine()
        self.cache = cache

    # --------------------------------------------------------------- run sync
    def analyze_sync(
        self,
        url: str,
        features: List[float],
        url_features: Dict,
        domain_rep_score: float = 0.0,
        content_score: float = 0.0,
        dom_signals: Optional[Dict] = None,
        redirect_chain: Optional[List[str]] = None,
        heuristic_score: float = 0.0,
    ) -> Dict:
        """Run ensemble inference + scoring. Cached on the feature vector."""
        cache_key = self.cache.make_key(features)
        cached_ensemble = self.cache.get(cache_key)

        if cached_ensemble is None:
            cached_ensemble = self.ensemble.predict(features)
            self.cache.set(cache_key, cached_ensemble)

        e = cached_ensemble
        scores = self.scoring.score(
            url=url,
            ensemble_probability=e.threat_probability,
            url_features=url_features,
            domain_rep_score=domain_rep_score,
            content_score=content_score,
            dom_signals=dom_signals,
            redirect_chain=redirect_chain,
            heuristic_score=heuristic_score,
        )

        risk_level = self.scoring.risk_level(scores.overall_threat_score)
        prediction = self._pick_prediction(scores, risk_level)

        return {
            "prediction": prediction,
            "risk_level": risk_level,
            "confidence": round(e.confidence * 100.0, 2),
            "agreement": round(e.agreement * 100.0, 2),
            "ensemble_probability": round(e.threat_probability * 100.0, 2),
            "models": {name: round(p * 100.0, 2) for name, p in e.per_model.items()},
            "weighted_votes": {name: round(v * 100.0, 2) for name, v in e.weighted_votes.items()},
            "model_weights": {name: round(w, 4) for name, w in e.weights.items()},
            "scores": scores.to_dict(),
            "engine_status": "ml" if self.mm.loaded else "heuristic_fallback",
        }

    # -------------------------------------------------------------- run async
    async def analyze(self, *args, **kwargs) -> Dict:
        """Async wrapper — offloads CPU-bound inference off the event loop."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.analyze_sync(*args, **kwargs))

    # ------------------------------------------------------------ prediction
    @staticmethod
    def _pick_prediction(scores, risk_level: str) -> str:
        """Pick the dominant threat label by comparing specialised scores."""
        if risk_level == "safe":
            return "safe"

        # Each candidate competes on its own dedicated score; the winner wins
        # only if it clears 50 — otherwise we fall back to a generic label.
        candidates = (
            ("phishing",         scores.phishing_probability),
            ("malware",          scores.malware_probability),
            ("impersonation",    scores.impersonation_risk),
            ("credential_theft", scores.credential_theft_risk),
            ("redirect_abuse",   scores.redirect_abuse_risk),
        )
        label, val = max(candidates, key=lambda kv: kv[1])
        if val >= 50:
            return label
        if risk_level in ("high", "critical"):
            return "phishing"
        return "suspicious"
