"""
CyberShield AI Engine
=====================
Production-grade multi-model threat scoring engine.

Public API:
    - ModelManager:       load/manage the individual ML models
    - EnsemblePredictor:  weighted-vote aggregation of model outputs
    - ScoringEngine:      derive specialised risk scores from features + ensemble
    - PredictionCache:    fast, TTL-bound result cache
    - ThreatAnalyzer:     facade that ties everything together for the API layer

The engine is split into small, focused modules so each piece (model loading,
voting, scoring, caching) can be swapped, unit-tested and reused independently.
"""

from .model_manager import ModelManager
from .ensemble_predictor import EnsemblePredictor
from .scoring_engine import ScoringEngine
from .prediction_cache import PredictionCache
from .analyzer import ThreatAnalyzer

__all__ = [
    "ModelManager",
    "EnsemblePredictor",
    "ScoringEngine",
    "PredictionCache",
    "ThreatAnalyzer",
]
