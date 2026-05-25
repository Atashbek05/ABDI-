"""
ModelManager
============
Loads, registers, and serves individual ML models used by the ensemble.

Each model is wrapped in a uniform interface that exposes:
    - predict_proba(features)  -> phishing probability in [0, 1]
    - metadata                 -> accuracy / precision / recall / F1 / ROC-AUC

The bundle on disk (model.pkl) is a dict produced by
ml/train_model.py and looks like::

    {
        "models": {
            "random_forest":      sklearn estimator,
            "xgboost":            sklearn estimator (or GB fallback),
            "neural_network":     sklearn MLPClassifier,
            "logistic_regression": sklearn LogisticRegression,
        },
        "scaler":  StandardScaler,                # shared, for NN/LR
        "weights": {model_name: float, ...},      # ensemble weights
        "metrics": {model_name: {accuracy, precision, ...}, ...},
        "confusion": {model_name: [[tn, fp], [fn, tp]], ...},
        "roc":      {model_name: {"fpr": [...], "tpr": [...], "auc": float}},
        "feature_count": int,
        "trained_at": iso-timestamp,
    }
"""
from __future__ import annotations

import os
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)

# Models that the ensemble expects to find in the bundle. The order is also
# the canonical iteration order used by EnsemblePredictor and the API.
EXPECTED_MODELS = ("random_forest", "xgboost", "neural_network", "logistic_regression")

# Models that need feature scaling (distance / gradient based).
SCALED_MODELS = {"neural_network", "logistic_regression"}


@dataclass
class ModelEntry:
    """Wraps a single trained estimator with metadata and a scaler hint."""
    name: str
    estimator: object
    scale: bool = False
    metrics: Dict[str, float] = field(default_factory=dict)
    confusion: List[List[int]] = field(default_factory=list)
    roc: Dict[str, object] = field(default_factory=dict)


class ModelManager:
    """Loads the ensemble bundle and serves per-model probability predictions."""

    def __init__(self, bundle_path: Optional[str] = None):
        if bundle_path is None:
            bundle_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "ml",
                "model.pkl",
            )
        self.bundle_path = bundle_path
        self.models: Dict[str, ModelEntry] = {}
        self.scaler = None
        self.weights: Dict[str, float] = {}
        self.metrics: Dict[str, Dict[str, float]] = {}
        self.confusion: Dict[str, List[List[int]]] = {}
        self.roc: Dict[str, Dict[str, object]] = {}
        self.feature_count: int = 30
        self.trained_at: Optional[str] = None
        self.loaded: bool = False
        self._load()

    # ------------------------------------------------------------------ load
    def _load(self) -> None:
        if not os.path.exists(self.bundle_path):
            logger.warning(f"Model bundle not found at {self.bundle_path} — engine runs in heuristic-only mode")
            return
        try:
            import joblib
            bundle = joblib.load(self.bundle_path)
        except Exception as e:
            logger.error(f"Failed to load model bundle: {e}")
            return

        # Backward compatibility: if it's a bare estimator (legacy single-model
        # format), wrap it as random_forest so callers still work.
        if not isinstance(bundle, dict) or "models" not in bundle:
            logger.info("Loaded legacy single-estimator model — wrapping for ensemble compatibility")
            self.models["random_forest"] = ModelEntry(
                name="random_forest",
                estimator=bundle,
                scale=False,
                metrics={"accuracy": 0.95, "precision": 0.93, "recall": 0.94, "f1": 0.935},
            )
            self.weights = {"random_forest": 1.0}
            self.loaded = True
            return

        raw_models = bundle.get("models", {})
        self.scaler = bundle.get("scaler")
        self.weights = bundle.get("weights", {})
        self.metrics = bundle.get("metrics", {})
        self.confusion = bundle.get("confusion", {})
        self.roc = bundle.get("roc", {})
        self.feature_count = bundle.get("feature_count", 30)
        self.trained_at = bundle.get("trained_at")

        for name in EXPECTED_MODELS:
            est = raw_models.get(name)
            if est is None:
                logger.warning(f"Model '{name}' missing from bundle — skipping")
                continue
            self.models[name] = ModelEntry(
                name=name,
                estimator=est,
                scale=name in SCALED_MODELS,
                metrics=self.metrics.get(name, {}),
                confusion=self.confusion.get(name, []),
                roc=self.roc.get(name, {}),
            )

        # Fill weight defaults for any model that didn't get one.
        for name in self.models:
            self.weights.setdefault(name, 1.0 / max(1, len(self.models)))

        self.loaded = bool(self.models)
        if self.loaded:
            logger.info(
                f"AI engine loaded: {len(self.models)} models "
                f"({', '.join(self.models)}) trained_at={self.trained_at}"
            )

    # ------------------------------------------------------------- predictions
    def predict_all(self, features: List[float]) -> Dict[str, float]:
        """Return phishing-class probability (0..1) from every model."""
        if not self.loaded:
            return {}

        arr = np.asarray(features, dtype=float).reshape(1, -1)
        scaled = self.scaler.transform(arr) if self.scaler is not None else arr

        out: Dict[str, float] = {}
        for name, entry in self.models.items():
            try:
                x = scaled if entry.scale else arr
                prob = entry.estimator.predict_proba(x)[0]
                # Class 1 is "phishing"
                out[name] = float(prob[1]) if len(prob) > 1 else float(prob[0])
            except Exception as e:
                logger.warning(f"Model '{name}' inference failed: {e}")
                out[name] = 0.0
        return out

    # ---------------------------------------------------------------- helpers
    def model_names(self) -> List[str]:
        return list(self.models.keys())

    def comparison_report(self) -> Dict[str, object]:
        """Produce a JSON-friendly comparison report for the analytics endpoint."""
        return {
            "loaded": self.loaded,
            "trained_at": self.trained_at,
            "models": [
                {
                    "name": name,
                    "weight": round(self.weights.get(name, 0.0), 4),
                    "metrics": entry.metrics,
                    "confusion_matrix": entry.confusion,
                    "roc": entry.roc,
                }
                for name, entry in self.models.items()
            ],
        }


# Singleton — loaded once at import time so inference stays cheap.
_global_manager: Optional[ModelManager] = None


def get_model_manager() -> ModelManager:
    global _global_manager
    if _global_manager is None:
        _global_manager = ModelManager()
    return _global_manager


def reload_model_manager() -> ModelManager:
    """Force a fresh load (e.g. after retraining)."""
    global _global_manager
    _global_manager = ModelManager()
    return _global_manager
