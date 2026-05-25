"""
EnsemblePredictor
=================
Combines per-model probabilities into a single threat probability and a
confidence figure.

We use a weighted soft-vote: each model contributes its phishing probability
multiplied by its weight, then renormalised. Confidence is derived from two
signals:
    1. The magnitude of the aggregated probability (distance from 0.5).
    2. The level of inter-model agreement (low variance = high confidence).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, List

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class EnsembleResult:
    threat_probability: float           # 0..1
    confidence: float                   # 0..1
    agreement: float                    # 0..1 (1 = perfect agreement)
    per_model: Dict[str, float]         # raw probabilities, 0..1
    weighted_votes: Dict[str, float]    # weighted contributions, 0..1
    weights: Dict[str, float]           # the weights actually used


class EnsemblePredictor:
    """Weighted soft-vote ensemble with confidence aggregation."""

    def __init__(self, model_manager):
        self.mm = model_manager

    def predict(self, features: List[float]) -> EnsembleResult:
        per_model = self.mm.predict_all(features)

        if not per_model:
            return EnsembleResult(
                threat_probability=0.0,
                confidence=0.0,
                agreement=0.0,
                per_model={},
                weighted_votes={},
                weights={},
            )

        weights = self._normalise_weights(per_model.keys())
        weighted = {name: per_model[name] * weights[name] for name in per_model}
        threat_p = float(sum(weighted.values()))

        probs = np.array(list(per_model.values()), dtype=float)
        # Agreement: inverse of standard deviation, clipped to [0, 1]. With 4
        # models, std maxes out near 0.5; we map 0 std -> 1.0, 0.5 -> 0.
        agreement = float(np.clip(1.0 - (probs.std() * 2.0), 0.0, 1.0))

        # Confidence: how far the consensus is from indecision, lifted by
        # agreement. Both factors are bounded so the result stays in [0, 1].
        decisiveness = float(min(1.0, abs(threat_p - 0.5) * 2.0))
        confidence = float(np.clip(0.55 * decisiveness + 0.45 * agreement, 0.0, 1.0))

        return EnsembleResult(
            threat_probability=threat_p,
            confidence=confidence,
            agreement=agreement,
            per_model=per_model,
            weighted_votes=weighted,
            weights=weights,
        )

    def _normalise_weights(self, model_names) -> Dict[str, float]:
        """Pull weights from the manager, falling back to uniform if missing."""
        raw = {name: float(self.mm.weights.get(name, 0.0)) for name in model_names}
        total = sum(raw.values())
        if total <= 0:
            n = max(1, len(raw))
            return {name: 1.0 / n for name in raw}
        return {name: w / total for name, w in raw.items()}
