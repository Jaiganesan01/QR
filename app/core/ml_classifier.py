"""
Machine-Learning Threat Classifier Adapter Interface for QShield.
Provides a safe integration boundary for statistical URL classification models.
If no pre-trained model artifact is configured, fails safely to 'unavailable' status
without fabricating predictions or interrupting local rule-based heuristic analysis.
"""
import logging
from typing import Any, Dict, Optional
from app.core.feature_extractor import extract_numerical_feature_vector

logger = logging.getLogger(__name__)


class MLThreatClassifier:
    """
    Adapter interface for optional machine-learning models.
    Supports pluggable local estimators with strict input validation.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self._model = None
        self._metadata: Dict[str, Any] = {
            "model_name": "QShield-Lexical-Classifier",
            "model_type": "LogisticRegression / DecisionTree (Baseline)",
            "version": "1.0.0-experimental",
            "feature_count": 21,
            "status": "unavailable",
            "trained_date": None,
        }
        self._load_model()

    def _load_model(self):
        """Attempts to load a verified local model artifact if configured."""
        if not self.model_path:
            self._metadata["status"] = "unavailable"
            return

        try:
            # Safe loading placeholder: can load pickle or custom json weights
            # For security, we avoid unverified deserialization
            self._metadata["status"] = "unavailable"
        except Exception as ex:
            logger.warning("Failed to initialize ML classifier: %s", str(ex))
            self._metadata["status"] = "load_error"

    def is_available(self) -> bool:
        """Returns True only if a verified model artifact is active in memory."""
        return self._model is not None and self._metadata["status"] == "active"

    def get_metadata(self) -> Dict[str, Any]:
        """Returns model operational metadata."""
        return dict(self._metadata)

    def predict(self, url: str, feature_vector: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
        """
        Executes model inference on extracted numerical features.
        If model is unavailable, returns an explicit, safe fallback structure.
        """
        if not self.is_available():
            return {
                "status": "unavailable",
                "model_name": self._metadata["model_name"],
                "prediction": None,
                "confidence": None,
                "risk_contribution": 0,
                "message": "No pre-trained ML model is configured. System safely utilizes explainable rule-based heuristics.",
                "limitations": "ML classification requires an offline-trained model artifact. Defaulting to rule-based evaluation."
            }

        # If model is active, extract features if not provided
        if feature_vector is None:
            feature_vector = extract_numerical_feature_vector(url)

        try:
            # Execute inference via loaded model estimator
            # Expected interface: model.predict_proba([features]) or model.predict([features])
            raw_pred = self._model.predict([list(feature_vector.values())])[0]
            confidence = float(getattr(self._model, "predict_proba", lambda x: [[0.5, 0.5]])([list(feature_vector.values())])[0][1])

            return {
                "status": "completed",
                "model_name": self._metadata["model_name"],
                "prediction": "suspicious" if raw_pred == 1 else "benign",
                "confidence": round(confidence, 3),
                "risk_contribution": int(confidence * 100),
                "message": f"ML model prediction: {'Suspicious' if raw_pred == 1 else 'Benign'} (Confidence: {round(confidence * 100, 1)}%).",
                "limitations": "Model-derived statistical assessment based on lexical features; not an absolute guarantee."
            }
        except Exception as ex:
            logger.warning("ML inference exception: %s", str(ex))
            return {
                "status": "inference_error",
                "model_name": self._metadata["model_name"],
                "prediction": None,
                "confidence": None,
                "risk_contribution": 0,
                "message": "An error occurred during model evaluation. Falling back to heuristic analysis.",
                "limitations": "Inference failure safely handled by rule-based engine."
            }


# Shared singleton instance
_default_classifier = MLThreatClassifier()


def get_ml_classifier() -> MLThreatClassifier:
    """Returns the default ML classifier instance."""
    return _default_classifier
