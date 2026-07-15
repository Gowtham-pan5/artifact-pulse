"""Inference pipeline for the Artifact-Pulse Scikit-learn ensemble."""

from __future__ import annotations

import logging
from pathlib import Path
import pickle
from typing import Any, Dict, List

import numpy as np

from ml.feature_engineer import FeatureEngineer
from ml.model_trainer import ModelTrainer

logger = logging.getLogger(__name__)


class ModelPredictor:
    """Load trained models and produce per-artifact and aggregate predictions."""

    def __init__(self) -> None:
        """Initialize predictor state and feature engineer."""
        try:
            self.feature_engineer = FeatureEngineer()
            self.models: Dict[str, Any] = {}
        except Exception:
            logger.exception("Failed initializing ModelPredictor")
            raise

    def load_models(self) -> bool:
        """Load all persisted model objects from disk."""
        try:
            for name, path in ModelTrainer.MODEL_PATHS.items():
                if not Path(path).exists():
                    return False
                with Path(path).open("rb") as fh:
                    self.models[name] = pickle.load(fh)
            return True
        except Exception:
            logger.exception("Failed loading serialized models")
            return False

    def predict_artifact(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        """Run full ensemble inference for one artifact."""
        try:
            if not self.models:
                return self._safe_prediction(artifact, "models_not_loaded")

            feat = self.feature_engineer.artifact_to_features(artifact)
            feature_names = self.models["metadata"].get("trained_feature_names", [])
            vec = np.array([[feat.get(k, 0.0) for k in feature_names]], dtype=float)
            scaler = self.models["scaler"]
            X_scaled = scaler.transform(vec)

            if_model = self.models["isolation_forest"]
            if_pred = int(if_model.predict(X_scaled)[0])
            if_score_raw = float(if_model.decision_function(X_scaled)[0])
            if_score = float(np.clip(1.0 / (1.0 + np.exp(if_score_raw)), 0.0, 1.0))
            is_anomaly = if_pred == -1

            rf = self.models["random_forest"]
            rf_probs = rf.predict_proba(X_scaled)[0]
            best_idx = int(np.argmax(rf_probs))
            attack_confidence = float(rf_probs[best_idx])
            label_encoder = self.models["label_encoder"]
            attack_type = str(label_encoder.inverse_transform([best_idx])[0])

            gb = self.models["gradient_boost"]
            gb_probs = gb.predict_proba(X_scaled)[0]
            gb_risk_score = float(gb_probs[1]) if len(gb_probs) > 1 else float(gb_probs[0])

            kmeans = self.models["kmeans"]
            behavioral_cluster = int(kmeans.predict(X_scaled)[0])

            raw_risk = float(artifact.get("risk_weight", 0.0) or 0.0)
            combined = (if_score * 0.40) + (gb_risk_score * 0.35) + (raw_risk * 0.25)
            combined = float(np.clip(combined, 0.0, 1.0))
            severity = self._severity(combined)

            return {
                "artifact_id": str(artifact.get("artifact_id", "UNKNOWN")),
                "is_anomaly": bool(is_anomaly),
                "anomaly_score": round(if_score, 4),
                "attack_type": attack_type,
                "attack_confidence": round(attack_confidence, 4),
                "gb_risk_score": round(gb_risk_score, 4),
                "behavioral_cluster": behavioral_cluster,
                "combined_risk": round(combined, 4),
                "severity": severity,
            }
        except Exception:
            logger.exception("Failed predicting artifact")
            return self._safe_prediction(artifact, "prediction_error")

    def predict_all(self, artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run ensemble inference on all artifacts and aggregate summary metrics."""
        try:
            if not artifacts:
                return {
                    "total_artifacts": 0,
                    "total_anomalies": 0,
                    "anomaly_rate": 0.0,
                    "final_suspicion_score": 0.0,
                    "severity": "LOW",
                    "mean_risk_score": 0.0,
                    "max_risk_score": 0.0,
                    "attack_type_breakdown": {},
                    "top_anomalies": [],
                    "prediction_errors": 0,
                    "predictions": [],
                }

            if len(artifacts) > 8000:
                artifacts_eval = artifacts[:8000]
            else:
                artifacts_eval = artifacts

            predictions: List[Dict[str, Any]] = []
            errors = 0
            for artifact in artifacts_eval:
                p = self.predict_artifact(artifact)
                if p.get("error"):
                    errors += 1
                predictions.append(p)

            risks = [float(p.get("combined_risk", 0.0)) for p in predictions]
            anomalies = [p for p in predictions if p.get("is_anomaly")]
            attack_breakdown: Dict[str, int] = {}
            for p in predictions:
                key = str(p.get("attack_type", "UNKNOWN"))
                attack_breakdown[key] = attack_breakdown.get(key, 0) + 1

            mean_risk = float(np.mean(risks)) if risks else 0.0
            max_risk = float(np.max(risks)) if risks else 0.0
            anomaly_rate = float(len(anomalies) / max(1, len(predictions)))
            final_score = float(np.clip((mean_risk * 65 + anomaly_rate * 35) * 100, 0, 100))
            severity = self._severity(final_score / 100.0)
            top_anomalies = sorted(predictions, key=lambda x: x.get("combined_risk", 0.0), reverse=True)[:20]

            return {
                "total_artifacts": len(predictions),
                "total_anomalies": len(anomalies),
                "anomaly_rate": round(anomaly_rate, 4),
                "final_suspicion_score": round(final_score, 2),
                "severity": severity,
                "mean_risk_score": round(mean_risk, 4),
                "max_risk_score": round(max_risk, 4),
                "attack_type_breakdown": attack_breakdown,
                "top_anomalies": top_anomalies,
                "prediction_errors": errors,
                "predictions": predictions,
                "artifacts_processed": len(artifacts_eval),
                "artifacts_received": len(artifacts),
            }
        except Exception:
            logger.exception("Failed aggregate prediction")
            return {
                "total_artifacts": 0,
                "total_anomalies": 0,
                "anomaly_rate": 0.0,
                "final_suspicion_score": 0.0,
                "severity": "LOW",
                "mean_risk_score": 0.0,
                "max_risk_score": 0.0,
                "attack_type_breakdown": {},
                "top_anomalies": [],
                "prediction_errors": len(artifacts),
                "predictions": [],
            }

    def _severity(self, score01: float) -> str:
        """Map normalized risk score to severity label."""
        try:
            if score01 >= 0.8:
                return "CRITICAL"
            if score01 >= 0.6:
                return "HIGH"
            if score01 >= 0.4:
                return "MEDIUM"
            return "LOW"
        except Exception:
            logger.exception("Failed severity mapping")
            return "LOW"

    def _safe_prediction(self, artifact: Dict[str, Any], reason: str) -> Dict[str, Any]:
        """Create safe fallback prediction payload for failure cases."""
        try:
            return {
                "artifact_id": str(artifact.get("artifact_id", "UNKNOWN")),
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "attack_type": "NORMAL",
                "attack_confidence": 0.0,
                "gb_risk_score": 0.0,
                "behavioral_cluster": -1,
                "combined_risk": 0.0,
                "severity": "LOW",
                "error": reason,
            }
        except Exception:
            logger.exception("Failed generating safe prediction")
            return {}


if __name__ == "__main__":
    predictor = ModelPredictor()
    logger.info("Models loaded: %s", predictor.load_models())

