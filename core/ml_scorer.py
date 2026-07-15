"""Scikit-learn ensemble scoring module for Artifact-Pulse."""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from database.db_manager import DBManager
from ml.explainer import Explainer
from ml.feature_engineer import FeatureEngineer
from ml.model_predictor import ModelPredictor
from ml.model_trainer import ModelTrainer

logger = logging.getLogger(__name__)


class MLScorer:
    """Train, predict, and explain anomaly signals using offline sklearn models."""

    def __init__(self, db: DBManager, clusters: List[Dict[str, Any]]) -> None:
        """Initialize scorer with DB and correlation clusters."""
        try:
            self.db = db
            self.clusters = clusters
        except Exception:
            logger.exception("Failed to initialize MLScorer")
            raise

    def run_all(self) -> Dict[str, Any]:
        """Execute full ML lifecycle and return comprehensive scoring payload."""
        try:
            artifacts = self.db.get_all_artifacts()
            if len(artifacts) > 8000:
                artifacts_for_ml = artifacts[:8000]
            else:
                artifacts_for_ml = artifacts
            trainer = ModelTrainer()
            training_metadata = trainer.train(artifacts_for_ml)

            predictor = ModelPredictor()
            if not predictor.load_models():
                return self._safe_result(
                    "Model loading failed after training",
                    training_metadata=training_metadata,
                )
            prediction_result = predictor.predict_all(artifacts_for_ml)

            fe = FeatureEngineer()
            feature_matrix, _ = fe.artifacts_to_matrix(artifacts_for_ml)
            feature_rows = feature_matrix.to_dict(orient="records")

            rf_model = predictor.models.get("random_forest")
            trained_features = predictor.models.get("metadata", {}).get(
                "trained_feature_names", list(feature_matrix.columns)
            )
            explainer = Explainer(rf_model=rf_model, feature_names=trained_features)
            all_predictions = prediction_result.get("predictions", [])
            anomaly_candidates = sorted(
                [p for p in all_predictions if p.get("is_anomaly")],
                key=lambda item: float(item.get("combined_risk", 0.0)),
                reverse=True,
            )[:200]
            indexed_artifacts = {
                str(a.get("artifact_id", "UNKNOWN")): a for a in artifacts_for_ml
            }
            indexed_features = {
                str(a.get("artifact_id", "UNKNOWN")): f
                for a, f in zip(artifacts_for_ml, feature_rows)
            }
            anomaly_explanations: List[Dict[str, Any]] = []
            for pred in anomaly_candidates:
                aid = str(pred.get("artifact_id", "UNKNOWN"))
                artifact = indexed_artifacts.get(aid, {"artifact_id": aid})
                feat = indexed_features.get(aid, {})
                anomaly_explanations.append(
                    explainer.explain_artifact(artifact, pred, feat)
                )
            global_importance = explainer.get_global_feature_importance()

            keywords = int(sum(1 for f in feature_rows if f.get("has_suspicious_url", 0.0) > 0))
            top_anomalies = prediction_result.get("top_anomalies", [])[:10]
            final_score = float(prediction_result.get("final_suspicion_score", 0.0))
            severity = str(prediction_result.get("severity", "LOW"))
            anomaly_rate = float(prediction_result.get("anomaly_rate", 0.0))
            total_anomalies = int(prediction_result.get("total_anomalies", 0))
            isolation_forest_score = float(prediction_result.get("mean_risk_score", 0.0) * 100.0)

            top_cluster_score = (
                float(self.clusters[0].get("suspicion_score", 0.0))
                if self.clusters
                else 0.0
            )
            final_score = round(min(100.0, (final_score * 0.75) + (top_cluster_score * 0.25)), 2)

            return {
                "final_suspicion_score": final_score,
                "severity": severity,
                "anomaly_rate": round(anomaly_rate, 4),
                "total_anomalies": total_anomalies,
                "isolation_forest_score": round(isolation_forest_score, 2),
                "keyword_hits": keywords,
                "attack_type_breakdown": prediction_result.get("attack_type_breakdown", {}),
                "top_anomaly_explanations": anomaly_explanations[:10],
                "global_feature_importance": global_importance[:15],
                "training_metadata": training_metadata,
                "top_anomalies": top_anomalies,
                "ml_artifacts_processed": len(artifacts_for_ml),
                "total_artifacts_available": len(artifacts),
            }
        except Exception:
            logger.exception("ML run_all failed")
            return self._safe_result("ML scoring pipeline failed")

    def _safe_result(
        self, message: str, training_metadata: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """Return safe default payload for frontend/report consumers."""
        try:
            return {
                "final_suspicion_score": 0.0,
                "severity": "LOW",
                "anomaly_rate": 0.0,
                "total_anomalies": 0,
                "isolation_forest_score": 0.0,
                "keyword_hits": 0,
                "attack_type_breakdown": {},
                "top_anomaly_explanations": [],
                "global_feature_importance": [],
                "training_metadata": training_metadata or {"status": "error", "message": message},
                "top_anomalies": [],
            }
        except Exception:
            logger.exception("Failed generating ML safe result")
            return {}

    def run_isolation_forest(self) -> float:
        """Run isolation forest helper (for tests)."""
        try:
            res = self.run_all()
            return float(res.get("isolation_forest_score", 0.0) / 100.0)
        except Exception:
            logger.exception("Failed run_isolation_forest")
            return 0.0

    def compute_final_score(
        self, raw_risk: float, n_events: int, anomaly_score: float
    ) -> Dict[str, Any]:
        """Compute final score and map to severity label (for tests)."""
        try:
            score = (anomaly_score * 0.5) + (raw_risk * 0.5)
            if score >= 0.8:
                severity = "CRITICAL"
            elif score >= 0.6:
                severity = "HIGH"
            elif score >= 0.4:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            return {"score": score, "severity": severity}
        except Exception:
            logger.exception("Failed compute_final_score")
            return {"score": 0.0, "severity": "LOW"}
