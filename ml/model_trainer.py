"""Train and persist offline Scikit-learn ensemble models."""

from __future__ import annotations

import logging
from pathlib import Path
import pickle
from typing import Any, Dict, List, Optional

import numpy as np
from sklearn.cluster import KMeans
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.model_selection import cross_val_score
from sklearn.preprocessing import LabelEncoder, StandardScaler

from ml.feature_engineer import FeatureEngineer

logger = logging.getLogger(__name__)


class ModelTrainer:
    """Train Isolation Forest, Random Forest, Gradient Boosting, and KMeans."""

    MODELS_DIR = Path(__file__).resolve().parent / "models"
    MODEL_PATHS = {
        "isolation_forest": MODELS_DIR / "isolation_forest.pkl",
        "random_forest": MODELS_DIR / "random_forest.pkl",
        "gradient_boost": MODELS_DIR / "gradient_boost.pkl",
        "kmeans": MODELS_DIR / "kmeans.pkl",
        "scaler": MODELS_DIR / "scaler.pkl",
        "label_encoder": MODELS_DIR / "label_encoder.pkl",
        "metadata": MODELS_DIR / "metadata.pkl",
    }
    ATTACK_LABELS = [
        "NORMAL",
        "DATA_EXFILTRATION",
        "EVIDENCE_TAMPERING",
        "SUSPICIOUS_NETWORK",
        "MALICIOUS_PROCESS",
        "ANOMALOUS_ACTIVITY",
    ]

    def __init__(self) -> None:
        """Initialize trainer and ensure model directory exists."""
        try:
            self.MODELS_DIR.mkdir(parents=True, exist_ok=True)
            self.feature_engineer = FeatureEngineer()
        except Exception:
            logger.exception("Failed initializing ModelTrainer")
            raise

    def _auto_label_attack_types(
        self, df: Any, if_predictions: np.ndarray
    ) -> List[str]:
        """Generate weak-supervision labels from feature conditions."""
        labels: List[str] = []
        try:
            for i, row in df.iterrows():
                if int(if_predictions[i]) == 1:
                    labels.append("NORMAL")
                elif float(row.get("has_suspicious_url", 0.0)) == 1.0:
                    labels.append("DATA_EXFILTRATION")
                elif (
                    float(row.get("is_antiforensic", 0.0)) == 1.0
                    or float(row.get("risk_weight", 0.0)) >= 0.9
                ):
                    labels.append("EVIDENCE_TAMPERING")
                elif (
                    float(row.get("is_network_conn", 0.0)) == 1.0
                    and float(row.get("is_public_ip", 0.0)) == 1.0
                ):
                    labels.append("SUSPICIOUS_NETWORK")
                elif (
                    float(row.get("is_process_artifact", 0.0)) == 1.0
                    and float(row.get("is_high_risk", 0.0)) == 1.0
                ):
                    labels.append("MALICIOUS_PROCESS")
                else:
                    labels.append("ANOMALOUS_ACTIVITY")
            return labels
        except Exception:
            logger.exception("Failed auto-labeling attack types")
            return ["NORMAL"] * len(df)

    def train(self, artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run complete training pipeline and persist all model objects."""
        try:
            X_df, artifact_ids = self.feature_engineer.artifacts_to_matrix(artifacts)
            n_samples = len(X_df)
            if n_samples == 0:
                metadata = {
                    "status": "no_data",
                    "n_samples": 0,
                    "n_features": 0,
                    "artifact_ids": [],
                }
                with self.MODEL_PATHS["metadata"].open("wb") as fh:
                    pickle.dump(metadata, fh)
                return metadata

            if n_samples > 4000:
                sampled = X_df.sample(n=4000, random_state=42)
                sampled_ids = list(sampled.index)
                X_df = sampled.reset_index(drop=True)
                artifact_ids = [
                    artifact_ids[idx]
                    for idx in sampled_ids
                    if idx < len(artifact_ids)
                ]
                n_samples = len(X_df)

            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X_df.values)

            isolation_forest = IsolationForest(
                contamination=0.05,
                n_estimators=200,
                random_state=42,
                n_jobs=-1,
            )
            isolation_forest.fit(X_scaled)
            if_predictions = isolation_forest.predict(X_scaled)

            y_labels = self._auto_label_attack_types(X_df, if_predictions)
            label_encoder = LabelEncoder()
            y_encoded = label_encoder.fit_transform(y_labels)

            random_forest = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            )
            random_forest.fit(X_scaled, y_encoded)

            cv_folds = 5 if n_samples <= 1500 else 3
            cv_folds = min(cv_folds, max(2, n_samples))
            if len(np.unique(y_encoded)) > 1 and n_samples >= 2:
                cv_scores = cross_val_score(
                    random_forest, X_scaled, y_encoded, cv=cv_folds, scoring="accuracy"
                )
                cv_mean = float(np.mean(cv_scores))
            else:
                cv_mean = 1.0

            y_binary = (if_predictions == -1).astype(int)
            if len(np.unique(y_binary)) < 2:
                y_binary = np.where(np.arange(n_samples) % 2 == 0, 0, 1)

            gradient_boost = GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.05,
                max_depth=4,
                subsample=0.8,
                random_state=42,
            )
            gradient_boost.fit(X_scaled, y_binary)

            k_clusters = min(8, (n_samples // 10) + 1)
            k_clusters = max(1, min(k_clusters, n_samples))
            kmeans = KMeans(
                n_clusters=k_clusters,
                n_init=20,
                max_iter=500,
                random_state=42,
            )
            kmeans.fit(X_scaled)

            metadata = {
                "status": "trained",
                "n_samples": int(n_samples),
                "n_features": int(X_df.shape[1]),
                "cv_accuracy_mean": round(cv_mean, 4),
                "label_distribution": {
                    label: int(y_labels.count(label)) for label in set(y_labels)
                },
                "kmeans_clusters": int(k_clusters),
                "trained_feature_names": list(X_df.columns),
                "artifact_ids_trained": artifact_ids[:1000],
            }

            to_save = {
                "isolation_forest": isolation_forest,
                "random_forest": random_forest,
                "gradient_boost": gradient_boost,
                "kmeans": kmeans,
                "scaler": scaler,
                "label_encoder": label_encoder,
                "metadata": metadata,
            }
            for name, obj in to_save.items():
                with self.MODEL_PATHS[name].open("wb") as fh:
                    pickle.dump(obj, fh)
            return metadata
        except Exception:
            logger.exception("Training pipeline failed")
            return {"status": "error", "message": "Training failed"}

    @staticmethod
    def models_exist() -> bool:
        """Check whether all required serialized model files exist."""
        try:
            return all(path.exists() for path in ModelTrainer.MODEL_PATHS.values())
        except Exception:
            logger.exception("Failed checking model files")
            return False

    @staticmethod
    def get_training_metadata() -> Optional[Dict[str, Any]]:
        """Load saved training metadata if available."""
        try:
            path = ModelTrainer.MODEL_PATHS["metadata"]
            if not path.exists():
                return None
            with path.open("rb") as fh:
                return pickle.load(fh)
        except Exception:
            logger.exception("Failed loading training metadata")
            return None


if __name__ == "__main__":
    trainer = ModelTrainer()
    logger.info("Model files present: %s", trainer.models_exist())

