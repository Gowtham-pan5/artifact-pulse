"""Explainable ML outputs for Artifact-Pulse anomaly predictions."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class Explainer:
    """Generate local and global explanations from model predictions."""

    FEATURE_EXPLANATIONS = {
        "hour": "Hour of event occurrence in 24-hour format.",
        "minute": "Minute bucket for fine-grained temporal activity.",
        "day_of_week": "Day index showing weekday/weekend behavior.",
        "is_after_hours": "Event occurred outside standard office hours.",
        "is_weekend": "Event occurred during weekend timeframe.",
        "is_antiforensic": "Artifact belongs to anti-forensic source layer.",
        "risk_weight": "Base risk assigned during extraction stage.",
        "is_high_risk": "Flag for high-risk artifacts (>= 0.7).",
        "is_browser_history": "Browser history evidence indicator.",
        "is_network_conn": "Network connection artifact indicator.",
        "is_process_artifact": "Process snapshot artifact indicator.",
        "has_suspicious_url": "Content references known suspicious destinations.",
        "has_suspicious_ext": "Path uses suspicious executable/archive extensions.",
        "has_credential_pattern": "Content contains credential-related keywords.",
        "has_ip_address": "Content contains IPv4 address patterns.",
        "is_public_ip": "Detected public IP outside private RFC1918 ranges.",
        "risk_x_afterhours": "Risk amplified by after-hours activity.",
        "source_path_depth": "Depth of source path indicating obfuscation potential.",
    }

    def __init__(
        self, rf_model: Optional[Any] = None, feature_names: Optional[List[str]] = None
    ) -> None:
        """Initialize explainer with Random Forest and feature names."""
        try:
            self.rf_model = rf_model
            self.feature_names = feature_names or []
        except Exception:
            logger.exception("Failed initializing Explainer")
            raise

    def explain_artifact(
        self,
        artifact: Dict[str, Any],
        prediction: Dict[str, Any],
        features: Dict[str, float],
        top_n: int = 5,
    ) -> Dict[str, Any]:
        """Build human-readable explanation for one prediction."""
        try:
            importances = self._get_feature_importances(features)
            top_features = importances[:top_n]
            reasons = self._derive_reasons(features, prediction)
            attack_type = str(prediction.get("attack_type", "ANOMALOUS_ACTIVITY"))
            summary = self._build_summary(artifact, prediction, reasons, attack_type)
            return {
                "artifact_id": str(artifact.get("artifact_id", "UNKNOWN")),
                "attack_type": attack_type,
                "severity": str(prediction.get("severity", "LOW")),
                "combined_risk": float(prediction.get("combined_risk", 0.0)),
                "summary": summary,
                "reasons": reasons,
                "feature_contributions": top_features,
                "is_anomaly": bool(prediction.get("is_anomaly", False)),
                "attack_confidence": float(prediction.get("attack_confidence", 0.0)),
            }
        except Exception:
            logger.exception("Failed explaining artifact")
            return {
                "artifact_id": str(artifact.get("artifact_id", "UNKNOWN")),
                "attack_type": "ANOMALOUS_ACTIVITY",
                "severity": "LOW",
                "combined_risk": 0.0,
                "summary": "Unable to generate explanation due to processing error.",
                "reasons": [],
                "feature_contributions": [],
                "is_anomaly": False,
                "attack_confidence": 0.0,
            }

    def explain_all_anomalies(
        self,
        artifacts: List[Dict[str, Any]],
        predictions: List[Dict[str, Any]],
        features_list: List[Dict[str, float]],
    ) -> List[Dict[str, Any]]:
        """Explain only anomalous predictions sorted by risk descending."""
        try:
            explanations: List[Dict[str, Any]] = []
            for artifact, prediction, features in zip(
                artifacts, predictions, features_list
            ):
                if prediction.get("is_anomaly"):
                    explanations.append(
                        self.explain_artifact(artifact, prediction, features)
                    )
            return sorted(
                explanations,
                key=lambda item: float(item.get("combined_risk", 0.0)),
                reverse=True,
            )
        except Exception:
            logger.exception("Failed explaining anomalies")
            return []

    def get_global_feature_importance(self) -> List[Dict[str, Any]]:
        """Return top 15 global Random Forest feature importance entries."""
        try:
            if self.rf_model is None or not hasattr(self.rf_model, "feature_importances_"):
                return []
            importances = list(self.rf_model.feature_importances_)
            names = self.feature_names or [f"f_{idx}" for idx in range(len(importances))]
            merged = []
            for name, score in zip(names, importances):
                merged.append(
                    {
                        "feature": name,
                        "importance": round(float(score), 6),
                        "explanation": self.FEATURE_EXPLANATIONS.get(
                            name, "Model-derived feature importance signal."
                        ),
                    }
                )
            merged.sort(key=lambda item: item["importance"], reverse=True)
            return merged[:15]
        except Exception:
            logger.exception("Failed getting global feature importances")
            return []

    def _get_feature_importances(self, features: Dict[str, float]) -> List[Dict[str, Any]]:
        """Build sorted local contribution list using global RF importances."""
        try:
            if self.rf_model is None or not hasattr(self.rf_model, "feature_importances_"):
                return []
            importances = self.rf_model.feature_importances_
            names = self.feature_names or list(features.keys())
            rows: List[Dict[str, Any]] = []
            for idx, name in enumerate(names):
                weight = float(importances[idx]) * float(abs(features.get(name, 0.0)))
                rows.append(
                    {
                        "feature": name,
                        "weight": round(weight, 6),
                        "explanation": self.FEATURE_EXPLANATIONS.get(
                            name, "Model feature supporting this decision."
                        ),
                    }
                )
            rows.sort(key=lambda item: item["weight"], reverse=True)
            return rows
        except Exception:
            logger.exception("Failed deriving local contributions")
            return []

    def _derive_reasons(
        self, features: Dict[str, float], prediction: Dict[str, Any]
    ) -> List[str]:
        """Generate heuristic human-readable reasons for suspiciousness."""
        try:
            reasons: List[str] = []
            if features.get("has_suspicious_url", 0.0) == 1.0:
                reasons.append("Content references suspicious data transfer or onion domains.")
            if features.get("is_antiforensic", 0.0) == 1.0:
                reasons.append("Artifact is from anti-forensic layer, indicating potential cover-up.")
            if features.get("has_credential_pattern", 0.0) == 1.0:
                reasons.append("Credential-related keywords are present in the artifact content.")
            if features.get("is_public_ip", 0.0) == 1.0:
                reasons.append("Public IP exposure detected in content, suggesting external communication.")
            if features.get("risk_x_afterhours", 0.0) > 0.5:
                reasons.append("High-risk behavior occurred during after-hours window.")
            if features.get("is_high_risk", 0.0) == 1.0:
                reasons.append("Source extraction stage already marked this artifact as high risk.")
            if not reasons and prediction.get("is_anomaly"):
                reasons.append("Ensemble model consensus marked this artifact as statistically anomalous.")
            return reasons[:8]
        except Exception:
            logger.exception("Failed deriving textual reasons")
            return ["Unable to derive reasons from current feature set."]

    def _build_summary(
        self,
        artifact: Dict[str, Any],
        prediction: Dict[str, Any],
        reasons: List[str],
        attack_type: str,
    ) -> str:
        """Create attack-type-specific plain English summary paragraph."""
        try:
            aid = str(artifact.get("artifact_id", "UNKNOWN"))
            sev = str(prediction.get("severity", "LOW"))
            risk = round(float(prediction.get("combined_risk", 0.0)) * 100, 2)
            top_reason = reasons[0] if reasons else "No direct indicator was extracted."
            return (
                f"Artifact {aid} is classified as {attack_type} with {sev} severity "
                f"at a combined risk score of {risk}/100. Primary indicator: {top_reason}"
            )
        except Exception:
            logger.exception("Failed building summary")
            return "Explanation summary unavailable due to processing error."


if __name__ == "__main__":
    explainer = Explainer()
    logger.info("Feature explanation entries: %s", len(explainer.FEATURE_EXPLANATIONS))

