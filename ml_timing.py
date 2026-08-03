"""Time each ML pipeline phase (train / predict / explain).

Usage:  PYTHONPATH= ./.venv/Scripts/python.exe ml_timing.py
Prints per-phase wall-clock durations so model speed regressions are visible.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.db_manager import DBManager  # noqa: E402
from ml.explainer import Explainer  # noqa: E402
from ml.feature_engineer import FeatureEngineer  # noqa: E402
from ml.model_predictor import ModelPredictor  # noqa: E402
from ml.model_trainer import ModelTrainer  # noqa: E402


def phase(name, fn):
    t0 = time.perf_counter()
    result = fn()
    print(f"[timing] {name:<28} {time.perf_counter() - t0:7.1f}s")
    return result


with DBManager() as db:
    artifacts = db.get_all_artifacts()
    artifacts_for_ml = artifacts[:8000]
    print(f"[timing] artifacts loaded: {len(artifacts)} "
          f"(using {len(artifacts_for_ml)})")

    trainer = ModelTrainer()
    metadata = phase("train", lambda: trainer.train(artifacts_for_ml))
    print(f"[timing]   train status: {metadata.get('status')}, "
          f"samples={metadata.get('n_samples')}")

    predictor = ModelPredictor()
    phase("load_models", lambda: predictor.load_models())

    prediction_result = phase(
        "predict_all", lambda: predictor.predict_all(artifacts_for_ml)
    )
    print(f"[timing]   predictions: "
          f"{len(prediction_result.get('predictions', []))}")

    fe = FeatureEngineer()
    feature_matrix = phase(
        "feature_matrix", lambda: fe.artifacts_to_matrix(artifacts_for_ml)[0]
    )
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
    )[:60]
    indexed_artifacts = {
        str(a.get("artifact_id", "UNKNOWN")): a for a in artifacts_for_ml
    }
    indexed_features = {
        str(a.get("artifact_id", "UNKNOWN")): f
        for a, f in zip(artifacts_for_ml, feature_rows)
    }

    def do_explain():
        out = []
        for pred in anomaly_candidates:
            aid = str(pred.get("artifact_id", "UNKNOWN"))
            out.append(
                explainer.explain_artifact(
                    indexed_artifacts.get(aid, {"artifact_id": aid}),
                    pred,
                    indexed_features.get(aid, {}),
                )
            )
        return out

    explanations = phase(
        f"explain {len(anomaly_candidates)} anomalies", do_explain
    )
    phase("global_importance", explainer.get_global_feature_importance)
    print(f"[timing] explanations: {len(explanations)}")
    print("[timing] DONE — total ML lifecycle OK")
