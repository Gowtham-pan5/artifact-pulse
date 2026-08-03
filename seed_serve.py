"""Seed the Flask API's in-memory state from the evidence store and serve.

The full extraction pipeline (extractors -> ML scoring -> evidence sealing) can
take 30+ minutes; the ML explanation step in particular iterates over every
anomaly candidate and its outputs are not consumed by the current web UI.
All data the UI *does* consume (artifacts, clusters, anti-forensic events,
chain verification) is already persisted in output/artifact_pulse.db, so this
launcher loads that store directly into the API's global_state and serves it.

Run with:  PYTHONPATH= ./.venv/Scripts/python.exe seed_serve.py
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.db_manager import DBManager  # noqa: E402
from web.app import app, global_state, state_lock  # noqa: E402


def severity_from_risk(risk: float) -> str:
    if risk >= 0.9:
        return "critical"
    if risk >= 0.7:
        return "high"
    if risk >= 0.4:
        return "medium"
    return "low"


def enrich_artifact(row: dict) -> dict:
    """Map raw artifacts row to the frontend BackendArtifact contract."""
    return {
        "id": row["artifact_id"],
        "timestamp": row["event_time"],
        "source_layer": row["source_layer"],
        "source": row["source_path"],
        "description": row["content"],
        "severity": severity_from_risk(float(row["risk_weight"] or 0)),
        "content_hash": row["content_hash"],
        "chain_hash": row["chain_hash"],
        "risk_weight": row["risk_weight"],
    }


def enrich_cluster(row: dict) -> dict:
    """Map raw clusters row to the frontend BackendCluster contract."""
    raw_layers = str(row["layers_involved"] or "").split(",")
    layers = [layer for layer in raw_layers if layer]
    return {
        "id": row["cluster_id"],
        "window_start": row["window_start"],
        "window_end": row["window_end"],
        "artifact_count": int(row["event_count"] or 0),
        "layer_diversity": len(layers),
        "suspicion_score": float(row["suspicion_score"] or 0),
        "pattern": row["attack_type"] or "Anomalous Endpoint Activity",
        "layers": layers,
    }


def enrich_antiforensic(row: dict) -> dict:
    """Map raw antiforensic row to the API contract."""
    return {
        "id": str(row["id"]),
        "timestamp": row["event_time"],
        "technique": row["event_type"],
        "evidence": row["evidence"],
        "severity": row["severity"],
    }


def main() -> None:
    with DBManager() as db:
        rows = db.get_all_artifacts()
        artifacts = [enrich_artifact(dict(r)) for r in rows]

        # clusters table has no DBManager getter; read directly
        cluster_rows = db._conn.execute(
            "SELECT * FROM clusters ORDER BY id ASC"
        ).fetchall()
        clusters = [enrich_cluster(dict(r)) for r in cluster_rows]

        af_rows = db.get_antiforensic_events()
        antiforensic = [enrich_antiforensic(dict(r)) for r in af_rows]

        integrity, message = db.verify_chain_integrity()
        master_hash = db.compute_master_hash()

    with state_lock:
        global_state.update(
            {
                "running": False,
                "progress": 100,
                "stage": "completed",
                "message": (
                    f"Loaded {len(artifacts)} artifacts, {len(clusters)} "
                    f"clusters, {len(antiforensic)} anti-forensic events "
                    "from evidence store"
                ),
                "error": None,
                "ml_scores": {},
                "report_path": None,
                "artifacts": artifacts,
                "clusters": clusters,
                "antiforensic": antiforensic,
                "seal": {
                    "chain_integrity": integrity,
                    "master_hash": master_hash,
                    "message": message,
                    "status": "INTACT" if integrity else "TAMPERED",
                },
            }
        )

    print(
        f"[seed] artifacts={len(artifacts)} clusters={len(clusters)} "
        f"antiforensic={len(antiforensic)} chain_integrity={integrity}"
    )
    app.run(debug=False, host="127.0.0.1", port=5000)


if __name__ == "__main__":
    main()
