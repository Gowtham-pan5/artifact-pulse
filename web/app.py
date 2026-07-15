"""Flask web API and dashboard for Artifact-Pulse."""

from __future__ import annotations

from datetime import UTC, datetime
import logging
from pathlib import Path
import sys
import threading
from typing import Any, Dict

from flask import Flask, jsonify, render_template, request, send_file
from flask_cors import CORS

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import CASE_ID, TOOL_VERSION
from core.antiforensic_detector import AntiForensicDetector
from core.correlation_engine import CorrelationEngine
from core.eventlog_extractor import EventLogExtractor
from core.evidence_sealer import EvidenceSealer
from core.filesystem_extractor import FilesystemExtractor
from core.ml_scorer import MLScorer
from core.process_extractor import ProcessExtractor
from database.db_manager import DBManager
from report.pdf_generator import PDFGenerator

logger = logging.getLogger(__name__)
app = Flask(__name__)
CORS(app)

global_state: Dict[str, Any] = {
    "running": False,
    "progress": 0,
    "stage": "idle",
    "message": "Waiting",
    "started_at": None,
    "error": None,
    "ml_scores": {},
    "report_path": None,
    "artifacts": [],
    "clusters": [],
    "antiforensic": [],
    "seal": {},
}
state_lock = threading.Lock()


def _run_pipeline() -> None:
    """Run extraction pipeline in background thread safely."""
    try:
        with DBManager() as db:
            with state_lock:
                global_state["stage"] = "filesystem"
                global_state["progress"] = 10
                global_state["message"] = "Extracting filesystem artifacts..."
            FilesystemExtractor(db).run_all()

            with state_lock:
                global_state["stage"] = "eventlogs"
                global_state["progress"] = 30
                global_state["message"] = "Parsing Windows Event Logs..."
            EventLogExtractor(db).run_all()

            with state_lock:
                global_state["stage"] = "process"
                global_state["progress"] = 50
                global_state["message"] = "Capturing live process snapshot..."
            ProcessExtractor(db).run_all()

            with state_lock:
                global_state["stage"] = "antiforensic"
                global_state["progress"] = 65
                global_state["message"] = "Running anti-forensic detection..."
            AntiForensicDetector(db).run_all()

            with state_lock:
                global_state["stage"] = "correlation"
                global_state["progress"] = 78
                global_state["message"] = "Cross-layer correlation engine..."
            corr = CorrelationEngine(db)
            clusters = corr.run_all()

            with state_lock:
                global_state["stage"] = "ml_train"
                global_state["progress"] = 90
                global_state["message"] = (
                    "Training Scikit-learn models (IF + RF + GB + KMeans)..."
                )
            with state_lock:
                global_state["stage"] = "ml_predict"
                global_state["progress"] = 93
                global_state["message"] = "Running ensemble predictions on all artifacts..."
            with state_lock:
                global_state["stage"] = "ml_explain"
                global_state["progress"] = 95
                global_state["message"] = "Generating ML explanations for anomalies..."
            ml = MLScorer(db, clusters).run_all()

            with state_lock:
                global_state["stage"] = "seal"
                global_state["progress"] = 97
                global_state["message"] = "Sealing evidence chain..."
            seal = EvidenceSealer(db).seal()
            with state_lock:
                global_state["artifacts"] = db.get_all_artifacts()
                global_state["clusters"] = clusters
                global_state["antiforensic"] = db.get_antiforensic_events()
                global_state["ml_scores"] = ml
                global_state["seal"] = seal
                global_state["progress"] = 100
                global_state["stage"] = "completed"
                global_state["message"] = (
                    f"Extraction complete — {len(global_state['artifacts'])} artifacts"
                )
                global_state["running"] = False
    except Exception as exc:
        logger.exception("Pipeline failed")
        with state_lock:
            global_state["running"] = False
            global_state["error"] = str(exc)
            global_state["stage"] = "error"


@app.get("/")
def index() -> str:
    """Render home dashboard page."""
    try:
        return render_template("index.html")
    except Exception:
        logger.exception("Failed rendering index")
        raise


@app.get("/dashboard")
def dashboard() -> str:
    """Render alternate dashboard page."""
    try:
        return render_template("dashboard.html")
    except Exception:
        logger.exception("Failed rendering dashboard")
        raise


@app.get("/api/health")
def health() -> Any:
    """Return API health status payload."""
    try:
        return jsonify({"status": "ok", "version": TOOL_VERSION, "case_id": CASE_ID})
    except Exception:
        logger.exception("Health endpoint failed")
        raise


@app.post("/api/extraction/start")
def start_extraction() -> Any:
    """Start background extraction if not currently running."""
    try:
        with state_lock:
            if global_state["running"]:
                return jsonify({"error": "already running"}), 409
            global_state.update(
                {
                    "running": True,
                    "progress": 0,
                    "stage": "starting",
                    "message": "Pipeline starting",
                    "started_at": datetime.now(UTC).isoformat(),
                    "error": None,
                }
            )
        threading.Thread(target=_run_pipeline, daemon=True).start()
        return jsonify({"status": "started", "case_id": CASE_ID}), 202
    except Exception:
        logger.exception("Start extraction failed")
        raise


@app.get("/api/extraction/status")
def extraction_status() -> Any:
    """Return extraction execution state for polling clients."""
    try:
        with state_lock:
            return jsonify(
                {
                    "running": global_state["running"],
                    "progress": global_state["progress"],
                    "stage": global_state["stage"],
                    "message": global_state["message"],
                    "started_at": global_state["started_at"],
                    "error": global_state["error"],
                    "ml_scores": global_state["ml_scores"],
                }
            )
    except Exception:
        logger.exception("Status endpoint failed")
        raise


@app.get("/api/artifacts")
def artifacts() -> Any:
    """Return paginated artifact list with optional layer filter."""
    try:
        layer = request.args.get("layer")
        limit = min(int(request.args.get("limit", 100)), 1000)
        offset = int(request.args.get("offset", 0))
        data = global_state["artifacts"]
        if layer and layer != "all":
            data = [a for a in data if a.get("source_layer") == layer]
        return jsonify(data[offset : offset + limit])
    except Exception:
        logger.exception("Artifacts endpoint failed")
        raise


@app.get("/api/antiforensic")
def antiforensic() -> Any:
    """Return anti-forensic findings list."""
    try:
        return jsonify(global_state["antiforensic"])
    except Exception:
        logger.exception("Antiforensic endpoint failed")
        raise


@app.get("/api/clusters")
def clusters() -> Any:
    """Return suspicious clusters list."""
    try:
        return jsonify(global_state["clusters"])
    except Exception:
        logger.exception("Clusters endpoint failed")
        raise


@app.get("/api/stats")
def stats() -> Any:
    """Return aggregate counts across extracted data categories."""
    try:
        artifacts = global_state["artifacts"]
        return jsonify(
            {
                "layer_breakdown": _layer_breakdown(artifacts),
                "total": len(artifacts),
                "af_count": len(global_state["antiforensic"]),
                "high_risk_count": len(
                    [a for a in artifacts if float(a.get("risk_weight") or 0) >= 0.7]
                ),
                "total_artifacts": len(artifacts),
                "antiforensic": len(global_state["antiforensic"]),
                "high_risk": len(
                    [a for a in artifacts if float(a.get("risk_weight") or 0) >= 0.7]
                ),
                "clusters": len(global_state["clusters"]),
            }
        )
    except Exception:
        logger.exception("Stats endpoint failed")
        raise


@app.get("/api/chain/verify")
def chain_verify() -> Any:
    """Run chain verification against DB and return integrity payload."""
    try:
        with DBManager() as db:
            integrity, message = db.verify_chain_integrity()
            master_hash = db.compute_master_hash()
        return jsonify(
            {
                "integrity": integrity,
                "status": "INTACT" if integrity else "TAMPERED",
                "message": message,
                "master_hash": master_hash,
            }
        )
    except Exception:
        logger.exception("Chain verification failed")
        raise


@app.post("/api/report/generate")
def generate_report() -> Any:
    """Generate forensic PDF report from current in-memory state."""
    try:
        pdf = PDFGenerator(
            global_state["artifacts"],
            global_state["clusters"],
            global_state["antiforensic"],
            global_state["ml_scores"],
            global_state["seal"],
        ).generate()
        with state_lock:
            global_state["report_path"] = str(pdf)
        return jsonify({"status": "generated", "path": str(pdf)}), 201
    except Exception:
        logger.exception("Report generation failed")
        raise


@app.get("/api/report/download")
def download_report() -> Any:
    """Download generated PDF report as attachment."""
    try:
        path = global_state.get("report_path")
        if not path:
            return jsonify({"error": "Report not generated"}), 404
        return send_file(path, as_attachment=True)
    except Exception:
        logger.exception("Report download failed")
        raise


@app.get("/api/ml/feature-importance")
def ml_feature_importance() -> Any:
    """Return global feature importance from latest ML scoring run."""
    try:
        return jsonify(global_state.get("ml_scores", {}).get("global_feature_importance", []))
    except Exception:
        logger.exception("ML feature importance endpoint failed")
        raise


@app.get("/api/ml/explanations")
def ml_explanations() -> Any:
    """Return top anomaly explanations from latest ML scoring run."""
    try:
        return jsonify(global_state.get("ml_scores", {}).get("top_anomaly_explanations", []))
    except Exception:
        logger.exception("ML explanations endpoint failed")
        raise


@app.get("/api/ml/attack-breakdown")
def ml_attack_breakdown() -> Any:
    """Return attack-type distribution from latest ML scoring run."""
    try:
        return jsonify(global_state.get("ml_scores", {}).get("attack_type_breakdown", {}))
    except Exception:
        logger.exception("ML attack breakdown endpoint failed")
        raise


@app.get("/api/ml/training-info")
def ml_training_info() -> Any:
    """Return model training metadata from latest ML scoring run."""
    try:
        return jsonify(global_state.get("ml_scores", {}).get("training_metadata", {}))
    except Exception:
        logger.exception("ML training metadata endpoint failed")
        raise


def _layer_breakdown(artifacts: list[dict[str, Any]]) -> dict[str, int]:
    """Compute artifact counts grouped by source layer."""
    try:
        breakdown: dict[str, int] = {}
        for artifact in artifacts:
            layer = str(artifact.get("source_layer", "unknown"))
            breakdown[layer] = breakdown.get(layer, 0) + 1
        return breakdown
    except Exception:
        logger.exception("Failed computing layer breakdown")
        return {}


@app.errorhandler(404)
def not_found(_: Any) -> Any:
    """Handle 404 HTTP errors with JSON payload."""
    try:
        return jsonify({"error": "Not found"}), 404
    except Exception:
        logger.exception("404 handler failed")
        raise


@app.errorhandler(500)
def server_error(_: Any) -> Any:
    """Handle 500 HTTP errors with JSON payload."""
    try:
        return jsonify({"error": "Internal server error"}), 500
    except Exception:
        logger.exception("500 handler failed")
        raise


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
