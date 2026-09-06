"""Flask web API for Artifact-Pulse."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import logging
import os
from pathlib import Path
import sys
import threading
from typing import Any, Dict

from dotenv import load_dotenv
import requests
from flask import Flask, jsonify, render_template, request, send_file, Response
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import CASE_ID, MITRE_TECHNIQUE_MAP, TOOL_VERSION
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

_jwt_secret = os.environ.get("JWT_SECRET_KEY", "")
if not _jwt_secret or _jwt_secret == "change-me-generate-a-random-secret":
    _jwt_secret = "artifact-pulse-local-forensic-triage-secret-2026"

app.config["JWT_SECRET_KEY"] = _jwt_secret
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(
    minutes=int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRES_MINUTES", "1440"))
)
jwt = JWTManager(app)

# ── In-process pipeline state ────────────────────────────────────────────────
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


# ── Auth ─────────────────────────────────────────────────────────────────────
@app.post("/api/auth/token")
def get_token() -> Any:
    """Issue a JWT for the local analyst session (no password in local-only mode)."""
    try:
        token = create_access_token(identity="analyst")
        return jsonify({"access_token": token}), 200
    except Exception:
        logger.exception("Token issuance failed")
        raise


# ── Pipeline ─────────────────────────────────────────────────────────────────
def _run_pipeline() -> None:
    """Run extraction pipeline in background thread."""
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
                global_state["message"] = "Training Scikit-learn models (IF + RF + GB + KMeans)..."
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
                global_state["artifacts"] = [
                    _enrich_artifact(dict(r)) for r in db.get_all_artifacts()
                ]
                global_state["clusters"] = clusters
                global_state["antiforensic"] = [
                    _enrich_antiforensic(dict(r))
                    for r in db.get_antiforensic_events()
                ]
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


# ── Routes ───────────────────────────────────────────────────────────────────

# ── Frontend Reverse Proxy ───────────────────────────────────────────────────
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-encoding",  # requests automatically decodes gzip content
}

proxy_session = requests.Session()
proxy_session.trust_env = False  # Avoid routing local loopback traffic through system/external proxy (e.g. 8080)


def _proxy_to_frontend(path: str = "") -> Any:
    # Do not proxy /api routes
    if path.startswith("api/") or path == "api":
        return jsonify({"error": "Not found"}), 404

    target_url = f"http://127.0.0.1:3000/{path}"
    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in ("host", "content-length")
    }

    try:
        resp = proxy_session.request(
            method=request.method,
            url=target_url,
            params=request.args,
            data=request.get_data(),
            headers=headers,
            allow_redirects=False,
            timeout=10,
        )

        response_headers = [
            (name, value)
            for name, value in resp.headers.items()
            if name.lower() not in HOP_BY_HOP_HEADERS
        ]

        return Response(
            response=resp.content,
            status=resp.status_code,
            headers=response_headers,
            content_type=resp.headers.get("content-type"),
        )
    except Exception as exc:
        logger.warning("Frontend proxy request to %s failed: %s", target_url, exc)
        return jsonify({
            "error": "Frontend SSR server is currently unavailable on port 3000.",
            "detail": str(exc),
        }), 503


@app.get("/api/health")
def health() -> Any:
    """Public health probe — no auth required."""
    try:
        return jsonify({"status": "ok", "version": TOOL_VERSION, "case_id": CASE_ID})
    except Exception:
        logger.exception("Health endpoint failed")
        raise


@app.get("/api/health/detailed")
@jwt_required()
def health_detailed() -> Any:
    """Detailed liveness check including DB and pipeline state."""
    try:
        db_ok = False
        db_artifact_count = 0
        try:
            with DBManager() as db:
                db_ok = True
                db_artifact_count = len(db.get_all_artifacts())
        except Exception:
            logger.warning("DB health check failed")

        with state_lock:
            pipeline_stage = global_state["stage"]
            pipeline_running = global_state["running"]

        return jsonify({
            "status": "ok",
            "version": TOOL_VERSION,
            "case_id": CASE_ID,
            "db": {"connected": db_ok, "artifact_count": db_artifact_count},
            "pipeline": {"stage": pipeline_stage, "running": pipeline_running},
            "timestamp": datetime.now(UTC).isoformat(),
        })
    except Exception:
        logger.exception("Detailed health endpoint failed")
        raise


@app.post("/api/extraction/start")
@jwt_required()
def start_extraction() -> Any:
    try:
        with state_lock:
            if global_state["running"]:
                return jsonify({"error": "already running"}), 409
            global_state.update({
                "running": True,
                "progress": 0,
                "stage": "starting",
                "message": "Pipeline starting",
                "started_at": datetime.now(UTC).isoformat(),
                "error": None,
            })
        threading.Thread(target=_run_pipeline, daemon=True).start()
        return jsonify({"status": "started", "case_id": CASE_ID}), 202
    except Exception:
        logger.exception("Start extraction failed")
        raise


@app.get("/api/extraction/status")
@jwt_required()
def extraction_status() -> Any:
    try:
        with state_lock:
            return jsonify({
                "running": global_state["running"],
                "progress": global_state["progress"],
                "stage": global_state["stage"],
                "message": global_state["message"],
                "started_at": global_state["started_at"],
                "error": global_state["error"],
                "ml_scores": global_state["ml_scores"],
            })
    except Exception:
        logger.exception("Status endpoint failed")
        raise


@app.get("/api/artifacts")
@jwt_required()
def artifacts() -> Any:
    try:
        layer = request.args.get("layer", "")
        try:
            limit = min(int(request.args.get("limit", 100)), 1000)
            offset = max(int(request.args.get("offset", 0)), 0)
        except (ValueError, TypeError):
            return jsonify({"error": "limit and offset must be integers"}), 400

        data = global_state["artifacts"]
        if layer and layer != "all":
            allowed_layers = {"filesystem", "eventlog", "process", "antiforensic", "registry"}
            if layer not in allowed_layers:
                return jsonify({"error": f"unknown layer: {layer}"}), 400
            data = [a for a in data if a.get("source_layer") == layer]
        return jsonify({"artifacts": data[offset: offset + limit], "total": len(data)})
    except Exception:
        logger.exception("Artifacts endpoint failed")
        raise


@app.get("/api/antiforensic")
@jwt_required()
def antiforensic() -> Any:
    try:
        return jsonify({"antiforensic": global_state["antiforensic"]})
    except Exception:
        logger.exception("Antiforensic endpoint failed")
        raise


@app.get("/api/clusters")
@jwt_required()
def clusters() -> Any:
    try:
        return jsonify({"clusters": global_state["clusters"]})
    except Exception:
        logger.exception("Clusters endpoint failed")
        raise


@app.get("/api/stats")
@jwt_required()
def stats() -> Any:
    try:
        art = global_state["artifacts"]
        return jsonify({
            "layer_breakdown": _layer_breakdown(art),
            "total_artifacts": len(art),
            "af_count": len(global_state["antiforensic"]),
            "high_risk_count": len([a for a in art if float(a.get("risk_weight") or 0) >= 0.7]),
            "antiforensic": len(global_state["antiforensic"]),
            "high_risk": len([a for a in art if float(a.get("risk_weight") or 0) >= 0.7]),
            "clusters": len(global_state["clusters"]),
        })
    except Exception:
        logger.exception("Stats endpoint failed")
        raise


@app.get("/api/chain/verify")
@jwt_required()
def chain_verify() -> Any:
    try:
        with DBManager() as db:
            integrity, message = db.verify_chain_integrity()
            master_hash = db.compute_master_hash()
        return jsonify({
            "integrity": integrity,
            "status": "INTACT" if integrity else "TAMPERED",
            "message": message,
            "master_hash": master_hash,
        })
    except Exception:
        logger.exception("Chain verification failed")
        raise


@app.post("/api/report/generate")
@jwt_required()
def generate_report() -> Any:
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
@jwt_required(optional=True)
def download_report() -> Any:
    try:
        path = global_state.get("report_path")
        if not path or not os.path.exists(path):
            from config import REPORT_DIR
            reports = sorted(list(REPORT_DIR.glob("ArtifactPulse_Report_*.pdf")), key=lambda p: p.stat().st_mtime, reverse=True)
            if reports:
                path = str(reports[0])
            else:
                return jsonify({"error": "Report not generated yet"}), 404
        return send_file(path, as_attachment=True, download_name=os.path.basename(path))
    except Exception:
        logger.exception("Report download failed")
        raise


@app.get("/api/ml/feature-importance")
@jwt_required()
def ml_feature_importance() -> Any:
    try:
        return jsonify(global_state.get("ml_scores", {}).get("global_feature_importance", []))
    except Exception:
        logger.exception("ML feature importance endpoint failed")
        raise


@app.get("/api/ml/explanations")
@jwt_required()
def ml_explanations() -> Any:
    try:
        return jsonify(global_state.get("ml_scores", {}).get("top_anomaly_explanations", []))
    except Exception:
        logger.exception("ML explanations endpoint failed")
        raise


@app.get("/api/ml/attack-breakdown")
@jwt_required()
def ml_attack_breakdown() -> Any:
    try:
        return jsonify(global_state.get("ml_scores", {}).get("attack_type_breakdown", {}))
    except Exception:
        logger.exception("ML attack breakdown endpoint failed")
        raise


@app.get("/api/ml/training-info")
@jwt_required()
def ml_training_info() -> Any:
    try:
        return jsonify(global_state.get("ml_scores", {}).get("training_metadata", {}))
    except Exception:
        logger.exception("ML training metadata endpoint failed")
        raise


@app.route("/", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
def index() -> Any:
    return _proxy_to_frontend("")


@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
def frontend_catchall(path: str) -> Any:
    return _proxy_to_frontend(path)


# ── Helpers ──────────────────────────────────────────────────────────────────
def _severity_from_risk(risk: float) -> str:
    if risk >= 0.9:
        return "critical"
    if risk >= 0.7:
        return "high"
    if risk >= 0.4:
        return "medium"
    return "low"


def _enrich_artifact(row: dict) -> dict:
    return {
        "id": row.get("artifact_id") or str(row.get("id") or ""),
        "timestamp": row.get("event_time"),
        "source_layer": row.get("source_layer"),
        "source": row.get("source_path"),
        "description": row.get("content"),
        "severity": _severity_from_risk(float(row.get("risk_weight") or 0)),
        "content_hash": row.get("content_hash"),
        "chain_hash": row.get("chain_hash"),
        "risk_weight": row.get("risk_weight"),
    }


def _enrich_antiforensic(row: dict) -> dict:
    technique = row.get("event_type", "")
    mitre = MITRE_TECHNIQUE_MAP.get(technique, ("", ""))
    return {
        "id": str(row.get("id") or ""),
        "timestamp": row.get("event_time"),
        "technique": technique,
        "evidence": row.get("evidence"),
        "severity": row.get("severity"),
        "mitre_technique_id": mitre[0],
        "mitre_tactic": mitre[1],
    }


def _layer_breakdown(artifacts: list[dict[str, Any]]) -> dict[str, int]:
    try:
        breakdown: dict[str, int] = {}
        for artifact in artifacts:
            layer = str(artifact.get("source_layer", "unknown"))
            breakdown[layer] = breakdown.get(layer, 0) + 1
        return breakdown
    except Exception:
        logger.exception("Failed computing layer breakdown")
        return {}


# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(_: Any) -> Any:
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(422)
def unprocessable(_: Any) -> Any:
    return jsonify({"error": "Unprocessable request"}), 422


@app.errorhandler(500)
def server_error(_: Any) -> Any:
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    from waitress import serve
    host = os.environ.get("SERVER_HOST", "127.0.0.1")
    port = int(os.environ.get("SERVER_PORT", "5000"))
    logger.info("Starting Artifact-Pulse API on %s:%s via waitress", host, port)
    serve(app, host=host, port=port, threads=4)
