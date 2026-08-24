"""Integration tests for the Flask API endpoints."""

from __future__ import annotations

import os
import sys
from pathlib import Path
import pytest

# Set required env vars before importing the app module
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-pytest")
os.environ.setdefault("CORS_ORIGINS", "http://localhost:5173")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture()
def client():
    from web.app import app
    app.config["TESTING"] = True
    app.config["JWT_SECRET_KEY"] = "test-secret-key-for-pytest"
    with app.test_client() as c:
        yield c


@pytest.fixture()
def auth_token(client):
    resp = client.post("/api/auth/token")
    assert resp.status_code == 200
    return resp.get_json()["access_token"]


@pytest.fixture()
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}


def test_health_no_auth_required(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert "version" in data


def test_token_endpoint_returns_token(client):
    resp = client.post("/api/auth/token")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "access_token" in data
    assert len(data["access_token"]) > 20


def test_protected_endpoint_requires_auth(client):
    resp = client.get("/api/extraction/status")
    assert resp.status_code == 401


def test_extraction_status_with_auth(client, auth_headers):
    resp = client.get("/api/extraction/status", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert "running" in data
    assert "stage" in data


def test_artifacts_endpoint_with_auth(client, auth_headers):
    resp = client.get("/api/artifacts", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert "artifacts" in data


def test_artifacts_invalid_limit(client, auth_headers):
    resp = client.get("/api/artifacts?limit=abc", headers=auth_headers)
    assert resp.status_code == 400


def test_artifacts_invalid_layer(client, auth_headers):
    resp = client.get("/api/artifacts?layer=unknown_layer", headers=auth_headers)
    assert resp.status_code == 400


def test_stats_with_auth(client, auth_headers):
    resp = client.get("/api/stats", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert "total_artifacts" in data


def test_antiforensic_with_auth(client, auth_headers):
    resp = client.get("/api/antiforensic", headers=auth_headers)
    assert resp.status_code == 200
    assert "antiforensic" in resp.get_json()


def test_clusters_with_auth(client, auth_headers):
    resp = client.get("/api/clusters", headers=auth_headers)
    assert resp.status_code == 200
    assert "clusters" in resp.get_json()


def test_ml_feature_importance_with_auth(client, auth_headers):
    resp = client.get("/api/ml/feature-importance", headers=auth_headers)
    assert resp.status_code == 200


def test_ml_attack_breakdown_with_auth(client, auth_headers):
    resp = client.get("/api/ml/attack-breakdown", headers=auth_headers)
    assert resp.status_code == 200


def test_ml_training_info_with_auth(client, auth_headers):
    resp = client.get("/api/ml/training-info", headers=auth_headers)
    assert resp.status_code == 200


def test_404_returns_json(client):
    resp = client.get("/api/nonexistent")
    assert resp.status_code == 404
    assert resp.get_json() == {"error": "Not found"}


def test_start_extraction_requires_auth(client):
    resp = client.post("/api/extraction/start")
    assert resp.status_code == 401


def test_report_download_not_found_with_auth(client, auth_headers):
    resp = client.get("/api/report/download", headers=auth_headers)
    assert resp.status_code == 404
