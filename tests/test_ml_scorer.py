"""Unit tests for ML scoring module."""

from __future__ import annotations

from pathlib import Path

from core.ml_scorer import MLScorer
from database.db_manager import DBManager


def test_isolation_forest_returns_float(tmp_path: Path) -> None:
    """Isolation forest score should be numeric float."""
    with DBManager(tmp_path / "m.db") as db:
        for i in range(20):
            db.insert_artifact("filesystem", "x", f"p{i}", "a", "2026-01-01T00:00:00+00:00", 0.3)
        score = MLScorer(db, []).run_isolation_forest()
        assert isinstance(score, float)


def test_returns_severity_label(tmp_path: Path) -> None:
    """Final score payload must include severity label."""
    with DBManager(tmp_path / "m.db") as db:
        result = MLScorer(db, []).compute_final_score(0.1, 1, 0.1)
        assert result["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_critical_threshold_above_80(tmp_path: Path) -> None:
    """Score above 80 should classify as CRITICAL."""
    with DBManager(tmp_path / "m.db") as db:
        result = MLScorer(db, []).compute_final_score(1.0, 50, 1.0)
        assert result["severity"] == "CRITICAL"
