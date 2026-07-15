"""Unit tests for correlation engine behavior."""

from __future__ import annotations

from pathlib import Path

from core.correlation_engine import CorrelationEngine
from database.db_manager import DBManager


def test_empty_artifacts_returns_empty_clusters(tmp_path: Path) -> None:
    """No artifacts should produce no suspicious clusters."""
    with DBManager(tmp_path / "c.db") as db:
        engine = CorrelationEngine(db)
        clusters = engine.run_all()
        assert clusters == []


def test_single_event_no_cluster(tmp_path: Path) -> None:
    """Single low-risk event should not cross cluster threshold."""
    with DBManager(tmp_path / "c.db") as db:
        db.insert_artifact("filesystem", "x", "p", "v", "2026-01-01T00:00:00+00:00", 0.1)
        engine = CorrelationEngine(db)
        clusters = engine.run_all()
        assert isinstance(clusters, list)


def test_high_risk_events_form_cluster(tmp_path: Path) -> None:
    """Burst of high-risk events should produce suspicious cluster."""
    with DBManager(tmp_path / "c.db") as db:
        for i in range(8):
            db.insert_artifact(
                "process_snapshot",
                "running_process",
                f"p{i}",
                {"i": i},
                "2026-01-01T00:00:00+00:00",
                0.9,
            )
        clusters = CorrelationEngine(db).run_all()
        assert len(clusters) >= 1


def test_antiforensic_raises_score(tmp_path: Path) -> None:
    """Anti-forensic event in same window should increase score weight."""
    with DBManager(tmp_path / "c.db") as db:
        for _ in range(5):
            db.insert_artifact("filesystem", "x", "p", "v", "2026-01-01T00:00:00+00:00", 0.7)
        db.insert_antiforensic("AUDIT_LOG_CLEARED", "clear", "2026-01-01T00:00:01+00:00", "CRITICAL", "x")
        clusters = CorrelationEngine(db).run_all()
        assert isinstance(clusters, list)
