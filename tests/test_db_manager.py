"""Unit tests for DB manager chain integrity and hashing."""

from __future__ import annotations

from pathlib import Path

import pytest

from database.db_manager import DBManager


class TestChainIntegrity:
    """Validate blockchain-style chain behaviors."""

    def test_empty_chain_is_valid(self, tmp_path: Path) -> None:
        """Empty chain should verify as intact."""
        with DBManager(tmp_path / "t.db") as db:
            ok, _ = db.verify_chain_integrity()
            assert ok is True

    def test_single_artifact_chain_valid(self, tmp_path: Path) -> None:
        """Single inserted artifact must preserve chain integrity."""
        with DBManager(tmp_path / "t.db") as db:
            db.insert_artifact("filesystem", "x", "p", {"a": 1}, None, 0.2)
            ok, _ = db.verify_chain_integrity()
            assert ok is True

    def test_tampered_record_breaks_chain(self, tmp_path: Path) -> None:
        """Manual tamper should be detected by chain verification."""
        with DBManager(tmp_path / "t.db") as db:
            db.insert_artifact("filesystem", "x", "p", {"a": 1}, None, 0.2)
            with db._conn:
                db._conn.execute("UPDATE artifacts SET chain_hash='bad' WHERE id=1")
            ok, msg = db.verify_chain_integrity()
            assert ok is False
            assert "CHAIN BROKEN" in msg

    def test_10_artifacts_all_chained(self, tmp_path: Path) -> None:
        """Ten artifacts should produce valid continuous chain."""
        with DBManager(tmp_path / "t.db") as db:
            for i in range(10):
                db.insert_artifact("filesystem", "x", f"p{i}", {"i": i}, None, 0.2)
            ok, _ = db.verify_chain_integrity()
            assert ok is True

    def test_invalid_risk_weight_raises(self, tmp_path: Path) -> None:
        """Out-of-range risk value must raise ValueError."""
        with DBManager(tmp_path / "t.db") as db:
            with pytest.raises(ValueError):
                db.insert_artifact("filesystem", "x", "p", "y", None, 1.5)


class TestMasterHash:
    """Validate deterministic master hash behavior."""

    def test_deterministic_hash(self, tmp_path: Path) -> None:
        """Master hash should be deterministic over same DB state."""
        with DBManager(tmp_path / "t.db") as db:
            db.insert_artifact("filesystem", "x", "p", "a", None, 0.2)
            h1 = db.compute_master_hash()
            h2 = db.compute_master_hash()
            assert h1 == h2

    def test_hash_changes_on_new_artifact(self, tmp_path: Path) -> None:
        """Adding artifact must update master hash value."""
        with DBManager(tmp_path / "t.db") as db:
            h1 = db.compute_master_hash()
            db.insert_artifact("filesystem", "x", "p", "a", None, 0.2)
            h2 = db.compute_master_hash()
            assert h1 != h2
