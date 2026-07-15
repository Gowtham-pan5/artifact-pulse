"""Unit tests for filesystem extractor basics."""

from __future__ import annotations

from pathlib import Path

from core.filesystem_extractor import FilesystemExtractor
from database.db_manager import DBManager


def test_run_all_returns_summary_dict(tmp_path: Path) -> None:
    """Filesystem run_all should always return a summary dictionary."""
    with DBManager(tmp_path / "f.db") as db:
        result = FilesystemExtractor(db).run_all()
        assert isinstance(result, dict)
