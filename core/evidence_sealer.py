"""Evidence chain sealing and export module."""

from __future__ import annotations

from datetime import UTC, datetime
import json
import logging
from pathlib import Path
from typing import Any, Dict

from config import CASE_ID, COMPLIANCE_STMTS
from database.db_manager import DBManager

logger = logging.getLogger(__name__)


class EvidenceSealer:
    """Finalize case evidence with chain integrity and master hash output."""

    def __init__(self, db: DBManager) -> None:
        """Initialize sealer with DB manager."""
        try:
            self.db = db
            self._seal_cache: Dict[str, Any] = {}
        except Exception:
            logger.exception("Failed to initialize EvidenceSealer")
            raise

    def seal(self) -> Dict[str, Any]:
        """Verify chain, finalize case, and return immutable seal metadata."""
        try:
            integrity, message = self.db.verify_chain_integrity()
            master_hash = self.db.compute_master_hash()
            self.db.finalize_case()
            total = len(self.db.get_all_artifacts())
            self._seal_cache = {
                "seal_timestamp": datetime.now(UTC).isoformat(),
                "total_artifacts": total,
                "chain_integrity": integrity,
                "chain_message": message,
                "master_hash": master_hash,
                "algorithm": "SHA-256",
                "compliance": COMPLIANCE_STMTS,
                "case_id": CASE_ID,
            }
            return self._seal_cache
        except Exception:
            logger.exception("Evidence sealing failed")
            return {}

    def export_seal_json(self, path: Path) -> Path:
        """Export current seal data to JSON path and return saved path."""
        try:
            if not self._seal_cache:
                self.seal()
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(self._seal_cache, handle, indent=2)
            return path
        except Exception:
            logger.exception("Failed to export seal JSON")
            raise
