"""SQLite manager for Artifact-Pulse forensic records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import logging
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple
import uuid

from config import (
    CASE_ID,
    CHAIN_GENESIS,
    COMPLIANCE_STMTS,
    DB_PATH,
    HASH_ALGORITHM,
    INVESTIGATOR,
    TOOL_NAME,
    TOOL_VERSION,
)

logger = logging.getLogger(__name__)


@dataclass
class ArtifactRecord:
    """Typed artifact payload before storage."""

    source_layer: str
    artifact_type: str
    source_path: str
    content: Any
    event_time: Optional[str]
    risk_weight: float


class DBManager:
    """Manage Artifact-Pulse SQLite schema and transactional access."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        """Initialize manager and ensure schema exists."""
        try:
            if db_path is None:
                db_path = DB_PATH
            self.db_path = db_path if isinstance(db_path, Path) else Path(db_path)
            self._conn = self._connect()
            self._init_schema()
            self._init_case()
        except Exception:
            logger.exception("Failed to initialize DBManager")
            raise

    def _connect(self) -> sqlite3.Connection:
        """Create SQLite connection with forensic-safe pragmas."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.execute("PRAGMA synchronous=FULL;")
            return conn
        except Exception:
            logger.exception("Unable to connect to SQLite database")
            raise

    def _init_schema(self) -> None:
        """Create all required tables if they are absent."""
        try:
            with self._conn:
                self._conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS artifacts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        artifact_id TEXT UNIQUE NOT NULL,
                        case_id TEXT NOT NULL,
                        source_layer TEXT NOT NULL
                        CHECK(source_layer IN (
                            'filesystem','system_events',
                            'process_snapshot','registry','antiforensic'
                        )),
                        artifact_type TEXT NOT NULL,
                        source_path TEXT NOT NULL,
                        content TEXT NOT NULL,
                        event_time TEXT,
                        extracted_at TEXT NOT NULL,
                        risk_weight REAL CHECK(risk_weight >= 0.0 AND risk_weight <= 1.0),
                        content_hash TEXT NOT NULL,
                        chain_hash TEXT NOT NULL,
                        tool_version TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS antiforensic_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        case_id TEXT,
                        event_type TEXT,
                        description TEXT,
                        event_time TEXT,
                        detected_at TEXT,
                        severity TEXT CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
                        evidence TEXT
                    );

                    CREATE TABLE IF NOT EXISTS clusters (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        cluster_id TEXT UNIQUE,
                        case_id TEXT,
                        window_start TEXT,
                        window_end TEXT,
                        event_count INTEGER,
                        suspicion_score REAL,
                        attack_type TEXT,
                        layers_involved TEXT,
                        top_artifacts TEXT,
                        antiforensic_count INTEGER DEFAULT 0,
                        created_at TEXT
                    );

                    CREATE TABLE IF NOT EXISTS case_info (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        case_id TEXT UNIQUE,
                        tool_name TEXT,
                        tool_version TEXT,
                        investigator TEXT,
                        started_at TEXT,
                        completed_at TEXT,
                        master_hash TEXT,
                        compliance TEXT
                    );
                    """
                )
        except Exception:
            logger.exception("Failed to initialize DB schema")
            raise

    def _init_case(self) -> None:
        """Insert case metadata once for this case id."""
        try:
            now = datetime.now(UTC).isoformat()
            with self._conn:
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO case_info
                    (case_id, tool_name, tool_version, investigator, started_at, compliance)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (CASE_ID, TOOL_NAME, TOOL_VERSION, INVESTIGATOR, now, json.dumps(COMPLIANCE_STMTS)),
                )
        except Exception:
            logger.exception("Failed to initialize case metadata")
            raise

    def _hash_content(self, content: str) -> str:
        """Hash content deterministically with SHA-256."""
        try:
            return hashlib.sha256(content.encode("utf-8")).hexdigest()
        except Exception:
            logger.exception("Failed to hash content")
            raise

    def _compute_chain_hash(self, prev: str, content_hash: str) -> str:
        """Compute chained hash linking previous and current content hash."""
        try:
            data = f"{prev}:{content_hash}"
            return hashlib.sha256(data.encode("utf-8")).hexdigest()
        except Exception:
            logger.exception("Failed to compute chain hash")
            raise

    def _get_last_chain_hash(self) -> str:
        """Get latest chain hash or genesis when table is empty."""
        try:
            row = self._conn.execute(
                "SELECT chain_hash FROM artifacts ORDER BY id DESC LIMIT 1"
            ).fetchone()
            return row["chain_hash"] if row else CHAIN_GENESIS
        except Exception:
            logger.exception("Failed to read last chain hash")
            raise

    def _make_artifact_id(self, layer: str, idx: int) -> str:
        """Construct stable artifact identifier."""
        try:
            return f"{CASE_ID}-{layer}-{idx:06d}"
        except Exception:
            logger.exception("Failed to build artifact id")
            raise

    def insert_artifact(
        self,
        source_layer: str,
        artifact_type: str,
        source_path: Optional[str] = None,
        content: Any = None,
        event_time: Optional[Any] = None,
        risk_weight: float = 0.0,
    ) -> str:
        """Insert a chain-linked artifact and return artifact_id."""
        try:
            if risk_weight < 0.0 or risk_weight > 1.0:
                raise ValueError("risk_weight must be between 0.0 and 1.0")
            
            # Convert datetime to ISO string if needed
            if isinstance(event_time, datetime):
                event_time = event_time.isoformat()
            elif event_time is None:
                event_time = datetime.now(UTC).isoformat()
            
            # Generate UUID artifact_id
            artifact_id = str(uuid.uuid4())
            
            content_text = (
                content
                if isinstance(content, str)
                else json.dumps(content, ensure_ascii=False, default=str)
            )
            content_hash = self._hash_content(content_text)
            prev_hash = self._get_last_chain_hash()
            chain_hash = self._compute_chain_hash(prev_hash, content_hash)
            
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO artifacts (
                        artifact_id, case_id, source_layer, artifact_type, source_path,
                        content, event_time, extracted_at, risk_weight, content_hash,
                        chain_hash, tool_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        artifact_id,
                        CASE_ID,
                        source_layer,
                        artifact_type,
                        source_path,
                        content_text,
                        event_time,
                        datetime.now(UTC).isoformat(),
                        risk_weight,
                        content_hash,
                        chain_hash,
                        TOOL_VERSION,
                    ),
                )
            return artifact_id
        except Exception:
            logger.exception("Failed to insert artifact")
            raise

    def insert_antiforensic(
        self,
        event_type: str,
        description: str,
        event_time: str,
        severity: str,
        evidence: Optional[str] = None,
    ) -> None:
        """Insert anti-forensic detection event."""
        try:
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO antiforensic_events (
                        case_id, event_type, description, event_time,
                        detected_at, severity, evidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        CASE_ID,
                        event_type,
                        description,
                        event_time,
                        datetime.now(UTC).isoformat(),
                        severity,
                        evidence,
                    ),
                )
        except Exception:
            logger.exception("Failed to insert anti-forensic event")
            raise

    def get_all_artifacts(self) -> List[Dict[str, Any]]:
        """Return all artifacts in insertion order."""
        try:
            rows = self._conn.execute("SELECT * FROM artifacts ORDER BY id ASC").fetchall()
            return [dict(r) for r in rows]
        except Exception:
            logger.exception("Failed to fetch all artifacts")
            raise

    def get_artifacts_by_layer(self, layer: str) -> List[Dict[str, Any]]:
        """Return artifacts filtered by source layer."""
        try:
            rows = self._conn.execute(
                "SELECT * FROM artifacts WHERE source_layer = ? ORDER BY id ASC", (layer,)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            logger.exception("Failed to fetch layer artifacts")
            raise

    def get_antiforensic_events(self) -> List[Dict[str, Any]]:
        """Return anti-forensic events."""
        try:
            rows = self._conn.execute(
                "SELECT * FROM antiforensic_events ORDER BY id ASC"
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            logger.exception("Failed to fetch anti-forensic events")
            raise

    def get_layer_stats(self) -> Dict[str, int]:
        """Return artifact count per layer."""
        try:
            rows = self._conn.execute(
                "SELECT source_layer, COUNT(*) as c FROM artifacts GROUP BY source_layer"
            ).fetchall()
            return {r["source_layer"]: int(r["c"]) for r in rows}
        except Exception:
            logger.exception("Failed to compute layer stats")
            raise

    def get_high_risk_artifacts(self, threshold: float = 0.7) -> List[Dict[str, Any]]:
        """Return artifacts where risk weight is at least threshold."""
        try:
            rows = self._conn.execute(
                """
                SELECT * FROM artifacts
                WHERE risk_weight >= ?
                ORDER BY risk_weight DESC, id ASC
                """,
                (threshold,),
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            logger.exception("Failed to fetch high-risk artifacts")
            raise

    def verify_chain_integrity(self) -> Tuple[bool, str]:
        """Recompute chain and report integrity status."""
        try:
            rows = self._conn.execute(
                "SELECT id, artifact_id, content_hash, chain_hash FROM artifacts ORDER BY id ASC"
            ).fetchall()
            prev = CHAIN_GENESIS
            for row in rows:
                expected = self._compute_chain_hash(prev, row["content_hash"])
                if expected != row["chain_hash"]:
                    return False, f"CHAIN BROKEN at {row['artifact_id']}"
                prev = row["chain_hash"]
            return True, "CHAIN INTACT"
        except Exception:
            logger.exception("Failed chain integrity verification")
            raise

    def compute_master_hash(self) -> str:
        """Compute deterministic case master hash from all chain hashes."""
        try:
            rows = self._conn.execute(
                "SELECT chain_hash FROM artifacts ORDER BY id ASC"
            ).fetchall()
            blob = "".join(r["chain_hash"] for r in rows) or CHAIN_GENESIS
            return hashlib.sha256(blob.encode("utf-8")).hexdigest()
        except Exception:
            logger.exception("Failed to compute master hash")
            raise

    def finalize_case(self) -> str:
        """Finalize case and return persisted master hash."""
        try:
            master_hash = self.compute_master_hash()
            with self._conn:
                self._conn.execute(
                    "UPDATE case_info SET completed_at = ?, master_hash = ? WHERE case_id = ?",
                    (datetime.now(UTC).isoformat(), master_hash, CASE_ID),
                )
            return master_hash
        except Exception:
            logger.exception("Failed to finalize case")
            raise

    def close(self) -> None:
        """Close database connection."""
        try:
            self._conn.close()
        except Exception:
            logger.exception("Failed to close database")
            raise

    def __enter__(self) -> "DBManager":
        """Return DBManager for context management."""
        try:
            return self
        except Exception:
            logger.exception("Failed entering DBManager context")
            raise

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        """Close DB connection on context exit."""
        try:
            self.close()
        except Exception:
            logger.exception("Failed exiting DBManager context")
            raise
