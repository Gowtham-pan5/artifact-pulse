"""Artifact-Pulse smoke test suite.

Run with:
    python test_smoke.py
"""

from __future__ import annotations

from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
import sqlite3
import sys
import tempfile
from typing import Callable
from unittest.mock import patch


Result = tuple[str, bool, str]
results: list[Result] = []


def check(name: str, fn: Callable[[], None]) -> None:
    """Execute a single smoke check and capture output."""
    try:
        fn()
        print(f"  OK   {name}")
        results.append((name, True, ""))
    except Exception as exc:  # noqa: BLE001 - smoke test needs broad capture
        print(f"  FAIL {name}")
        print(f"       Error: {exc}")
        results.append((name, False, str(exc)))


def _new_dbmanager():
    """Create an isolated DBManager instance for test checks."""
    from database.db_manager import DBManager

    tmp_path = Path(tempfile.mktemp(suffix="_artifact_pulse_smoke.db"))
    return DBManager(tmp_path), tmp_path


def t1_python_version() -> None:
    """Validate Python runtime version is supported."""
    v = sys.version_info
    assert (v.major, v.minor) >= (3, 9), f"Need Python 3.9+, got {v.major}.{v.minor}"


def t2_flask_installed() -> None:
    """Validate Flask package is installed."""
    assert metadata.version("flask")


def t3_pandas_installed() -> None:
    """Validate pandas package is installed."""
    assert metadata.version("pandas")


def t4_sklearn_installed() -> None:
    """Validate scikit-learn package is installed."""
    assert metadata.version("scikit-learn")


def t5_psutil_installed() -> None:
    """Validate psutil package is installed."""
    assert metadata.version("psutil")


def t6_reportlab_installed() -> None:
    """Validate reportlab package is installed."""
    assert metadata.version("reportlab")


def t7_matplotlib_installed() -> None:
    """Validate matplotlib package is installed."""
    assert metadata.version("matplotlib")


def t8_python_evtx_installed() -> None:
    """Validate python-evtx package is installed."""
    assert metadata.version("python-evtx")


def t9_config_loads() -> None:
    """Validate configuration module imports and constants exist."""
    import config

    assert hasattr(config, "TOOL_NAME")
    assert hasattr(config, "OUTPUT_DIR")
    assert hasattr(config, "DB_PATH")


def t10_db_manager_chain_valid() -> None:
    """Validate DBManager starts with an intact chain."""
    db, tmp = _new_dbmanager()
    try:
        ok, _ = db.verify_chain_integrity()
        assert ok is True
    finally:
        db.close()
        tmp.unlink(missing_ok=True)


def t11_insert_without_event_time() -> None:
    """Validate artifact insert works without event_time argument."""
    db, tmp = _new_dbmanager()
    try:
        artifact_id = db.insert_artifact(
            source_layer="filesystem",
            artifact_type="smoke_without_event_time",
            source_path="C:/tmp/source.txt",
            content={"check": 11},
            risk_weight=0.2,
        )
        assert isinstance(artifact_id, str) and len(artifact_id) > 0
    finally:
        db.close()
        tmp.unlink(missing_ok=True)


def t12_insert_with_datetime_event_time() -> None:
    """Validate artifact insert supports datetime event_time values."""
    db, tmp = _new_dbmanager()
    try:
        dt = datetime.now(UTC)
        artifact_id = db.insert_artifact(
            source_layer="filesystem",
            artifact_type="smoke_with_event_time",
            source_path="C:/tmp/source2.txt",
            content="content",
            event_time=dt,
            risk_weight=0.3,
        )
        assert isinstance(artifact_id, str) and len(artifact_id) > 0
    finally:
        db.close()
        tmp.unlink(missing_ok=True)


def t13_chain_integrity_with_five_artifacts() -> None:
    """Validate SHA-256 chain remains intact after five inserts."""
    db, tmp = _new_dbmanager()
    try:
        for idx in range(5):
            db.insert_artifact(
                source_layer="filesystem",
                artifact_type=f"chain_{idx}",
                source_path=f"C:/tmp/{idx}.txt",
                content=f"item_{idx}",
                risk_weight=0.1,
            )
        ok, _ = db.verify_chain_integrity()
        assert ok is True
    finally:
        db.close()
        tmp.unlink(missing_ok=True)


def t14_tamper_detection() -> None:
    """Validate chain verification detects direct evidence tampering."""
    from database.db_manager import DBManager

    tmp_path = Path(tempfile.mktemp(suffix="_tamper.db"))
    with patch("config.CASE_ID", "AP-SMOKE-TAMPER-001"):
        db = DBManager(tmp_path)
        try:
            db.insert_artifact(
                source_layer="filesystem",
                artifact_type="tamper_test",
                source_path="C:/tmp/tamper.txt",
                content="original",
                risk_weight=0.1,
            )
            conn = sqlite3.connect(str(tmp_path))
            try:
                conn.execute("UPDATE artifacts SET content_hash='0' WHERE id=1")
                conn.commit()
            finally:
                conn.close()
            ok, _ = db.verify_chain_integrity()
            assert ok is False
        finally:
            db.close()
            tmp_path.unlink(missing_ok=True)


def t15_core_module_imports() -> None:
    """Validate all core modules import successfully."""
    from core.antiforensic_detector import AntiForensicDetector
    from core.correlation_engine import CorrelationEngine
    from core.evidence_sealer import EvidenceSealer
    from core.eventlog_extractor import EventLogExtractor
    from core.filesystem_extractor import FilesystemExtractor
    from core.ml_scorer import MLScorer
    from core.process_extractor import ProcessExtractor

    assert all(
        cls is not None
        for cls in (
            FilesystemExtractor,
            EventLogExtractor,
            ProcessExtractor,
            AntiForensicDetector,
            CorrelationEngine,
            MLScorer,
            EvidenceSealer,
        )
    )


def t16_flask_app_exists() -> None:
    """Validate web application entrypoint exists."""
    assert Path("web/app.py").exists()


def t17_psutil_reads_processes() -> None:
    """Validate psutil can read live process information."""
    import psutil

    procs = list(psutil.process_iter(["pid", "name"]))
    assert len(procs) > 0


def t18_output_directories_exist() -> None:
    """Validate output directories are created by config."""
    import config

    assert config.OUTPUT_DIR.exists()
    assert config.REPORT_DIR.exists()
    assert config.LOG_DIR.exists()


def t19_antiforensic_insert_retrieve() -> None:
    """Validate anti-forensic insert and retrieval path."""
    db, tmp = _new_dbmanager()
    try:
        db.insert_antiforensic(
            event_type="SMOKE_EVENT",
            description="Smoke anti-forensic event",
            event_time=datetime.now(UTC).isoformat(),
            severity="HIGH",
            evidence="test evidence",
        )
        events = db.get_antiforensic_events()
        assert len(events) >= 1
    finally:
        db.close()
        tmp.unlink(missing_ok=True)


def t20_master_hash_valid_sha256() -> None:
    """Validate master hash is a 64-character SHA-256 hex string."""
    db, tmp = _new_dbmanager()
    try:
        db.insert_artifact(
            source_layer="filesystem",
            artifact_type="master_hash_test",
            source_path="C:/tmp/master.txt",
            content="master hash content",
            risk_weight=0.1,
        )
        master = db.compute_master_hash()
        assert len(master) == 64
        int(master, 16)
    finally:
        db.close()
        tmp.unlink(missing_ok=True)


if __name__ == "__main__":
    print("\n" + "=" * 55)
    print("  ARTIFACT-PULSE SMOKE TEST")
    print("=" * 55 + "\n")

    checks: list[tuple[str, Callable[[], None]]] = [
        ("Python version 3.9+", t1_python_version),
        ("Flask installed", t2_flask_installed),
        ("Pandas installed", t3_pandas_installed),
        ("Scikit-learn installed", t4_sklearn_installed),
        ("psutil installed", t5_psutil_installed),
        ("ReportLab installed", t6_reportlab_installed),
        ("Matplotlib installed", t7_matplotlib_installed),
        ("python-evtx installed", t8_python_evtx_installed),
        ("config.py loads correctly", t9_config_loads),
        ("DBManager creates DB + chain valid", t10_db_manager_chain_valid),
        ("Insert artifact without event_time", t11_insert_without_event_time),
        ("Insert artifact with event_time datetime", t12_insert_with_datetime_event_time),
        ("SHA-256 chain integrity with 5 artifacts", t13_chain_integrity_with_five_artifacts),
        ("SHA-256 tamper detection", t14_tamper_detection),
        ("All core module imports", t15_core_module_imports),
        ("Flask app.py exists", t16_flask_app_exists),
        ("psutil reads live processes", t17_psutil_reads_processes),
        ("Output directories exist", t18_output_directories_exist),
        ("Anti-forensic insert + retrieve", t19_antiforensic_insert_retrieve),
        ("Master hash is valid SHA-256", t20_master_hash_valid_sha256),
    ]

    for name, fn in checks:
        check(name, fn)

    passed = sum(1 for _, ok, _ in results if ok)
    failed = len(results) - passed
    print("\n" + "=" * 55)
    print(f"  RESULT: {passed}/{len(results)} tests passed")
    print("=" * 55)
    if failed:
        raise SystemExit(1)
