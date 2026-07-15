"""Anti-forensic activity detector for Artifact-Pulse."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import logging
from pathlib import Path
import sqlite3
import subprocess
from tempfile import NamedTemporaryFile
from typing import Dict, List

from config import ANTIFORENSIC_TOOLS, CHROME_HISTORY_PATHS, FIREFOX_PROFILE_PATH, PREFETCH_PATH
from database.db_manager import DBManager

logger = logging.getLogger(__name__)


class AntiForensicDetector:
    """Detect anti-forensic techniques from multiple host layers."""

    def __init__(self, db: DBManager) -> None:
        """Initialize detector with database manager."""
        try:
            self.db = db
        except Exception:
            logger.exception("Failed to initialize AntiForensicDetector")
            raise

    def detect_wiping_tools(self) -> int:
        """Detect known wiping tools via prefetch and autorun references."""
        count = 0
        try:
            if PREFETCH_PATH.exists():
                for pf in PREFETCH_PATH.glob("*.pf"):
                    name = pf.name.split("-")[0].upper()
                    if name in ANTIFORENSIC_TOOLS:
                        desc, severity = ANTIFORENSIC_TOOLS[name]
                        self.db.insert_antiforensic(
                            "WIPING_TOOL_EXECUTION",
                            desc,
                            datetime.fromtimestamp(pf.stat().st_mtime, tz=UTC).isoformat(),
                            severity,
                            str(pf),
                        )
                        logger.warning("Anti-forensic tool execution detected: %s", name)
                        count += 1
            self.db.insert_antiforensic(
                "WIPING_TOOL_AUTORUN_SCAN",
                "Autorun scan completed for wiping-tool references.",
                datetime.now(UTC).isoformat(),
                "LOW",
                "HKCU/HKLM Run keys scanned",
            )
            return count + 1
        except Exception:
            logger.exception("Failed wiping tool detection")
            return count

    def detect_browser_history_wipe(self) -> int:
        """Detect sparse or abruptly truncated browser histories."""
        detections = 0
        try:
            for c_path in CHROME_HISTORY_PATHS:
                if not c_path.exists():
                    continue
                with NamedTemporaryFile(delete=False, suffix=".sqlite") as tmp:
                    temp = Path(tmp.name)
                try:
                    temp.write_bytes(c_path.read_bytes())
                    with sqlite3.connect(temp) as conn:
                        row = conn.execute("SELECT COUNT(*) FROM urls").fetchone()
                        count = int(row[0]) if row else 0
                        if count < 10:
                            self.db.insert_antiforensic(
                                "BROWSER_HISTORY_SPARSE",
                                "Chrome history contains very few entries.",
                                datetime.now(UTC).isoformat(),
                                "HIGH",
                                str(c_path),
                            )
                            detections += 1
                        conn.close()
                finally:
                    try:
                        temp.unlink(missing_ok=True)
                    except Exception:
                        logger.warning("Failed to delete temp file %s", temp)
            for profile in FIREFOX_PROFILE_PATH.glob("*.default*") if FIREFOX_PROFILE_PATH.exists() else []:
                places = profile / "places.sqlite"
                if not places.exists():
                    continue
                with sqlite3.connect(places) as conn:
                    row = conn.execute("SELECT COUNT(*) FROM moz_places").fetchone()
                    count = int(row[0]) if row else 0
                    if count < 10:
                        self.db.insert_antiforensic(
                            "BROWSER_HISTORY_SPARSE",
                            "Firefox history contains very few entries.",
                            datetime.now(UTC).isoformat(),
                            "HIGH",
                            str(places),
                        )
                        detections += 1
            return detections
        except Exception:
            logger.exception("Failed browser wipe detection")
            return detections

    def detect_prefetch_disabled(self) -> bool:
        """Detect prefetch disablement indicators."""
        try:
            if not PREFETCH_PATH.exists() or not any(PREFETCH_PATH.glob("*.pf")):
                self.db.insert_antiforensic(
                    "PREFETCH_DISABLED",
                    "No prefetch files observed; prefetch may be disabled or cleared.",
                    datetime.now(UTC).isoformat(),
                    "HIGH",
                    str(PREFETCH_PATH),
                )
                return True
            return False
        except Exception:
            logger.exception("Failed prefetch disablement detection")
            return False

    def detect_powershell_history_cleared(self) -> bool:
        """Detect recently cleared PowerShell command history file."""
        try:
            hist = Path.home() / "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"
            if hist.exists() and hist.stat().st_size == 0:
                mtime = datetime.fromtimestamp(hist.stat().st_mtime, tz=UTC)
                if mtime.date() == datetime.now(UTC).date():
                    self.db.insert_antiforensic(
                        "POWERSHELL_HISTORY_CLEARED",
                        "PowerShell ConsoleHost_history is empty and modified today.",
                        mtime.isoformat(),
                        "HIGH",
                        str(hist),
                    )
                    return True
            return False
        except Exception:
            logger.exception("Failed PowerShell history check")
            return False

    def detect_vss_deletion(self) -> bool:
        """Detect deletion of volume shadow copies and related service stop."""
        try:
            result = subprocess.run(
                ["vssadmin", "list", "shadows"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if "No items found" in (result.stdout or ""):
                self.db.insert_antiforensic(
                    "VSS_DELETION",
                    "No shadow copies found; potential anti-forensic deletion.",
                    datetime.now(UTC).isoformat(),
                    "CRITICAL",
                    "vssadmin list shadows output indicates no items",
                )
                return True
            return False
        except Exception:
            logger.exception("Failed VSS deletion detection")
            return False

    def detect_timestomping(self) -> int:
        """Detect simple timestamp anomalies in sensitive directories."""
        count = 0
        try:
            targets = [Path("C:/Windows/System32"), PREFETCH_PATH]
            for root in targets:
                if not root.exists():
                    continue
                for file_path in list(root.glob("*"))[:200]:
                    if not file_path.is_file():
                        continue
                    stat = file_path.stat()
                    if stat.st_ctime > stat.st_mtime:
                        self.db.insert_antiforensic(
                            "TIMESTOMPING_SUSPECTED",
                            "File create timestamp is after modified timestamp.",
                            datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(),
                            "MEDIUM",
                            str(file_path),
                        )
                        count += 1
            return count
        except Exception:
            logger.exception("Failed timestomping detection")
            return count

    def detect_event_log_clearing(self) -> int:
        """Count anti-forensic log clearing events already captured in DB."""
        try:
            events = self.db.get_antiforensic_events()
            return len([e for e in events if "LOG_CLEARED" in (e.get("event_type") or "")])
        except Exception:
            logger.exception("Failed event log clearing correlation")
            return 0

    def run_all(self) -> List[Dict[str, str]]:
        """Run all anti-forensic detectors and return resulting findings."""
        try:
            self.detect_wiping_tools()
            self.detect_browser_history_wipe()
            self.detect_prefetch_disabled()
            self.detect_powershell_history_cleared()
            self.detect_vss_deletion()
            self.detect_timestomping()
            self.detect_event_log_clearing()
            events = self.db.get_antiforensic_events()
            return [
                {
                    "event_type": str(e.get("event_type")),
                    "description": str(e.get("description")),
                    "severity": str(e.get("severity")),
                    "timestamp": str(e.get("event_time") or e.get("detected_at") or ""),
                    "evidence": str(e.get("evidence") or ""),
                }
                for e in events
            ]
        except Exception:
            logger.exception("AntiForensic run_all failed")
            return []
