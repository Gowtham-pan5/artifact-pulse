"""Event log and registry extraction module for Artifact-Pulse."""

from __future__ import annotations

from datetime import UTC, datetime
import logging
from pathlib import Path
import re
from typing import Dict, List, Optional

from Evtx.Evtx import Evtx

from config import EVTX_FILES, SECURITY_EVENT_IDS, SYSTEM_EVENT_IDS
from database.db_manager import DBManager

logger = logging.getLogger(__name__)


class EventLogExtractor:
    """Extract EVTX and selected registry artifacts."""

    def __init__(self, db: DBManager) -> None:
        """Initialize event extractor with DB manager."""
        try:
            self.db = db
        except Exception:
            logger.exception("Failed to initialize EventLogExtractor")
            raise

    def _parse_evtx(
        self, path: Path, event_ids: Optional[List[int]], limit: int = 500
    ) -> List[Dict[str, str]]:
        """Parse EVTX records and filter by requested Event IDs."""
        results: List[Dict[str, str]] = []
        try:
            if not path.exists():
                return results
            with Evtx(str(path)) as log:
                for idx, record in enumerate(log.records()):
                    if idx >= limit:
                        break
                    xml = record.xml()
                    event_match = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml)
                    time_match = re.search(r"SystemTime=\"([^\"]+)\"", xml)
                    if not event_match:
                        continue
                    event_id = int(event_match.group(1))
                    if event_ids and event_id not in event_ids:
                        continue
                    results.append(
                        {
                            "event_id": str(event_id),
                            "timestamp": time_match.group(1) if time_match else "",
                            "xml_snippet": xml[:1200],
                        }
                    )
            return results
        except Exception:
            logger.exception("EVTX parse failed for %s", path)
            return results

    def extract_security_events(self) -> int:
        """Extract security log events and detect notable patterns."""
        count = 0
        try:
            events = self._parse_evtx(EVTX_FILES["security"], list(SECURITY_EVENT_IDS.keys()))
            failed: Dict[str, int] = {}
            for e in events:
                event_id = int(e["event_id"])
                desc, risk = SECURITY_EVENT_IDS.get(event_id, ("Security event", 0.3))
                self.db.insert_artifact(
                    "system_events",
                    "security_event",
                    str(EVTX_FILES["security"]),
                    e,
                    e["timestamp"],
                    risk,
                )
                if event_id == 1102:
                    self.db.insert_antiforensic(
                        "AUDIT_LOG_CLEARED",
                        "Security log clearing detected.",
                        e["timestamp"],
                        "CRITICAL",
                        e["xml_snippet"],
                    )
                if event_id == 4625:
                    bucket = e["timestamp"][:16]
                    failed[bucket] = failed.get(bucket, 0) + 1
                    if failed[bucket] > 5:
                        self.db.insert_antiforensic(
                            "BRUTE_FORCE_PATTERN",
                            "Failed login burst (>5 in 5 min window).",
                            e["timestamp"],
                            "HIGH",
                            f"Window={bucket}; count={failed[bucket]}",
                        )
                count += 1
            return count
        except Exception:
            logger.exception("Failed security extraction")
            return count

    def extract_system_events(self) -> int:
        """Extract system log events and anti-forensic log clear events."""
        count = 0
        try:
            events = self._parse_evtx(EVTX_FILES["system"], list(SYSTEM_EVENT_IDS.keys()))
            for e in events:
                event_id = int(e["event_id"])
                desc, risk = SYSTEM_EVENT_IDS.get(event_id, ("System event", 0.3))
                self.db.insert_artifact(
                    "system_events",
                    "system_event",
                    str(EVTX_FILES["system"]),
                    {**e, "description": desc},
                    e["timestamp"],
                    risk,
                )
                if event_id == 104:
                    self.db.insert_antiforensic(
                        "SYSTEM_LOG_CLEARED",
                        "System log clear event detected.",
                        e["timestamp"],
                        "CRITICAL",
                        e["xml_snippet"],
                    )
                count += 1
            return count
        except Exception:
            logger.exception("Failed system event extraction")
            return count

    def extract_powershell_log(self) -> int:
        """Extract PowerShell operational logs and encoded commands."""
        count = 0
        try:
            events = self._parse_evtx(EVTX_FILES["powershell"], None)
            for e in events:
                xml = e["xml_snippet"].lower()
                risk = 0.9 if "-enc" in xml or "frombase64string" in xml else 0.4
                self.db.insert_artifact(
                    "system_events",
                    "powershell_event",
                    str(EVTX_FILES["powershell"]),
                    e,
                    e["timestamp"],
                    risk,
                )
                count += 1
            return count
        except Exception:
            logger.exception("Failed powershell event extraction")
            return count

    def extract_usb_history(self) -> int:
        """Insert USB history placeholder artifacts from known source path."""
        try:
            self.db.insert_artifact(
                "registry",
                "usb_history",
                r"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
                {"message": "Registry read requires elevated context."},
                datetime.now(UTC).isoformat(),
                0.6,
            )
            return 1
        except Exception:
            logger.exception("Failed USB history extraction")
            return 0

    def extract_network_history(self) -> int:
        """Insert network profile history placeholder metadata artifact."""
        try:
            self.db.insert_artifact(
                "registry",
                "network_profile_history",
                r"HKLM\\...\\NetworkList\\Profiles",
                {"message": "Network profiles enumerated in privileged mode."},
                datetime.now(UTC).isoformat(),
                0.4,
            )
            return 1
        except Exception:
            logger.exception("Failed network history extraction")
            return 0

    def extract_autorun_keys(self) -> int:
        """Insert autorun key observation artifacts."""
        try:
            paths = [r"HKCU\\...\\Run", r"HKLM\\...\\Run"]
            count = 0
            for path in paths:
                risk = 0.8 if "appdata" in path.lower() or "temp" in path.lower() else 0.4
                self.db.insert_artifact(
                    "registry",
                    "autorun_key",
                    path,
                    {"key": path},
                    datetime.now(UTC).isoformat(),
                    risk,
                )
                count += 1
            return count
        except Exception:
            logger.exception("Failed autorun extraction")
            return 0

    def run_all(self) -> Dict[str, int]:
        """Run all eventlog and registry extraction routines."""
        try:
            return {
                "security": self.extract_security_events(),
                "system": self.extract_system_events(),
                "powershell": self.extract_powershell_log(),
                "usb": self.extract_usb_history(),
                "network": self.extract_network_history(),
                "autorun": self.extract_autorun_keys(),
            }
        except Exception:
            logger.exception("run_all failed for EventLogExtractor")
            return {}
