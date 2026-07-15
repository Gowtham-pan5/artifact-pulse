"""Process and runtime state artifact extraction module."""

from __future__ import annotations

from datetime import UTC, datetime
import logging
import os
from pathlib import Path
import psutil
import subprocess
from typing import Dict, List

from database.db_manager import DBManager

logger = logging.getLogger(__name__)


class ProcessExtractor:
    """Extract process, network, and volatile runtime artifacts."""

    SUSPICIOUS_PROCESS_NAMES = [
        "mimikatz",
        "metasploit",
        "meterpreter",
        "netcat",
        "ncat",
        "nc.exe",
        "pwdump",
        "procdump",
        "gsecdump",
        "wce.exe",
        "fgdump",
        "lsass_dump",
    ]

    def __init__(self, db: DBManager) -> None:
        """Initialize process extractor with DB manager."""
        try:
            self.db = db
        except Exception:
            logger.exception("Failed to initialize ProcessExtractor")
            raise

    def extract_running_processes(self) -> int:
        """Capture running process inventory and risk-score entries."""
        count = 0
        try:
            for proc in psutil.process_iter(
                ["pid", "name", "exe", "cmdline", "create_time", "username", "status"]
            ):
                try:
                    info = proc.info
                    name = (info.get("name") or "").lower()
                    exe = (info.get("exe") or "").lower()
                    risk = 0.2
                    if any(s in name for s in self.SUSPICIOUS_PROCESS_NAMES):
                        risk = 0.95
                    elif "\\temp\\" in exe or "\\appdata\\" in exe:
                        risk = 0.6
                    payload = {
                        "pid": info.get("pid"),
                        "name": info.get("name"),
                        "exe": info.get("exe"),
                        "cmdline": info.get("cmdline") or [],
                        "username": info.get("username"),
                        "status": info.get("status"),
                    }
                    event_time = datetime.fromtimestamp(
                        float(info.get("create_time") or datetime.now().timestamp()),
                        tz=UTC,
                    ).isoformat()
                    self.db.insert_artifact(
                        "process_snapshot",
                        "running_process",
                        str(info.get("exe") or "process://unknown"),
                        payload,
                        event_time,
                        risk,
                    )
                    count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return count
        except Exception:
            logger.exception("Failed process extraction")
            return count

    def extract_network_connections(self) -> int:
        """Capture network connections with exposure-based risk scoring."""
        count = 0
        try:
            for conn in psutil.net_connections(kind="all"):
                laddr = str(conn.laddr) if conn.laddr else ""
                raddr = str(conn.raddr) if conn.raddr else ""
                status = conn.status or "UNKNOWN"
                risk = 0.2
                if status == "ESTABLISHED" and raddr:
                    risk = 0.7
                    if not raddr.startswith("('10.") and not raddr.startswith("('192.168"):
                        risk = 0.9
                payload = {
                    "laddr": laddr,
                    "raddr": raddr,
                    "status": status,
                    "pid": conn.pid,
                    "family": str(conn.family),
                    "type": str(conn.type),
                }
                self.db.insert_artifact(
                    "process_snapshot",
                    "network_connection",
                    "net://connection",
                    payload,
                    datetime.now(UTC).isoformat(),
                    risk,
                )
                count += 1
            return count
        except Exception:
            logger.exception("Failed network connection extraction")
            return count

    def extract_open_file_handles(self) -> int:
        """Capture selected open file handles from running processes."""
        count = 0
        try:
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    for opened in proc.open_files()[:10]:
                        path = (opened.path or "").lower()
                        risk = 0.8 if "temp" in path or "prefetch" in path else 0.3
                        self.db.insert_artifact(
                            "process_snapshot",
                            "open_file_handle",
                            opened.path,
                            {"pid": proc.pid, "name": proc.name(), "path": opened.path},
                            datetime.now(UTC).isoformat(),
                            risk,
                        )
                        count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return count
        except Exception:
            logger.exception("Failed open file handle extraction")
            return count

    def extract_clipboard(self) -> int:
        """Extract current clipboard text content via PowerShell."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "Get-Clipboard"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            content = (result.stdout or "")[:2000]
            self.db.insert_artifact(
                "process_snapshot",
                "clipboard",
                "clipboard://current",
                {"content": content},
                datetime.now(UTC).isoformat(),
                0.5,
            )
            return 1
        except Exception:
            logger.exception("Failed clipboard extraction")
            return 0

    def extract_environment_variables(self) -> int:
        """Capture environment variables with path anomaly signaling."""
        count = 0
        try:
            for key, value in os.environ.items():
                risk = 0.2
                if key.upper() == "PATH" and ("temp" in value.lower() or "appdata" in value.lower()):
                    risk = 0.7
                self.db.insert_artifact(
                    "process_snapshot",
                    "environment_variable",
                    f"env://{key}",
                    {"name": key, "value": value},
                    datetime.now(UTC).isoformat(),
                    risk,
                )
                count += 1
            return count
        except Exception:
            logger.exception("Failed environment extraction")
            return count

    def run_all(self) -> Dict[str, int]:
        """Run all process extraction methods and return count summary."""
        try:
            return {
                "processes": self.extract_running_processes(),
                "network": self.extract_network_connections(),
                "handles": self.extract_open_file_handles(),
                "clipboard": self.extract_clipboard(),
                "env": self.extract_environment_variables(),
            }
        except Exception:
            logger.exception("Process extractor run_all failed")
            return {}
