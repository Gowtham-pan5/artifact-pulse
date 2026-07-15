"""Central configuration and logging for Artifact-Pulse."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
import getpass
import os

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"
REPORT_DIR = OUTPUT_DIR / "reports"
LOG_DIR = OUTPUT_DIR / "logs"
DB_PATH = OUTPUT_DIR / "artifact_pulse.db"

CASE_ID = f"AP-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"
TOOL_NAME = "Artifact-Pulse"
TOOL_VERSION = "1.0.0"
INVESTIGATOR = getpass.getuser()
ORGANIZATION = "Digital Forensics Unit"

WINDOWS_USER = os.environ.get("USERNAME", INVESTIGATOR)
USER_PROFILE = Path(os.environ.get("USERPROFILE", "C:/Users/Public"))
APPDATA_LOCAL = USER_PROFILE / "AppData" / "Local"
APPDATA_ROAM = USER_PROFILE / "AppData" / "Roaming"

CHROME_HISTORY_PATHS = [
    APPDATA_LOCAL / "Google" / "Chrome" / "User Data" / "Default" / "History",
    APPDATA_LOCAL / "Google" / "Chrome" / "User Data" / "Profile 1" / "History",
]
FIREFOX_PROFILE_PATH = APPDATA_ROAM / "Mozilla" / "Firefox" / "Profiles"
PREFETCH_PATH = Path("C:/Windows/Prefetch")
LNK_RECENT_PATH = APPDATA_ROAM / "Microsoft" / "Windows" / "Recent"
EVTX_DIR = Path("C:/Windows/System32/winevt/Logs")
EVTX_FILES = {
    "security": EVTX_DIR / "Security.evtx",
    "system": EVTX_DIR / "System.evtx",
    "powershell": EVTX_DIR / "Microsoft-Windows-PowerShell%4Operational.evtx",
}

SECURITY_EVENT_IDS = {
    4624: ("Successful login", 0.2),
    4625: ("Failed login", 0.6),
    4688: ("Process creation", 0.5),
    4720: ("User account created", 0.7),
    1102: ("Security log cleared", 1.0),
}
SYSTEM_EVENT_IDS = {
    104: ("System log cleared", 1.0),
    6005: ("Event log service started", 0.3),
    6006: ("Event log service stopped", 0.6),
    7036: ("Service state changed", 0.4),
}

ANTIFORENSIC_TOOLS = {
    "CCLEANER": ("Potential browser and temp cleanup", "MEDIUM"),
    "BLEACHBIT": ("Secure wiping utility observed", "HIGH"),
    "SDELETE": ("Secure file deletion utility observed", "CRITICAL"),
    "ERASER": ("Data erasure utility observed", "HIGH"),
    "PRIVAZER": ("Privacy cleaner utility observed", "MEDIUM"),
}

SUSPICIOUS_URLS = [
    "pastebin",
    "anonfiles",
    "mega.nz",
    "torproject",
    "onion",
    "dropbox",
]
SUSPICIOUS_EXTENSIONS = {
    "archives": [".zip", ".rar", ".7z"],
    "executables": [".exe", ".msi", ".dll"],
    "scripts": [".ps1", ".bat", ".cmd", ".vbs"],
}

ML_CONFIG = {
    "isolation_forest": {"contamination": 0.05, "random_state": 42, "n_estimators": 100},
    "kmeans": {"n_clusters": 5, "n_init": 10, "random_state": 42},
    "correlation": {"window_minutes": 5, "min_cluster_score": 20.0},
}

HASH_ALGORITHM = "sha256"
CHAIN_GENESIS = "ARTIFACT-PULSE-GENESIS-BLOCK-V1"
COMPLIANCE_STMTS = [
    "NIST SP 800-86 aligned forensic acquisition and analysis.",
    "ACPO Good Practice Guide principles observed.",
    "Section 65B digital evidence handling declaration included.",
]

for directory in (OUTPUT_DIR, REPORT_DIR, LOG_DIR):
    directory.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_DIR / "artifact_pulse.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler()],
)
