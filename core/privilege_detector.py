"""Privilege and capability detection engine for Adaptive Dual-Tier forensics.

Distinguishes between:
- Tier 1: User-Space Fast Triage (Non-Admin Standard User)
- Tier 2: Deep Forensic IR (Elevated Administrator)
"""

from __future__ import annotations

import ctypes
import logging
import os
import platform
import sys
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class PrivilegeDetector:
    """Detects active process execution token, privilege boundaries, and accessible artifact scopes."""

    @staticmethod
    def is_admin() -> bool:
        """Check if current process has administrative / elevated privileges."""
        try:
            if sys.platform == "win32":
                return bool(ctypes.windll.shell32.IsUserAnAdmin() != 0)
            return bool(os.geteuid() == 0)
        except Exception as exc:
            logger.debug("Failed checking admin privileges: %s", exc)
            return False

    @classmethod
    def get_tier_info(cls) -> Dict[str, Any]:
        """Return comprehensive privilege status and capability matrix."""
        admin = cls.is_admin()
        tier = "ADMIN_ELEVATED" if admin else "USER_SCOPE"
        tier_label = "Administrator (Full Deep Forensic Scan)" if admin else "Standard User (User-Space Fast Triage)"

        if admin:
            accessible_layers = [
                "filesystem_full",
                "browser_sqlite_history",
                "registry_hkcu",
                "registry_hklm_system",
                "registry_hklm_sam",
                "eventlog_security",
                "eventlog_system",
                "eventlog_powershell",
                "live_processes_all",
                "antiforensic_detection",
                "chain_of_custody",
            ]
            skipped_artifacts: List[str] = []
            elevation_hint = ""
        else:
            accessible_layers = [
                "filesystem_user_profile",
                "browser_sqlite_history",
                "registry_hkcu",
                "registry_hklm_readable",
                "live_processes_user",
                "antiforensic_heuristics",
                "chain_of_custody",
            ]
            skipped_artifacts = [
                "Security.evtx (Audit & Logon logs require SeSecurityPrivilege)",
                "System.evtx (System service audit logs require elevation)",
                "Microsoft-Windows-PowerShell Operational logs (requires Administrator)",
                "HKLM\\SAM & Restricted System Network Profiles",
                "Privileged Kernel Process token descriptors",
            ]
            elevation_hint = "Run as Administrator (right-click START.bat -> Run as administrator) to unlock Security/System EVTX logs and system hives."

        return {
            "is_admin": admin,
            "tier": tier,
            "tier_label": tier_label,
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "platform": sys.platform,
            "accessible_layers": accessible_layers,
            "skipped_artifacts": skipped_artifacts,
            "elevation_hint": elevation_hint,
        }
