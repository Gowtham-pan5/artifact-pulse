"""Event log and registry extraction module for Artifact-Pulse."""

from __future__ import annotations

from datetime import UTC, datetime
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

try:
    import winreg
except ImportError:
    winreg = None

try:
    from Evtx.Evtx import Evtx
except ImportError:
    Evtx = None

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
        if Evtx is None:
            logger.debug("python-evtx not available; skipping EVTX parse for %s", path)
            return results
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
        """Extract USB storage device connection history from Windows Registry."""
        count = 0
        now = datetime.now(UTC).isoformat()
        if winreg is None:
            logger.info("winreg not available on this platform; skipping USBSTOR extraction")
            return count

        try:
            # Enumerate USBSTOR devices under HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
            usbstor_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, usbstor_path, 0, winreg.KEY_READ) as usbstor_key:
                    dev_count, _, _ = winreg.QueryInfoKey(usbstor_key)
                    for i in range(dev_count):
                        dev_family = winreg.EnumKey(usbstor_key, i)
                        dev_full_path = f"{usbstor_path}\\{dev_family}"
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, dev_full_path, 0, winreg.KEY_READ) as dev_key:
                                inst_count, _, _ = winreg.QueryInfoKey(dev_key)
                                for j in range(inst_count):
                                    inst_id = winreg.EnumKey(dev_key, j)
                                    inst_full_path = f"{dev_full_path}\\{inst_id}"
                                    inst_props: Dict[str, Any] = {
                                        "device_family": dev_family,
                                        "instance_id": inst_id,
                                    }
                                    try:
                                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, inst_full_path, 0, winreg.KEY_READ) as inst_key:
                                            val_count = winreg.QueryInfoKey(inst_key)[1]
                                            for v in range(val_count):
                                                val_name, val_data, _ = winreg.EnumValue(inst_key, v)
                                                if val_name in (
                                                    "FriendlyName",
                                                    "HardwareID",
                                                    "DeviceDesc",
                                                    "CompatibleIDs",
                                                    "Mfg",
                                                    "ContainerID",
                                                ):
                                                    inst_props[val_name] = val_data
                                    except Exception:
                                        logger.debug("Failed reading instance properties for %s", inst_full_path)

                                    friendly = inst_props.get("FriendlyName") or inst_props.get("DeviceDesc") or dev_family
                                    self.db.insert_artifact(
                                        "registry",
                                        "usb_history",
                                        f"HKLM\\{inst_full_path}",
                                        {
                                            "name": friendly,
                                            "properties": inst_props,
                                            "description": f"USB Storage Device: {friendly} (Serial: {inst_id})",
                                        },
                                        now,
                                        0.5,
                                    )
                                    count += 1
                        except Exception:
                            logger.debug("Failed reading device family subkey %s", dev_full_path)
            except FileNotFoundError:
                logger.debug("USBSTOR registry key not found")
            except PermissionError:
                logger.warning("Permission denied reading USBSTOR registry key")

            # Also check MountedDevices for volume serial mappings
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\MountedDevices", 0, winreg.KEY_READ) as mnt_key:
                    _, mnt_val_count, _ = winreg.QueryInfoKey(mnt_key)
                    for v in range(mnt_val_count):
                        val_name, val_data, _ = winreg.EnumValue(mnt_key, v)
                        if val_name.startswith("\\DosDevices\\") or val_name.startswith("\\??\\Volume"):
                            data_repr = val_data.hex() if isinstance(val_data, bytes) else str(val_data)
                            self.db.insert_artifact(
                                "registry",
                                "mounted_device",
                                f"HKLM\\SYSTEM\\MountedDevices\\{val_name}",
                                {
                                    "device": val_name,
                                    "signature": data_repr[:64],
                                    "description": f"Mounted Volume: {val_name}",
                                },
                                now,
                                0.3,
                            )
                            count += 1
            except Exception:
                logger.debug("MountedDevices extraction skipped or unavailable")

            return count
        except Exception:
            logger.exception("Failed USB history extraction")
            return count

    def extract_network_history(self) -> int:
        """Extract Network list profiles and active interfaces from registry."""
        count = 0
        now = datetime.now(UTC).isoformat()
        if winreg is None:
            logger.info("winreg not available on this platform; skipping network history extraction")
            return count

        try:
            # 1. Network Profiles (SSID / Wired)
            net_profiles_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, net_profiles_path, 0, winreg.KEY_READ) as net_key:
                    sub_count, _, _ = winreg.QueryInfoKey(net_key)
                    for i in range(sub_count):
                        guid = winreg.EnumKey(net_key, i)
                        guid_path = f"{net_profiles_path}\\{guid}"
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, guid_path, 0, winreg.KEY_READ) as profile_key:
                                prof_name = "Unknown"
                                try:
                                    prof_name = winreg.QueryValueEx(profile_key, "ProfileName")[0]
                                except Exception:
                                    pass
                                self.db.insert_artifact(
                                    "registry",
                                    "network_profile",
                                    f"HKLM\\{guid_path}",
                                    {
                                        "guid": guid,
                                        "profile_name": prof_name,
                                        "description": f"Network Profile: {prof_name} ({guid})",
                                    },
                                    now,
                                    0.35,
                                )
                                count += 1
                        except Exception:
                            logger.debug("Failed reading profile subkey %s", guid)
            except PermissionError:
                logger.info("NetworkList\\Profiles requires elevated privileges; recording status")
                self.db.insert_artifact(
                    "registry",
                    "network_profile_status",
                    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles",
                    {
                        "message": "NetworkList\\Profiles is restricted to elevated Administrator context.",
                        "status": "elevated_required",
                    },
                    now,
                    0.2,
                )
                count += 1
            except FileNotFoundError:
                logger.debug("NetworkList\\Profiles not found")

            # 2. Network Interfaces
            interfaces_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, interfaces_path, 0, winreg.KEY_READ) as if_key:
                    if_count, _, _ = winreg.QueryInfoKey(if_key)
                    for i in range(if_count):
                        if_guid = winreg.EnumKey(if_key, i)
                        if_sub_path = f"{interfaces_path}\\{if_guid}"
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, if_sub_path, 0, winreg.KEY_READ) as sub_key:
                                ip_addr = ""
                                dhcp_ip = ""
                                domain = ""
                                try:
                                    ip_addr = winreg.QueryValueEx(sub_key, "IPAddress")[0]
                                except Exception:
                                    pass
                                try:
                                    dhcp_ip = winreg.QueryValueEx(sub_key, "DhcpIPAddress")[0]
                                except Exception:
                                    pass
                                try:
                                    domain = winreg.QueryValueEx(sub_key, "Domain")[0]
                                except Exception:
                                    pass

                                active_ip = dhcp_ip or (ip_addr[0] if isinstance(ip_addr, list) and ip_addr else ip_addr)
                                if active_ip and active_ip != "0.0.0.0":
                                    self.db.insert_artifact(
                                        "registry",
                                        "network_interface",
                                        f"HKLM\\{if_sub_path}",
                                        {
                                            "interface_guid": if_guid,
                                            "ip_address": active_ip,
                                            "domain": domain,
                                            "description": f"TCP/IP Interface {if_guid} (IP: {active_ip})",
                                        },
                                        now,
                                        0.3,
                                    )
                                    count += 1
                        except Exception:
                            logger.debug("Failed reading interface subkey %s", if_guid)
            except Exception:
                logger.debug("TCP/IP Interfaces enumeration skipped or unavailable")

            return count
        except Exception:
            logger.exception("Failed network history extraction")
            return count

    def extract_autorun_keys(self) -> int:
        """Enumerate autorun and persistence keys across HKCU and HKLM."""
        count = 0
        now = datetime.now(UTC).isoformat()
        if winreg is None:
            logger.info("winreg not available on this platform; skipping autorun extraction")
            return count

        run_targets = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\WOW6432Node\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\WOW6432Node\\RunOnce"),
        ]

        suspicious_markers = [
            "appdata",
            "temp",
            "public",
            "powershell",
            "cmd.exe",
            "wscript",
            "cscript",
            "mshta",
            "rundll32",
            "-enc",
            "-encodedcommand",
            "downloadstring",
            ".vbs",
            ".bat",
            ".ps1",
        ]

        try:
            for hive, subkey_path, label in run_targets:
                try:
                    with winreg.OpenKey(hive, subkey_path, 0, winreg.KEY_READ) as key:
                        _, val_count, _ = winreg.QueryInfoKey(key)
                        for i in range(val_count):
                            name, cmd, _ = winreg.EnumValue(key, i)
                            cmd_str = str(cmd)
                            cmd_lower = cmd_str.lower()

                            is_suspicious = any(marker in cmd_lower for marker in suspicious_markers)
                            risk = 0.85 if is_suspicious else 0.25

                            self.db.insert_artifact(
                                "registry",
                                "autorun_key",
                                f"{label}\\{name}",
                                {
                                    "name": name,
                                    "command": cmd_str,
                                    "location": label,
                                    "suspicious": is_suspicious,
                                    "description": f"Autorun Entry: {name} -> {cmd_str}",
                                },
                                now,
                                risk,
                            )
                            count += 1

                            if is_suspicious:
                                self.db.insert_antiforensic(
                                    "WIPING_TOOL_AUTORUN_SCAN",
                                    f"Suspicious persistence autorun entry found in {label}: {name}",
                                    now,
                                    "HIGH",
                                    f"Name={name}; Command={cmd_str}",
                                )
                except FileNotFoundError:
                    logger.debug("Autorun key %s not found", label)
                except PermissionError:
                    logger.warning("Permission denied reading %s", label)
                except Exception:
                    logger.debug("Error enumerating autorun key %s", label)

            return count
        except Exception:
            logger.exception("Failed autorun extraction")
            return count

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
