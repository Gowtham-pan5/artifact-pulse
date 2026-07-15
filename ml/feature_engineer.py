"""Feature engineering utilities for Artifact-Pulse ML models."""

from __future__ import annotations

from datetime import UTC, datetime
import logging
import math
from pathlib import Path
import re
from typing import Any, Dict, List, Tuple

import pandas as pd

logger = logging.getLogger(__name__)


class FeatureEngineer:
    """Convert forensic artifacts into robust numeric features."""

    SUSPICIOUS_URLS = [
        "wetransfer",
        "mega.nz",
        "anonfiles",
        "transfer.sh",
        "gofile",
        "pastebin",
        "onion",
        "temp-mail",
        "guerrilla",
    ]
    SUSPICIOUS_EXTENSIONS = [
        ".exe",
        ".ps1",
        ".bat",
        ".vbs",
        ".zip",
        ".rar",
        ".7z",
        ".dll",
    ]
    CREDENTIAL_PATTERNS = [
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "token",
        "credential",
        "private_key",
    ]

    def artifact_to_features(self, artifact: Dict[str, Any]) -> Dict[str, float]:
        """Build a full 30-feature dictionary from a single artifact."""
        features = self._zero_features()
        try:
            dt = self._parse_timestamp(artifact.get("event_time"))
            hour = float(dt.hour)
            risk = float(artifact.get("risk_weight", 0.0) or 0.0)
            layer = str(artifact.get("source_layer", "") or "")
            artifact_type = str(artifact.get("artifact_type", "") or "")
            content = str(artifact.get("content", "") or "")
            source_path = str(artifact.get("source_path", "") or "")

            features.update(self._extract_temporal(dt))
            features.update(self._extract_layer(layer))
            features.update(self._extract_risk(risk))
            features.update(self._extract_artifact_type(artifact_type))
            features.update(self._extract_behavioral(content, source_path))
            features.update(
                self._extract_contextual(hour, risk, source_path, content)
            )
            return {k: float(v) for k, v in features.items()}
        except Exception:
            logger.exception("Failed converting artifact to features")
            return features

    def artifacts_to_matrix(
        self, artifacts: List[Dict[str, Any]]
    ) -> Tuple[pd.DataFrame, List[str]]:
        """Convert artifacts list into DataFrame matrix and artifact ids."""
        try:
            if not artifacts:
                return pd.DataFrame(columns=list(self._zero_features().keys())), []
            rows: List[Dict[str, float]] = []
            artifact_ids: List[str] = []
            for artifact in artifacts:
                rows.append(self.artifact_to_features(artifact))
                artifact_ids.append(str(artifact.get("artifact_id", "UNKNOWN")))
            return pd.DataFrame(rows).fillna(0.0), artifact_ids
        except Exception:
            logger.exception("Failed creating feature matrix")
            return pd.DataFrame(columns=list(self._zero_features().keys())), []

    def _parse_timestamp(self, ts_str: Any) -> datetime:
        """Parse timestamp safely and fallback to current UTC time."""
        try:
            if ts_str is None:
                return datetime.now(UTC)
            if isinstance(ts_str, datetime):
                if ts_str.tzinfo is None:
                    return ts_str.replace(tzinfo=UTC)
                return ts_str.astimezone(UTC)
            parsed = pd.to_datetime(ts_str, utc=True, errors="coerce")
            if pd.isna(parsed):
                return datetime.now(UTC)
            return parsed.to_pydatetime()
        except Exception:
            logger.exception("Failed parsing timestamp")
            return datetime.now(UTC)

    def _extract_temporal(self, dt: datetime) -> Dict[str, float]:
        """Extract temporal feature group."""
        try:
            hour = float(dt.hour)
            minute = float(dt.minute)
            day_of_week = float(dt.weekday())
            is_after_hours = float(hour < 8 or hour > 20)
            is_weekend = float(day_of_week >= 5)
            return {
                "hour": hour,
                "minute": minute,
                "day_of_week": day_of_week,
                "is_after_hours": is_after_hours,
                "is_weekend": is_weekend,
            }
        except Exception:
            logger.exception("Failed extracting temporal features")
            return {k: 0.0 for k in ["hour", "minute", "day_of_week", "is_after_hours", "is_weekend"]}

    def _extract_layer(self, layer: str) -> Dict[str, float]:
        """Extract source-layer one-hot features."""
        try:
            s = layer.lower()
            return {
                "is_filesystem": float(s == "filesystem"),
                "is_system_events": float(s == "system_events"),
                "is_process_snapshot": float(s == "process_snapshot"),
                "is_registry": float(s == "registry"),
                "is_antiforensic": float(s == "antiforensic"),
            }
        except Exception:
            logger.exception("Failed extracting layer features")
            return {
                "is_filesystem": 0.0,
                "is_system_events": 0.0,
                "is_process_snapshot": 0.0,
                "is_registry": 0.0,
                "is_antiforensic": 0.0,
            }

    def _extract_risk(self, risk: float) -> Dict[str, float]:
        """Extract risk-derived features."""
        try:
            clamped = max(0.0, min(float(risk), 1.0))
            return {
                "risk_weight": clamped,
                "is_high_risk": float(clamped >= 0.7),
                "is_medium_risk": float(0.4 <= clamped < 0.7),
                "is_low_risk": float(clamped < 0.4),
                "risk_squared": clamped * clamped,
            }
        except Exception:
            logger.exception("Failed extracting risk features")
            return {
                "risk_weight": 0.0,
                "is_high_risk": 0.0,
                "is_medium_risk": 0.0,
                "is_low_risk": 0.0,
                "risk_squared": 0.0,
            }

    def _extract_artifact_type(self, atype: str) -> Dict[str, float]:
        """Extract artifact-type one-hot features."""
        try:
            s = atype.lower()
            return {
                "is_browser_history": float("browser_history" in s),
                "is_prefetch": float("prefetch" in s),
                "is_usb_device": float("usb_device" in s),
                "is_network_conn": float("network_connection" in s),
                "is_process_artifact": float("process" in s),
            }
        except Exception:
            logger.exception("Failed extracting artifact-type features")
            return {
                "is_browser_history": 0.0,
                "is_prefetch": 0.0,
                "is_usb_device": 0.0,
                "is_network_conn": 0.0,
                "is_process_artifact": 0.0,
            }

    def _extract_behavioral(self, content: str, path: str) -> Dict[str, float]:
        """Extract behavioral content/path pattern features."""
        try:
            content_lower = content.lower()
            path_lower = path.lower()
            content_length = float(min(len(content), 10000))
            has_suspicious_url = float(
                any(token in content_lower for token in self.SUSPICIOUS_URLS)
            )
            has_suspicious_ext = float(
                any(path_lower.endswith(ext) for ext in self.SUSPICIOUS_EXTENSIONS)
            )
            has_credential_pattern = float(
                any(token in content_lower for token in self.CREDENTIAL_PATTERNS)
            )
            has_ip_address = float(
                bool(re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content_lower))
            )
            return {
                "content_length": content_length,
                "has_suspicious_url": has_suspicious_url,
                "has_suspicious_ext": has_suspicious_ext,
                "has_credential_pattern": has_credential_pattern,
                "has_ip_address": has_ip_address,
            }
        except Exception:
            logger.exception("Failed extracting behavioral features")
            return {
                "content_length": 0.0,
                "has_suspicious_url": 0.0,
                "has_suspicious_ext": 0.0,
                "has_credential_pattern": 0.0,
                "has_ip_address": 0.0,
            }

    def _extract_contextual(
        self, hour: float, risk: float, path: str, content: str
    ) -> Dict[str, float]:
        """Extract contextual and interaction features."""
        try:
            hour_sin = math.sin((2.0 * math.pi * hour) / 24.0)
            hour_cos = math.cos((2.0 * math.pi * hour) / 24.0)
            is_after_hours = float(hour < 8 or hour > 20)
            risk_x_afterhours = max(0.0, min(risk, 1.0)) * is_after_hours
            is_public_ip = self._contains_public_ip(content)
            source_path_depth = self._path_depth(path)
            return {
                "hour_sin": float(hour_sin),
                "hour_cos": float(hour_cos),
                "risk_x_afterhours": float(risk_x_afterhours),
                "is_public_ip": float(is_public_ip),
                "source_path_depth": float(source_path_depth),
            }
        except Exception:
            logger.exception("Failed extracting contextual features")
            return {
                "hour_sin": 0.0,
                "hour_cos": 0.0,
                "risk_x_afterhours": 0.0,
                "is_public_ip": 0.0,
                "source_path_depth": 0.0,
            }

    def _contains_public_ip(self, text: str) -> bool:
        """Return true when any non-RFC1918 IPv4 appears in text."""
        try:
            for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
                parts = [int(p) for p in match.split(".")]
                if any(p < 0 or p > 255 for p in parts):
                    continue
                if parts[0] == 10:
                    continue
                if parts[0] == 192 and parts[1] == 168:
                    continue
                if parts[0] == 172 and 16 <= parts[1] <= 31:
                    continue
                return True
            return False
        except Exception:
            logger.exception("Failed public IP check")
            return False

    def _path_depth(self, path: str) -> int:
        """Calculate capped path depth for contextual signal."""
        try:
            if not path:
                return 0
            p = Path(path)
            return min(len(p.parts), 10)
        except Exception:
            logger.exception("Failed path depth extraction")
            return 0

    def _zero_features(self) -> Dict[str, float]:
        """Return canonical zero-filled feature template."""
        try:
            keys = [
                "hour",
                "minute",
                "day_of_week",
                "is_after_hours",
                "is_weekend",
                "is_filesystem",
                "is_system_events",
                "is_process_snapshot",
                "is_registry",
                "is_antiforensic",
                "risk_weight",
                "is_high_risk",
                "is_medium_risk",
                "is_low_risk",
                "risk_squared",
                "is_browser_history",
                "is_prefetch",
                "is_usb_device",
                "is_network_conn",
                "is_process_artifact",
                "content_length",
                "has_suspicious_url",
                "has_suspicious_ext",
                "has_credential_pattern",
                "has_ip_address",
                "hour_sin",
                "hour_cos",
                "risk_x_afterhours",
                "is_public_ip",
                "source_path_depth",
            ]
            return {k: 0.0 for k in keys}
        except Exception:
            logger.exception("Failed generating zero feature template")
            return {}


if __name__ == "__main__":
    sample = {
        "artifact_id": "AP-SAMPLE-000001",
        "event_time": datetime.now(UTC).isoformat(),
        "source_layer": "filesystem",
        "artifact_type": "download_file",
        "source_path": "C:/Users/Test/Downloads/sample.exe",
        "content": "password token to wetransfer 8.8.8.8",
        "risk_weight": 0.8,
    }
    engine = FeatureEngineer()
    logger.info("Feature sample: %s", engine.artifact_to_features(sample))

