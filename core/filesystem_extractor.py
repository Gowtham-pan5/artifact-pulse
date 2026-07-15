"""Filesystem artifact extraction module for Artifact-Pulse."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import logging
from pathlib import Path
import shutil
import sqlite3
from tempfile import NamedTemporaryFile
from typing import Dict

from config import (
    ANTIFORENSIC_TOOLS,
    CHROME_HISTORY_PATHS,
    FIREFOX_PROFILE_PATH,
    LNK_RECENT_PATH,
    PREFETCH_PATH,
    SUSPICIOUS_EXTENSIONS,
    SUSPICIOUS_URLS,
    USER_PROFILE,
)
from database.db_manager import DBManager

logger = logging.getLogger(__name__)


class FilesystemExtractor:
    """Extract endpoint file-system artifacts and persist them in DB."""

    def __init__(self, db: DBManager) -> None:
        """Initialize extractor with database manager."""
        try:
            self.db = db
        except Exception:
            logger.exception("Failed to initialize FilesystemExtractor")
            raise

    def _chrome_time_to_iso(self, micros: int) -> str:
        """Convert Chrome WebKit timestamp to UTC ISO string."""
        try:
            base = datetime(1601, 1, 1, tzinfo=UTC)
            return (base + timedelta(microseconds=micros)).isoformat()
        except Exception:
            logger.exception("Failed converting Chrome timestamp")
            return datetime.now(UTC).isoformat()

    def extract_chrome_history(self) -> int:
        """Extract Chrome browsing history from profile databases."""
        count = 0
        try:
            for db_path in CHROME_HISTORY_PATHS:
                if not db_path.exists():
                    continue
                with NamedTemporaryFile(delete=False, suffix=".sqlite") as tmp:
                    temp_path = Path(tmp.name)
                shutil.copy2(db_path, temp_path)
                with sqlite3.connect(temp_path) as conn:
                    rows = conn.execute(
                        "SELECT url, title, visit_count, last_visit_time FROM urls"
                    ).fetchall()
                for row in rows:
                    url = row[0] or ""
                    risk = 0.8 if any(s in url.lower() for s in SUSPICIOUS_URLS) else 0.2
                    payload = {
                        "url": url,
                        "title": row[1] or "",
                        "visit_count": row[2] or 0,
                        "last_visit_time": self._chrome_time_to_iso(int(row[3] or 0)),
                    }
                    self.db.insert_artifact(
                        "filesystem",
                        "browser_history_chrome",
                        str(db_path),
                        payload,
                        payload["last_visit_time"],
                        risk,
                    )
                    count += 1
                try:
                    conn.close()
                except Exception:
                    pass
                try:
                    temp_path.unlink(missing_ok=True)
                except Exception:
                    logger.warning("Failed to delete temp path: %s", temp_path)
            return count
        except Exception:
            logger.exception("Failed Chrome history extraction")
            return count

    def extract_firefox_history(self) -> int:
        """Extract Firefox history from all user profiles."""
        count = 0
        try:
            if not FIREFOX_PROFILE_PATH.exists():
                return 0
            for profile in FIREFOX_PROFILE_PATH.glob("*.default*"):
                places = profile / "places.sqlite"
                if not places.exists():
                    continue
                with sqlite3.connect(places) as conn:
                    rows = conn.execute(
                        "SELECT url, title, last_visit_date FROM moz_places"
                    ).fetchall()
                for row in rows:
                    ts = datetime.fromtimestamp((row[2] or 0) / 1_000_000, tz=UTC).isoformat()
                    payload = {"url": row[0] or "", "title": row[1] or "", "last_visit": ts}
                    self.db.insert_artifact(
                        "filesystem", "browser_history_firefox", str(places), payload, ts, 0.2
                    )
                    count += 1
            return count
        except Exception:
            logger.exception("Failed Firefox extraction")
            return count

    def extract_prefetch(self) -> int:
        """Extract metadata from Windows prefetch files."""
        count = 0
        try:
            if not PREFETCH_PATH.exists():
                return 0
            for pf in PREFETCH_PATH.glob("*.pf"):
                exe_name = pf.name.split("-")[0].upper()
                risk = 0.9 if exe_name in ANTIFORENSIC_TOOLS else 0.3
                payload = {
                    "filename": pf.name,
                    "exe_name": exe_name,
                    "mtime": datetime.fromtimestamp(pf.stat().st_mtime, tz=UTC).isoformat(),
                    "size_bytes": pf.stat().st_size,
                }
                self.db.insert_artifact(
                    "filesystem", "prefetch", str(pf), payload, payload["mtime"], risk
                )
                count += 1
            return count
        except Exception:
            logger.exception("Failed prefetch extraction")
            return count

    def extract_lnk_files(self) -> int:
        """Extract metadata from recent shortcut files."""
        count = 0
        try:
            folders = [LNK_RECENT_PATH, LNK_RECENT_PATH.parent / "Office" / "Recent"]
            for folder in folders:
                if not folder.exists():
                    continue
                for lnk in folder.glob("*.lnk"):
                    payload = {
                        "filename": lnk.name,
                        "target_stem": lnk.stem,
                        "mtime": datetime.fromtimestamp(
                            lnk.stat().st_mtime, tz=UTC
                        ).isoformat(),
                    }
                    self.db.insert_artifact(
                        "filesystem", "lnk_recent", str(lnk), payload, payload["mtime"], 0.3
                    )
                    count += 1
            return count
        except Exception:
            logger.exception("Failed LNK extraction")
            return count

    def extract_recycle_bin(self) -> int:
        """Extract recycle-bin metadata files from common drive roots."""
        count = 0
        try:
            for drive in [Path("C:/"), Path("D:/"), Path("E:/")]:
                rb = drive / "$Recycle.Bin"
                if not rb.exists():
                    continue
                for i_file in rb.rglob("$I*"):
                    payload = {
                        "filename": i_file.name,
                        "original_path": "unknown",
                        "size": i_file.stat().st_size,
                        "deletion_time": datetime.fromtimestamp(
                            i_file.stat().st_mtime, tz=UTC
                        ).isoformat(),
                    }
                    self.db.insert_artifact(
                        "filesystem",
                        "recycle_bin",
                        str(i_file),
                        payload,
                        payload["deletion_time"],
                        0.5,
                    )
                    count += 1
            return count
        except Exception:
            logger.exception("Failed recycle-bin extraction")
            return count

    def extract_downloads(self) -> int:
        """Extract metadata from user's Downloads folder."""
        count = 0
        try:
            downloads = USER_PROFILE / "Downloads"
            if not downloads.exists():
                return 0
            risky_ext = set(
                SUSPICIOUS_EXTENSIONS["archives"]
                + SUSPICIOUS_EXTENSIONS["executables"]
                + SUSPICIOUS_EXTENSIONS["scripts"]
            )
            for item in downloads.iterdir():
                if not item.is_file():
                    continue
                ext = item.suffix.lower()
                risk = 0.7 if ext in risky_ext else 0.2
                payload = {
                    "filename": item.name,
                    "extension": ext,
                    "size": item.stat().st_size,
                    "mtime": datetime.fromtimestamp(item.stat().st_mtime, tz=UTC).isoformat(),
                }
                self.db.insert_artifact(
                    "filesystem", "downloads", str(item), payload, payload["mtime"], risk
                )
                count += 1
            return count
        except Exception:
            logger.exception("Failed downloads extraction")
            return count

    def extract_jump_lists(self) -> int:
        """Extract metadata for jump-list destination files."""
        count = 0
        try:
            jump = LNK_RECENT_PATH / "AutomaticDestinations"
            if not jump.exists():
                return 0
            for item in jump.glob("*.automaticDestinations-ms"):
                payload = {
                    "filename": item.name,
                    "size": item.stat().st_size,
                    "mtime": datetime.fromtimestamp(item.stat().st_mtime, tz=UTC).isoformat(),
                }
                self.db.insert_artifact(
                    "filesystem", "jump_list", str(item), payload, payload["mtime"], 0.4
                )
                count += 1
            return count
        except Exception:
            logger.exception("Failed jump-list extraction")
            return count

    def run_all(self) -> Dict[str, int]:
        """Run all filesystem extraction routines and return summary counts."""
        try:
            return {
                "chrome": self.extract_chrome_history(),
                "firefox": self.extract_firefox_history(),
                "prefetch": self.extract_prefetch(),
                "lnk": self.extract_lnk_files(),
                "recycle_bin": self.extract_recycle_bin(),
                "downloads": self.extract_downloads(),
                "jump_lists": self.extract_jump_lists(),
            }
        except Exception:
            logger.exception("Filesystem run_all failed")
            return {}
