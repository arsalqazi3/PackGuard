import sqlite3
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Set
import httpx
from packguard.risk.config import METADATA_CACHE_DB, PYPI_MASTER_LIST_PATH

logger = logging.getLogger(__name__)

class PyPICache:
    """
    Persistent SQLite-backed cache for PyPI package metadata with offline fallback.
    Avoids rate-limiting, network failures, and redundant HTTP requests.
    """
    _offline_index_loaded = False
    _offline_valid_names: Set[str] = set()

    def __init__(self, db_path=METADATA_CACHE_DB):
        self.db_path = str(db_path)
        self._init_db()
        self._ensure_offline_index()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pypi_metadata (
                    package_name TEXT PRIMARY KEY,
                    [exists] INTEGER NOT NULL,
                    raw_data TEXT,
                    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def _ensure_offline_index(self):
        """Loads offline master index (500k packages) into a set for O(1) instant resolution."""
        if not PyPICache._offline_index_loaded and PYPI_MASTER_LIST_PATH.exists():
            try:
                valid_set = set()
                with open(PYPI_MASTER_LIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        name = line.strip().lower()
                        if name:
                            valid_set.add(name)
                PyPICache._offline_valid_names = valid_set
                PyPICache._offline_index_loaded = True
                logger.info(f"Loaded {len(valid_set)} offline PyPI package names.")
            except Exception as e:
                logger.warning(f"Failed to load offline index: {e}")

    def get(self, package_name: str) -> Optional[Dict[str, Any]]:
        norm_name = package_name.strip().lower()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT [exists], raw_data FROM pypi_metadata WHERE package_name = ?",
                (norm_name,)
            )
            row = cursor.fetchone()
            if row:
                exists_flag, raw_json = row
                if not exists_flag:
                    return {"exists": False, "name": norm_name}
                try:
                    data = json.loads(raw_json)
                    data["exists"] = True
                    return data
                except Exception as e:
                    logger.warning(f"Error parsing cached json for {norm_name}: {e}")
                    return None
        return None

    def set(self, package_name: str, exists: bool, data: Optional[Dict[str, Any]] = None):
        norm_name = package_name.strip().lower()
        raw_json = json.dumps(data) if data is not None else ""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO pypi_metadata (package_name, [exists], raw_data, fetched_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (norm_name, 1 if exists else 0, raw_json)
            )
            conn.commit()

    def fetch_live_metadata(self, package_name: str, allow_network: bool = False, timeout: float = 3.0) -> Dict[str, Any]:
        """
        Fetches metadata for package_name.
        Priority:
        1. SQLite Cache (0.1ms)
        2. Offline Master Corpus (0.01ms) - avoids network lag and rate limiting
        3. Optional Live PyPI JSON API
        """
        norm_name = package_name.strip().lower()

        # 1. SQLite cache check
        cached = self.get(norm_name)
        if cached is not None:
            return cached

        # 2. Check offline master list
        if PyPICache._offline_index_loaded:
            is_valid = norm_name in PyPICache._offline_valid_names
            if not is_valid:
                # Confirmed non-existent on PyPI
                res = {"exists": False, "name": norm_name}
                self.set(norm_name, exists=False, data=res)
                return res
            else:
                # Confirmed existing on PyPI - construct offline profile
                meta = {
                    "name": norm_name,
                    "exists": True,
                    "package_age_days": 750,  # Established package default
                    "total_releases": 12,
                    "days_since_last_release": 60,
                    "maintainer_count": 1,
                    "has_repository_url": True,
                    "has_documentation_url": True,
                    "description_length": 1500
                }
                self.set(norm_name, exists=True, data=meta)
                return meta

        # 3. Live network call if allowed
        if allow_network:
            url = f"https://pypi.org/pypi/{norm_name}/json"
            try:
                with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                    resp = client.get(url)
                    if resp.status_code == 404:
                        self.set(norm_name, exists=False, data={"name": norm_name})
                        return {"exists": False, "name": norm_name}
                    elif resp.status_code == 200:
                        json_data = resp.json()
                        parsed = self._extract_relevant_metadata(json_data, norm_name)
                        parsed["exists"] = True
                        self.set(norm_name, exists=True, data=parsed)
                        return parsed
            except Exception as e:
                logger.warning(f"Network error fetching {norm_name}: {e}")

        return {"exists": False, "name": norm_name}

    def _extract_relevant_metadata(self, raw_pypi_json: Dict[str, Any], norm_name: str) -> Dict[str, Any]:
        info = raw_pypi_json.get("info", {})
        releases = raw_pypi_json.get("releases", {})
        release_versions = [v for v in releases.keys() if releases[v]]

        all_upload_times = []
        for v, files in releases.items():
            for f in files:
                upload_time = f.get("upload_time_iso_8601") or f.get("upload_time")
                if upload_time:
                    try:
                        dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                        all_upload_times.append(dt)
                    except Exception:
                        pass

        now = datetime.now(timezone.utc)
        if all_upload_times:
            all_upload_times.sort()
            package_age_days = max(0, (now - all_upload_times[0]).days)
            days_since_last_release = max(0, (now - all_upload_times[-1]).days)
        else:
            package_age_days = 0
            days_since_last_release = 0

        project_urls = info.get("project_urls") or {}
        home_page = info.get("home_page") or ""
        description = info.get("description") or ""

        has_repo = any("github.com" in str(u).lower() or "gitlab.com" in str(u).lower() 
                       for u in list(project_urls.values()) + [home_page])
        has_docs = any("doc" in str(k).lower() or "readthedocs" in str(u).lower() 
                       for k, u in project_urls.items())

        return {
            "name": norm_name,
            "version": info.get("version", "0.0.0"),
            "description_length": len(description),
            "package_age_days": package_age_days,
            "total_releases": len(release_versions),
            "days_since_last_release": days_since_last_release,
            "maintainer_count": 1 if info.get("author") or info.get("maintainer") else 0,
            "has_repository_url": has_repo,
            "has_documentation_url": has_docs
        }
