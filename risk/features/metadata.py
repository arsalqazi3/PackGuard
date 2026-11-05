from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _days_since(iso: Optional[str], now: datetime) -> int:
    if not iso:
        return 0
    moment = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return max(0, (now - moment).days)


def extract_metadata_features(signals: Dict[str, Any]) -> Dict[str, Any]:
    """
    Turns the gateway's exists_on_pypi and metadata signals into model features.
    """
    if not signals.get("exists_on_pypi"):
        return {
            "exists_on_pypi": 0,
            "package_age_days": 0,
            "total_releases": 0,
            "days_since_last_release": 9999,
            "maintainer_count": 0,
            "has_repository_url": 0,
            "has_documentation_url": 0,
            "description_length": 0
        }

    meta = signals.get("metadata") or {}
    now = datetime.now(timezone.utc)
    return {
        "exists_on_pypi": 1,
        "package_age_days": _days_since(meta.get("first_upload"), now),
        "total_releases": int(meta.get("releases", 0)),
        "days_since_last_release": _days_since(meta.get("latest_upload"), now),
        "maintainer_count": 1 if meta.get("author") else 0,
        "has_repository_url": 1 if meta.get("has_repository") else 0,
        "has_documentation_url": 1 if meta.get("has_documentation") else 0,
        "description_length": int(meta.get("description_length", 0))
    }
