from typing import Dict, Any, Optional

def extract_metadata_features(metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Extracts numerical and categorical signals from PyPI metadata snapshot.
    Handles missing / null values gracefully.
    """
    if not metadata or not metadata.get("exists", False):
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

    return {
        "exists_on_pypi": 1,
        "package_age_days": int(metadata.get("package_age_days", 0)),
        "total_releases": int(metadata.get("total_releases", 0)),
        "days_since_last_release": int(metadata.get("days_since_last_release", 0)),
        "maintainer_count": int(metadata.get("maintainer_count", 0)),
        "has_repository_url": 1 if metadata.get("has_repository_url") else 0,
        "has_documentation_url": 1 if metadata.get("has_documentation_url") else 0,
        "description_length": int(metadata.get("description_length", 0))
    }
