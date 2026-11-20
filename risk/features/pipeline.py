from typing import Any, Dict, Optional

from risk.config import FEATURE_COLUMNS
from risk.features.lexical import extract_lexical_features
from risk.features.metadata import extract_metadata_features


def extract_features(signals: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Combines name, metadata and evidence signals into one feature row.
    Training and live scoring both use this, so they always match.

    Returns None when the signals are not complete enough to score, for example
    when the PyPI lookup failed. Treating that as "not on PyPI" would block real
    packages every time the network has a problem.
    """
    name = signals.get("name")
    exists = signals.get("exists_on_pypi")
    if not name or exists is None or (exists and not signals.get("metadata")):
        return None

    evidence = signals.get("hallucination_evidence") or {}
    features = {
        **extract_metadata_features(signals),
        **extract_lexical_features(name),
        "is_in_evidence_table": 1 if evidence.get("count") else 0,
        "evidence_model_frequency": len(evidence.get("models") or [])
    }

    # Ensure exact column ordering
    return {col: features[col] for col in FEATURE_COLUMNS}
