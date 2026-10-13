import pandas as pd
from typing import Dict, Any, List, Optional
from packguard.risk.config import FEATURE_COLUMNS
from packguard.risk.features.lexical import extract_lexical_features, normalize_package_name
from packguard.risk.features.metadata import extract_metadata_features
from packguard.risk.dataset.pypi_cache import PyPICache

class RiskFeaturePipeline:
    """
    End-to-end feature extraction pipeline.
    Combines PyPI metadata, lexical signals, and evidence table lookups.
    """
    def __init__(self, pypi_cache: Optional[PyPICache] = None, evidence_lookup: Optional[Dict[str, int]] = None):
        self.pypi_cache = pypi_cache or PyPICache()
        self.evidence_lookup = evidence_lookup or {}

    def extract_single(self, package_name: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        norm_name = normalize_package_name(package_name)

        # 1. Fetch metadata if not passed
        if metadata is None:
            metadata = self.pypi_cache.fetch_live_metadata(norm_name)

        # 2. Extract feature components
        meta_feat = extract_metadata_features(metadata)
        lex_feat = extract_lexical_features(norm_name)

        # 3. Evidence table signals
        evidence_freq = self.evidence_lookup.get(norm_name, 0)
        evidence_hit = 1 if evidence_freq > 0 else 0

        features = {
            **meta_feat,
            **lex_feat,
            "is_in_evidence_table": evidence_hit,
            "evidence_model_frequency": evidence_freq
        }

        # Ensure exact column ordering
        ordered_features = {col: features.get(col, 0) for col in FEATURE_COLUMNS}
        return ordered_features

    def transform(self, package_names: List[str], metadata_list: Optional[List[Dict[str, Any]]] = None) -> pd.DataFrame:
        rows = []
        if metadata_list is None:
            metadata_list = [None] * len(package_names)

        for name, meta in zip(package_names, metadata_list):
            rows.append(self.extract_single(name, meta))

        return pd.DataFrame(rows, columns=FEATURE_COLUMNS)
