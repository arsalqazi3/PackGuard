"""
Feature extraction for PackGuard AI Risk Prediction.
Everything here runs inside the gateway, so it must not import pandas.
"""
from .lexical import extract_lexical_features, LexicalAnalyzer
from .metadata import extract_metadata_features
from .pipeline import extract_features

__all__ = [
    "extract_lexical_features",
    "LexicalAnalyzer",
    "extract_metadata_features",
    "extract_features"
]
