import os
from pathlib import Path

# Base Paths
RISK_MODULE_DIR = Path(__file__).resolve().parent
PACKGUARD_ROOT = RISK_MODULE_DIR.parent
PROJECT_ROOT = PACKGUARD_ROOT.parent

# Data Directories
DATA_DIR = RISK_MODULE_DIR / "data"
CACHE_DIR = DATA_DIR / "cache"
GROUND_TRUTH_DIR = DATA_DIR / "ground_truth"
SAVED_MODELS_DIR = RISK_MODULE_DIR / "saved_models"

# External Reference Paths (from Zenodo / Spracklen Artifacts)
ZENODO_PYTHON_DATA = PROJECT_ROOT / "Zenodo dataset" / "Artifacts_Submission" / "Data" / "Python"
PYPI_MASTER_LIST_PATH = ZENODO_PYTHON_DATA / "pypi_package_names.csv"
FALSE_POSITIVES_PATH = ZENODO_PYTHON_DATA / "false_positive_packages.csv"

# Cache DB
METADATA_CACHE_DB = CACHE_DIR / "pypi_metadata_cache.sqlite"

# Typosquat / Reference Package Set Size
POPULAR_PACKAGES_COUNT = 5000
POPULAR_PACKAGES_CACHE_FILE = CACHE_DIR / "top_popular_packages.json"

# Common AI Hallucination Suffixes and Affixes observed in research
AI_SUSPICIOUS_AFFIXES = {
    "helper", "helpers", "util", "utils", "client", "wrapper", "wrappers",
    "tool", "tools", "sdk", "api", "core", "lib", "plugin", "plugins",
    "ext", "extension", "common", "base", "driver", "handler", "bridge"
}

# Decision Thresholds (Agreed upon in PackGuard FYP-1 Contract)
ALLOW_THRESHOLD = 0.35
BLOCK_THRESHOLD = 0.70  # Between 0.35 and 0.70 is 'warn'

# Feature names list for the XGBoost model
FEATURE_COLUMNS = [
    "exists_on_pypi",
    "name_length",
    "name_entropy",
    "has_hyphen_or_underscore",
    "ai_affix_match",
    "min_edit_distance_popular",
    "similarity_ratio_popular",
    "is_in_evidence_table",
    "evidence_model_frequency",
    "package_age_days",
    "total_releases",
    "days_since_last_release",
    "maintainer_count",
    "has_repository_url",
    "has_documentation_url",
    "description_length"
]
