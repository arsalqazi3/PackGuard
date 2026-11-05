from pathlib import Path

# Base Paths
RISK_MODULE_DIR = Path(__file__).resolve().parent
REPO_ROOT = RISK_MODULE_DIR.parent

# Data Directories
DATA_DIR = RISK_MODULE_DIR / "data"
CACHE_DIR = DATA_DIR / "cache"  # git ignored, only used while training
GROUND_TRUTH_DIR = DATA_DIR / "ground_truth"
SAVED_MODELS_DIR = RISK_MODULE_DIR / "saved_models"

# The model the gateway loads
MODEL_PATH = SAVED_MODELS_DIR / "packguard_xgboost.json"

# Signals collected for training, so a rerun does not fetch everything again
SIGNAL_CACHE_DB = CACHE_DIR / "training_signals.sqlite"

# External Reference Paths (from Zenodo / Spracklen Artifacts). Not committed.
ZENODO_PYTHON_DATA = REPO_ROOT / "Zenodo dataset" / "Artifacts_Submission" / "Data" / "Python"
PYPI_MASTER_LIST_PATH = ZENODO_PYTHON_DATA / "pypi_package_names.csv"

# Common AI Hallucination Suffixes and Affixes observed in research
AI_SUSPICIOUS_AFFIXES = {
    "helper", "helpers", "util", "utils", "client", "wrapper", "wrappers",
    "tool", "tools", "sdk", "api", "core", "lib", "plugin", "plugins",
    "ext", "extension", "common", "base", "driver", "handler", "bridge"
}

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
