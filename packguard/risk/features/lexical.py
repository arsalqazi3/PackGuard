import re
import math
import json
from collections import Counter
from typing import Dict, Any, List, Set, Optional
from rapidfuzz import process, distance, fuzz
from packguard.risk.config import (
    AI_SUSPICIOUS_AFFIXES,
    POPULAR_PACKAGES_COUNT,
    POPULAR_PACKAGES_CACHE_FILE,
    PYPI_MASTER_LIST_PATH
)

def normalize_package_name(name: str) -> str:
    """PEP 503 compliant package name normalization."""
    if not name or not isinstance(name, str):
        return ""
    return re.sub(r"[-_.]+", "-", name).strip().lower()

def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy of the string to measure randomness/complexity."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)

def check_ai_affixes(name: str, affixes: Set[str] = AI_SUSPICIOUS_AFFIXES) -> int:
    """
    Checks if package name contains known AI-hallucination patterns
    (e.g., 'flask-jwt-helper', 'requests-utils', 'crypto-py').
    Returns 1 if matched, else 0.
    """
    normalized = normalize_package_name(name)
    parts = set(re.split(r"[-_.]+", normalized))
    return 1 if bool(parts.intersection(affixes)) else 0


class LexicalAnalyzer:
    """
    Analyzes lexical characteristics, name entropy, AI hallucination affixes,
    and typosquatting edit distances against popular PyPI packages.
    """
    _instance = None
    _popular_packages: List[str] = []

    def __init__(self):
        if not LexicalAnalyzer._popular_packages:
            self._load_popular_packages()

    def _load_popular_packages(self):
        """Loads or builds the top popular PyPI reference set for typosquat detection."""
        if POPULAR_PACKAGES_CACHE_FILE.exists():
            try:
                with open(POPULAR_PACKAGES_CACHE_FILE, "r", encoding="utf-8") as f:
                    LexicalAnalyzer._popular_packages = json.load(f)
                    LexicalAnalyzer._popular_set = set(LexicalAnalyzer._popular_packages)
                    return
            except Exception:
                pass

        popular = []
        # Curated core popular packages seeded first
        seed_popular = [
            "requests", "numpy", "pandas", "urllib3", "six", "boto3", "botocore",
            "setuptools", "certifi", "pip", "idna", "charset-normalizer", "typing-extensions",
            "python-dateutil", "s3transfer", "wheel", "pytz", "rsa", "pyyaml", "packaging",
            "pytest", "click", "pydantic", "attrs", "cffi", "cryptography", "jinja2", "markupsafe",
            "scipy", "scikit-learn", "torch", "tensorflow", "fastapi", "flask", "django", "celery",
            "sqlalchemy", "redis", "pillow", "matplotlib", "seaborn", "tqdm", "httpx", "aiohttp",
            "psycopg2", "pyjwt", "werkzeug", "gunicorn", "uvicorn", "docker", "paramiko"
        ]
        popular.extend(seed_popular)

        # Load from pypi_package_names.csv if present to fill up to POPULAR_PACKAGES_COUNT
        if PYPI_MASTER_LIST_PATH.exists():
            try:
                with open(PYPI_MASTER_LIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        pkg = line.strip().lower()
                        if pkg and pkg not in popular:
                            popular.append(pkg)
                        if len(popular) >= POPULAR_PACKAGES_COUNT:
                            break
            except Exception:
                pass

        LexicalAnalyzer._popular_packages = popular
        LexicalAnalyzer._popular_set = set(popular)
        try:
            with open(POPULAR_PACKAGES_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(popular, f)
        except Exception:
            pass

    def compute_typosquat_signals(self, name: str) -> Dict[str, float]:
        """
        Computes minimum Levenshtein distance and maximum similarity ratio
        against the reference corpus of popular packages using candidate pruning.
        """
        norm_name = normalize_package_name(name)
        if not norm_name or not self._popular_packages:
            return {"min_edit_distance_popular": 99.0, "similarity_ratio_popular": 0.0}

        # Exact match O(1) check
        if norm_name in getattr(self, "_popular_set", set(self._popular_packages)):
            return {"min_edit_distance_popular": 0.0, "similarity_ratio_popular": 100.0}

        # Candidate pruning: only packages with length difference <= 2 can be typosquats
        n_len = len(norm_name)
        candidates = [p for p in self._popular_packages if abs(len(p) - n_len) <= 2]
        if not candidates:
            return {"min_edit_distance_popular": 99.0, "similarity_ratio_popular": 0.0}

        best_match = process.extractOne(
            norm_name,
            candidates,
            scorer=fuzz.ratio,
            score_cutoff=50.0
        )

        if best_match:
            match_name, score, _ = best_match
            edit_dist = distance.Levenshtein.distance(norm_name, match_name)
            return {
                "min_edit_distance_popular": float(edit_dist),
                "similarity_ratio_popular": float(score)
            }
        else:
            return {
                "min_edit_distance_popular": 99.0,
                "similarity_ratio_popular": 0.0
            }

    def analyze(self, name: str) -> Dict[str, Any]:
        norm_name = normalize_package_name(name)
        typo_signals = self.compute_typosquat_signals(norm_name)

        return {
            "name_length": len(norm_name),
            "name_entropy": calculate_shannon_entropy(norm_name),
            "has_hyphen_or_underscore": 1 if ("-" in norm_name or "_" in name) else 0,
            "ai_affix_match": check_ai_affixes(norm_name),
            **typo_signals
        }


def extract_lexical_features(package_name: str) -> Dict[str, Any]:
    analyzer = LexicalAnalyzer()
    return analyzer.analyze(package_name)
