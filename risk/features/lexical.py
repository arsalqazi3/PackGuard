import re
import math
from collections import Counter
from typing import Dict, Any, List, Set
from rapidfuzz import process, distance, fuzz
from core_guard.checks import load_top_packages
from risk.config import AI_SUSPICIOUS_AFFIXES

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
    Uses the same top packages list as Core Guard's typosquat check.
    """
    _popular_packages: List[str] = []
    _popular_set: Set[str] = set()

    def __init__(self):
        if not LexicalAnalyzer._popular_packages:
            LexicalAnalyzer._popular_packages = load_top_packages()
            LexicalAnalyzer._popular_set = set(LexicalAnalyzer._popular_packages)

    def compute_typosquat_signals(self, name: str) -> Dict[str, float]:
        """
        Computes minimum Levenshtein distance and maximum similarity ratio
        against the reference corpus of popular packages using candidate pruning.
        """
        norm_name = normalize_package_name(name)
        if not norm_name or not self._popular_packages:
            return {"min_edit_distance_popular": 99.0, "similarity_ratio_popular": 0.0}

        # Exact match O(1) check
        if norm_name in self._popular_set:
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
