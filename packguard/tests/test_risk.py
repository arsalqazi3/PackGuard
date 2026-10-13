import pytest
from packguard.risk.features.lexical import (
    extract_lexical_features,
    calculate_shannon_entropy,
    check_ai_affixes,
    normalize_package_name
)
from packguard.risk.models.baseline import RuleBasedBaseline
from packguard.risk.service import score_package

def test_normalization():
    assert normalize_package_name("Flask_JWT.Helper") == "flask-jwt-helper"
    assert normalize_package_name("Requests") == "requests"

def test_ai_affixes():
    assert check_ai_affixes("flask-jwt-helper") == 1
    assert check_ai_affixes("requests-utils") == 1
    assert check_ai_affixes("numpy") == 0

def test_entropy():
    e1 = calculate_shannon_entropy("aaaaaa")
    e2 = calculate_shannon_entropy("abcdef")
    assert e1 == 0.0
    assert e2 > e1

def test_typosquat_detection():
    lex_clean = extract_lexical_features("requests")
    assert lex_clean["min_edit_distance_popular"] == 0.0
    assert lex_clean["similarity_ratio_popular"] == 100.0

    lex_typo = extract_lexical_features("reqeusts")
    assert lex_typo["min_edit_distance_popular"] <= 2.0
    assert lex_typo["similarity_ratio_popular"] >= 80.0

def test_baseline_scoring():
    baseline = RuleBasedBaseline()
    
    # Safe package simulation
    safe_features = {
        "exists_on_pypi": 1,
        "package_age_days": 1000,
        "total_releases": 20,
        "has_repository_url": 1,
        "ai_affix_match": 0,
        "min_edit_distance_popular": 0.0
    }
    safe_res = baseline.score_single(safe_features)
    assert safe_res["decision"] == "allow"
    assert safe_res["score"] <= 0.35

    # Dangerous package simulation
    danger_features = {
        "exists_on_pypi": 0,
        "package_age_days": 0,
        "ai_affix_match": 1,
        "min_edit_distance_popular": 2.0,
        "similarity_ratio_popular": 85.0
    }
    danger_res = baseline.score_single(danger_features)
    assert danger_res["decision"] == "block"
    assert danger_res["score"] >= 0.70

def test_score_package_service():
    res = score_package("requests")
    assert res["decision"] == "allow"
    assert isinstance(res["score"], float)
    assert isinstance(res["reasons"], list)
    assert "signals" in res
