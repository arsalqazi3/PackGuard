from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest

from core_guard import checks
from gateway import db
from gateway.evaluate import evaluate
from risk import model
from risk.config import FEATURE_COLUMNS
from risk.features.lexical import (
    calculate_shannon_entropy,
    check_ai_affixes,
    extract_lexical_features,
    normalize_package_name,
)
from risk.features.pipeline import extract_features
from risk.models.evaluator import ModelEvaluator
from risk.models.xgboost_model import PackGuardXGBoostModel


def iso_days_ago(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


ESTABLISHED = {
    "releases": 29,
    "first_upload": iso_days_ago(5000),
    "latest_upload": iso_days_ago(60),
    "has_repository": True,
    "has_documentation": True,
    "author": "someone",
    "description_length": 2000,
}


def established(name="six"):
    return {"name": name, "exists_on_pypi": True, "metadata": dict(ESTABLISHED), "typosquat_of": []}


@pytest.fixture(autouse=True)
def no_database(monkeypatch):
    monkeypatch.setattr(db, "DATABASE_URL", "")
    monkeypatch.setattr(db, "_pool", None)


# Name features


def test_normalization():
    assert normalize_package_name("Flask_JWT.Helper") == "flask-jwt-helper"
    assert normalize_package_name("Requests") == "requests"


def test_ai_affixes():
    assert check_ai_affixes("flask-jwt-helper") == 1
    assert check_ai_affixes("requests-utils") == 1
    assert check_ai_affixes("numpy") == 0


def test_entropy():
    assert calculate_shannon_entropy("aaaaaa") == 0.0
    assert calculate_shannon_entropy("abcdef") > 0.0


def test_typosquat_features_use_the_real_top_packages():
    clean = extract_lexical_features("requests")
    assert clean["min_edit_distance_popular"] == 0.0
    assert clean["similarity_ratio_popular"] == 100.0

    typo = extract_lexical_features("reqeusts")
    assert typo["min_edit_distance_popular"] <= 2.0
    assert typo["similarity_ratio_popular"] >= 80.0


# Features come from the gateway's signals


def test_features_from_signals():
    signals = established()
    signals["hallucination_evidence"] = {"count": 3, "models": ["a", "b"], "sources": ["spracklen"]}
    features = extract_features(signals)
    assert list(features) == FEATURE_COLUMNS
    assert features["exists_on_pypi"] == 1
    assert features["total_releases"] == 29
    assert features["package_age_days"] == 5000
    assert features["days_since_last_release"] == 60
    assert features["maintainer_count"] == 1
    assert features["has_repository_url"] == 1
    assert features["has_documentation_url"] == 1
    assert features["description_length"] == 2000
    assert features["is_in_evidence_table"] == 1
    assert features["evidence_model_frequency"] == 2


def test_features_for_missing_package():
    features = extract_features({"name": "reqeusts", "exists_on_pypi": False})
    assert features["exists_on_pypi"] == 0
    assert features["days_since_last_release"] == 9999


@pytest.mark.parametrize(
    "signals",
    [
        {"name": "six"},  # the PyPI lookup failed
        {"name": "six", "exists_on_pypi": True},  # the metadata lookup failed
        {"exists_on_pypi": False},  # no name
    ],
)
def test_incomplete_signals_are_not_scored(signals):
    assert extract_features(signals) is None
    assert model.score(signals) is None
    assert model.explain(signals) == []


# The saved model


def test_saved_model_scores_real_signals():
    assert model.score(established()) < 0.5
    assert model.score({"name": "reqeusts", "exists_on_pypi": False}) > 0.8


def test_explain_names_what_raised_the_score():
    reasons = model.explain({"name": "reqeusts", "exists_on_pypi": False})
    assert 1 <= len(reasons) <= 3
    assert any("not registered on PyPI" in r for r in reasons)
    assert all("SHAP impact: +" in r for r in reasons)


# Through the gateway, with Core Guard stubbed so no network is needed


def stub_core_guard(monkeypatch, exists=True, meta=None):
    monkeypatch.setattr(checks, "exists", lambda n: exists)
    monkeypatch.setattr(checks, "metadata", lambda n: meta if meta is not None else dict(ESTABLISHED))
    monkeypatch.setattr(checks, "security", lambda n: {"known_malicious": False, "malicious_ids": [], "vulnerabilities": []})


def test_gateway_allows_established_package(monkeypatch):
    stub_core_guard(monkeypatch)
    result = evaluate("six")
    assert result.decision == "allow"
    assert result.signals["model_score"] < 0.5
    assert "model_reasons" not in result.signals
    assert "errors" not in result.signals
    assert "not_implemented" not in result.signals


def test_gateway_shows_model_reasons_when_the_model_warns(monkeypatch):
    stub_core_guard(monkeypatch, exists=False)
    result = evaluate("reqeusts")
    assert result.decision == "block"
    assert result.signals["model_reasons"]
    assert any(r.startswith("AI model: ") for r in result.reasons)


def test_network_failure_does_not_look_like_a_missing_package(monkeypatch):
    stub_core_guard(monkeypatch)

    def down(name):
        raise TimeoutError("pypi slow")

    monkeypatch.setattr(checks, "exists", down)
    result = evaluate("six")
    assert result.decision == "allow"
    assert "model_score" not in result.signals
    assert result.signals["errors"]["exists"] == "TimeoutError: pypi slow"


def test_broken_model_is_reported_and_baseline_still_works(monkeypatch):
    stub_core_guard(monkeypatch, exists=False)

    def broken(signals):
        raise RuntimeError("model file is corrupt")

    monkeypatch.setattr(model, "score", broken)
    result = evaluate("reqeusts")
    assert result.signals["errors"]["risk_model"] == "RuntimeError: model file is corrupt"
    assert "not_implemented" not in result.signals
    assert "risk_model check failed" in result.reasons
    assert result.decision == "block"  # from the baseline


def test_score_is_only_a_number():
    score = model.score(established())
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


# Training code


@pytest.fixture
def small_dataset():
    safe = [established(f"good-package-{i}") for i in range(30)]
    risky = [{"name": f"fake-package-{i}", "exists_on_pypi": False} for i in range(30)]
    signals = safe + risky
    X = pd.DataFrame([extract_features(s) for s in signals], columns=FEATURE_COLUMNS)
    y = pd.Series([0] * 30 + [1] * 30, name="label")
    return X, y, signals


def test_train_save_load_gives_the_same_scores(tmp_path, small_dataset):
    X, y, _ = small_dataset
    trained = PackGuardXGBoostModel.train(X, y, X, y)
    path = tmp_path / "model.json"
    trained.save(path)
    loaded = PackGuardXGBoostModel.load(path)
    assert loaded.predict_proba(X) == pytest.approx(trained.predict_proba(X))
    assert loaded.score_single(X.iloc[0].to_dict()) < 0.5
    assert loaded.score_single(X.iloc[-1].to_dict()) > 0.5


def test_load_missing_model_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        PackGuardXGBoostModel.load(tmp_path / "nothing.json")


def test_evaluator_compares_against_core_guard_baseline(small_dataset):
    X, y, signals = small_dataset
    table = ModelEvaluator(PackGuardXGBoostModel.train(X, y)).compare(X, y, signals)
    assert list(table["Model"]) == ["Core Guard Baseline", "PackGuard XGBoost"]
    baseline = table.iloc[0]
    assert baseline["True Positives"] == 30  # 0.9 from "not on PyPI" is a block
    assert baseline["False Positives"] == 0
