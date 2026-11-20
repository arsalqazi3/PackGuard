"""AI Risk Prediction. Owner: Ammar.

Plan:
1. Build a labelled dataset:
   - hallucinated package names (Spracklen et al.) as risky,
   - real PyPI packages, including small and less popular ones, as safe,
   - known malicious packages as risky.
2. Lock a held-out test set in risk/data/test/. It is never used for training
   and never used to build the evidence table.
3. Extract features from the Core Guard signals (see extract_features).
4. Train an XGBoost model from scratch on the training split only.
   The gateway loads the model from risk/saved_models/packguard_xgboost.json.
5. Evaluate on the held-out test set: precision, recall, F1 and false
   positive rate, compared against core_guard.checks.baseline_score.
"""
import threading

from risk.features.pipeline import extract_features

_engine = None
_engine_lock = threading.Lock()


def _load():
    """Load the model once, on first use, so importing this module stays fast."""
    global _engine
    with _engine_lock:
        if _engine is None:
            from risk.explainability.explainer import RiskExplainer
            from risk.models.xgboost_model import PackGuardXGBoostModel

            loaded = PackGuardXGBoostModel.load()
            _engine = (loaded, RiskExplainer(loaded))
    return _engine


def score(signals: dict) -> float | None:
    """Return a risk score between 0 and 1 (1 = risky) from the trained model.

    Returns None when the signals are incomplete, so the gateway uses the rule
    based baseline alone. Real errors are not caught here, the gateway reports
    them in signals["errors"].
    """
    features = extract_features(signals)
    if features is None:
        return None
    risk_model, _ = _load()
    return risk_model.score_single(features)


def explain(signals: dict) -> list[str]:
    """Return the top reasons, from TreeSHAP, why the model raised the score."""
    features = extract_features(signals)
    if features is None:
        return []
    _, explainer = _load()
    return explainer.explain_single(features)
