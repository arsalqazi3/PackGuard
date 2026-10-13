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
   Save trained models in risk/models/ (model files are git ignored).
5. Evaluate on the held-out test set: precision, recall, F1 and false
   positive rate, compared against core_guard.checks.baseline_score.
"""


def extract_features(signals: dict) -> dict:
    """Turn Core Guard signals into a flat dict of numeric features.

    `signals` uses the keys listed in gateway/contracts.py.
    """
    try:
        from packguard.risk.service import engine
        name = signals.get("name") or (signals.get("metadata") or {}).get("name", "")
        if name:
            return engine.pipeline.extract_single(name)
    except Exception:
        pass

    meta = signals.get("metadata") or {}
    evidence = signals.get("hallucination_evidence") or {}
    return {
        "exists_on_pypi": 1.0 if signals.get("exists_on_pypi") else 0.0,
        "package_age_days": float(meta.get("age_days", 0)),
        "total_releases": float(meta.get("releases", 0)),
        "has_repository_url": 1.0 if meta.get("has_repository") else 0.0,
        "is_in_evidence_table": 1.0 if evidence.get("count", 0) > 0 else 0.0,
        "evidence_model_frequency": float(len(evidence.get("models", []))),
    }


def score(signals: dict) -> float:
    """Return a risk score between 0 and 1 (1 = risky) from the trained model."""
    try:
        from packguard.risk.service import engine
        name = signals.get("name") or (signals.get("metadata") or {}).get("name", "")
        if name:
            res = engine.evaluate(name)
            return float(res["score"])

        features = extract_features(signals)
        if engine.model is not None:
            return float(engine.model.score_single(features)["score"])
        return float(engine.baseline.score_single(features)["score"])
    except Exception:
        raise NotImplementedError
