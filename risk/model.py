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

    `signals` uses the keys listed in gateway/contracts.py. Feature ideas:
    exists_on_pypi, package age in days, number of releases, has repository URL,
    number of typosquat matches, known_malicious, number of vulnerabilities,
    and from signals["hallucination_evidence"]: total count and the number of
    distinct models (cross-model agreement, the AI-specific signal from the proposal).
    Keep this the same for training and for live scoring.
    """
    raise NotImplementedError


def score(signals: dict) -> float:
    """Return a risk score between 0 and 1 (1 = risky) from the trained model."""
    raise NotImplementedError
