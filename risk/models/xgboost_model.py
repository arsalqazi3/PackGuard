import joblib
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from packguard.risk.config import (
    SAVED_MODELS_DIR,
    FEATURE_COLUMNS,
    ALLOW_THRESHOLD,
    BLOCK_THRESHOLD
)

logger = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = SAVED_MODELS_DIR / "packguard_xgboost.joblib"
DEFAULT_JSON_PATH = SAVED_MODELS_DIR / "packguard_xgboost.json"

class PackGuardXGBoostModel:
    """
    XGBoost Risk Classifier for Python Package Hallucination and Supply-Chain Risk.
    Predicts probability of risk [0.0, 1.0].
    """
    def __init__(self, model: Optional[XGBClassifier] = None):
        self.model = model
        self.feature_names = FEATURE_COLUMNS
        self.allow_threshold = ALLOW_THRESHOLD
        self.block_threshold = BLOCK_THRESHOLD

    @classmethod
    def train(cls, X_train: pd.DataFrame, y_train: pd.Series,
              X_val: Optional[pd.DataFrame] = None, y_val: Optional[pd.Series] = None) -> "PackGuardXGBoostModel":
        """
        Trains the XGBoost classifier with early stopping and regularization.
        """
        clf = XGBClassifier(
            n_estimators=150,
            max_depth=5,
            learning_rate=0.08,
            subsample=0.85,
            colsample_bytree=0.85,
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1
        )

        eval_set = [(X_train, y_train)]
        if X_val is not None and y_val is not None:
            eval_set.append((X_val, y_val))

        clf.fit(
            X_train, y_train,
            eval_set=eval_set,
            verbose=False
        )

        return cls(model=clf)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        if self.model is None:
            raise ValueError("Model is not trained or loaded.")
        # Ensure column order
        X_ordered = X[self.feature_names]
        # Return probability of positive class (risk = 1)
        return self.model.predict_proba(X_ordered)[:, 1]

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        probs = self.predict_proba(X)
        return (probs >= self.block_threshold).astype(int)

    def score_single(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Scores a single package feature dictionary and returns decision."""
        df = pd.DataFrame([features], columns=self.feature_names)
        prob = float(self.predict_proba(df)[0])
        prob = round(prob, 4)

        if prob >= self.block_threshold:
            decision = "block"
        elif prob >= self.allow_threshold:
            decision = "warn"
        else:
            decision = "allow"

        return {
            "score": prob,
            "decision": decision
        }

    def save(self, filepath: Path = DEFAULT_MODEL_PATH):
        if self.model is None:
            raise ValueError("Cannot save an untrained model.")
        filepath.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, filepath)
        # Also save native XGBoost JSON format for cross-platform portability
        self.model.save_model(str(DEFAULT_JSON_PATH))
        logger.info(f"Model saved to {filepath} and {DEFAULT_JSON_PATH}")

    @classmethod
    def load(cls, filepath: Path = DEFAULT_MODEL_PATH) -> "PackGuardXGBoostModel":
        if not filepath.exists():
            raise FileNotFoundError(f"Model file not found at {filepath}")
        model = joblib.load(filepath)
        return cls(model=model)
