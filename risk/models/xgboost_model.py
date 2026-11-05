from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import xgboost as xgb

from risk.config import FEATURE_COLUMNS, MODEL_PATH


class PackGuardXGBoostModel:
    """
    XGBoost Risk Classifier for Python Package Hallucination and Supply-Chain Risk.
    Predicts probability of risk [0.0, 1.0]. The gateway decides what the score means.
    """
    def __init__(self, booster: xgb.Booster):
        self.booster = booster

    @classmethod
    def train(cls, X_train, y_train, X_val=None, y_val=None) -> "PackGuardXGBoostModel":
        """
        Trains the XGBoost classifier. Needs requirements-train.txt.
        """
        from xgboost import XGBClassifier

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

        eval_set = [(X_train[FEATURE_COLUMNS], y_train)]
        if X_val is not None and y_val is not None:
            eval_set.append((X_val[FEATURE_COLUMNS], y_val))

        clf.fit(X_train[FEATURE_COLUMNS], y_train, eval_set=eval_set, verbose=False)
        return cls(clf.get_booster())

    def predict_proba(self, X) -> np.ndarray:
        """Risk probability for each row of a DataFrame."""
        rows = X[FEATURE_COLUMNS].to_numpy(dtype=float)
        return self.booster.predict(xgb.DMatrix(rows, feature_names=FEATURE_COLUMNS))

    @staticmethod
    def _single(features: Dict[str, Any]) -> xgb.DMatrix:
        row = np.array([[features[col] for col in FEATURE_COLUMNS]], dtype=float)
        return xgb.DMatrix(row, feature_names=FEATURE_COLUMNS)

    def score_single(self, features: Dict[str, Any]) -> float:
        return round(float(self.booster.predict(self._single(features))[0]), 4)

    def contributions(self, features: Dict[str, Any]) -> List[Tuple[str, float]]:
        """TreeSHAP value of each feature, built into XGBoost. Positive means more risk."""
        values = self.booster.predict(self._single(features), pred_contribs=True)[0]
        return [(col, float(val)) for col, val in zip(FEATURE_COLUMNS, values)]  # zip drops the bias term

    def save(self, filepath: Path = MODEL_PATH):
        filepath.parent.mkdir(parents=True, exist_ok=True)
        self.booster.save_model(str(filepath))

    @classmethod
    def load(cls, filepath: Optional[Path] = None) -> "PackGuardXGBoostModel":
        filepath = filepath or MODEL_PATH
        if not filepath.exists():
            raise FileNotFoundError(f"Model file not found at {filepath}")
        booster = xgb.Booster()
        booster.load_model(str(filepath))
        return cls(booster)
