import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score
)
from typing import Dict, List

from core_guard.checks import baseline_score
from gateway.evaluate import decide
from risk.config import GROUND_TRUTH_DIR
from risk.dataset.signals import build_feature_table
from risk.models.xgboost_model import PackGuardXGBoostModel


def calculate_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_proba: np.ndarray) -> Dict[str, float]:
    """
    Computes classification metrics including False Positive Rate and ROC-AUC.
    """
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    acc = accuracy_score(y_true, y_pred)
    try:
        auc = roc_auc_score(y_true, y_proba)
    except Exception:
        auc = 0.0

    return {
        "Accuracy": round(float(acc), 4),
        "Precision": round(float(prec), 4),
        "Recall": round(float(rec), 4),
        "F1-Score": round(float(f1), 4),
        "False Positive Rate (FPR)": round(float(fpr), 4),
        "ROC-AUC": round(float(auc), 4),
        "True Positives": int(tp),
        "False Positives": int(fp),
        "True Negatives": int(tn),
        "False Negatives": int(fn)
    }


def _block_labels(scores: np.ndarray) -> np.ndarray:
    # Uses the gateway's own thresholds, so results match what pip would see.
    return np.array([1 if decide(float(s)) == "block" else 0 for s in scores])


class ModelEvaluator:
    """
    Compares Core Guard's rule based baseline against the XGBoost model.
    """
    def __init__(self, xgb_model: PackGuardXGBoostModel):
        self.xgb_model = xgb_model

    def compare(self, X: pd.DataFrame, y: pd.Series, signals: List[dict]) -> pd.DataFrame:
        y_true = y.to_numpy()

        baseline_proba = np.array([baseline_score(s) for s in signals])
        baseline_metrics = calculate_metrics(y_true, _block_labels(baseline_proba), baseline_proba)

        xgb_proba = self.xgb_model.predict_proba(X)
        xgb_metrics = calculate_metrics(y_true, _block_labels(xgb_proba), xgb_proba)

        return pd.DataFrame([
            {"Model": "Core Guard Baseline", **baseline_metrics},
            {"Model": "PackGuard XGBoost", **xgb_metrics}
        ])

    def evaluate_test_set(self, test_ground_truth_path=None) -> pd.DataFrame:
        if test_ground_truth_path is None:
            test_ground_truth_path = GROUND_TRUTH_DIR / "held_out_test_ground_truth.csv"

        df_test = pd.read_csv(test_ground_truth_path)
        print(f"Loaded held-out test set with {len(df_test)} packages.")
        return self.compare(*build_feature_table(df_test))
