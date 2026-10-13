import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score
)
from typing import Dict, Any, Tuple
from packguard.risk.config import GROUND_TRUTH_DIR, FEATURE_COLUMNS
from packguard.risk.features.pipeline import RiskFeaturePipeline
from packguard.risk.models.baseline import RuleBasedBaseline
from packguard.risk.models.xgboost_model import PackGuardXGBoostModel

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

class ModelEvaluator:
    """
    Evaluator that rigorously tests and compares the Rule-Based Baseline
    against the XGBoost Model on the Held-Out Test Set.
    """
    def __init__(self, pipeline: RiskFeaturePipeline, xgb_model: PackGuardXGBoostModel):
        self.pipeline = pipeline
        self.xgb_model = xgb_model
        self.baseline = RuleBasedBaseline()

    def evaluate_test_set(self, test_ground_truth_path=None) -> pd.DataFrame:
        if test_ground_truth_path is None:
            test_ground_truth_path = GROUND_TRUTH_DIR / "held_out_test_ground_truth.csv"

        df_test = pd.read_csv(test_ground_truth_path)
        print(f"Loaded held-out test set with {len(df_test)} packages.")

        # Extract features
        packages = df_test["package_name"].tolist()
        y_true = df_test["label"].to_numpy()

        X_test = self.pipeline.transform(packages)

        # Baseline Predictions
        baseline_proba = np.array(self.baseline.predict_proba(X_test))
        baseline_preds = np.array(self.baseline.predict(X_test))
        baseline_metrics = calculate_metrics(y_true, baseline_preds, baseline_proba)

        # XGBoost Predictions
        xgb_proba = self.xgb_model.predict_proba(X_test)
        xgb_preds = self.xgb_model.predict(X_test)
        xgb_metrics = calculate_metrics(y_true, xgb_preds, xgb_proba)

        # Compare side-by-side
        comparison_df = pd.DataFrame([
            {"Model": "Rule-Based Baseline", **baseline_metrics},
            {"Model": "PackGuard XGBoost", **xgb_metrics}
        ])

        return comparison_df
