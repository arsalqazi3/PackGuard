"""Run with: python -m risk.train (needs requirements-train.txt and internet access)."""
import time

import pandas as pd

from risk.config import GROUND_TRUTH_DIR, SAVED_MODELS_DIR
from risk.dataset.signals import build_feature_table
from risk.models.evaluator import ModelEvaluator
from risk.models.xgboost_model import PackGuardXGBoostModel


def run_training_and_evaluation():
    print("=" * 70)
    print("PackGuard AI Risk Prediction - Model Training & Evaluation Pipeline")
    print("=" * 70)

    train_path = GROUND_TRUTH_DIR / "train_ground_truth.csv"
    val_path = GROUND_TRUTH_DIR / "val_ground_truth.csv"
    test_path = GROUND_TRUTH_DIR / "held_out_test_ground_truth.csv"

    if not train_path.exists():
        print("Ground truth datasets not found. Building now...")
        from risk.dataset.builder import build_and_split_dataset
        build_and_split_dataset()

    df_train = pd.read_csv(train_path)
    df_val = pd.read_csv(val_path)

    print(f"\n[1/4] Extracting features for Training Set ({len(df_train)} samples)...")
    t0 = time.time()
    X_train, y_train, _ = build_feature_table(df_train)
    print(f"      Completed in {time.time() - t0:.2f}s")

    print(f"\n[2/4] Extracting features for Validation Set ({len(df_val)} samples)...")
    t0 = time.time()
    X_val, y_val, _ = build_feature_table(df_val)
    print(f"      Completed in {time.time() - t0:.2f}s")

    print("\n[3/4] Training PackGuard XGBoost Classifier...")
    t0 = time.time()
    xgb_model = PackGuardXGBoostModel.train(X_train, y_train, X_val, y_val)
    xgb_model.save()
    print(f"      Model trained and saved in {time.time() - t0:.2f}s")

    print("\n[4/4] Evaluating against Core Guard Baseline on Held-Out Test Set...")
    comparison_df = ModelEvaluator(xgb_model).evaluate_test_set(test_path)

    print("\n" + "=" * 70)
    print("OFFICIAL FYP-1 EVALUATION RESULTS TABLE")
    print("=" * 70)
    print(comparison_df.to_string(index=False))

    results_csv = SAVED_MODELS_DIR / "evaluation_results.csv"
    comparison_df.to_csv(results_csv, index=False)
    print(f"\nResults saved to: {results_csv}")
    print("=" * 70)


if __name__ == "__main__":
    run_training_and_evaluation()
