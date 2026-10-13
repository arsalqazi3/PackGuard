from typing import Dict, Any, List
import pandas as pd
from packguard.risk.config import ALLOW_THRESHOLD, BLOCK_THRESHOLD

class RuleBasedBaseline:
    """
    Rule-based baseline scoring engine as specified in the FYP-1 work plan.
    Provides the benchmark against which the XGBoost model is formally evaluated.
    Scores range from 0.0 (safest) to 1.0 (highest risk).
    """
    def __init__(self, allow_thresh: float = ALLOW_THRESHOLD, block_thresh: float = BLOCK_THRESHOLD):
        self.allow_thresh = allow_thresh
        self.block_thresh = block_thresh

    def score_single(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Computes heuristic risk score based on rule hierarchy:
        1. Registry non-existence is a severe risk (+0.65).
        2. Known AI hallucination affix (+0.15).
        3. Near-typosquat of a popular package (+0.25).
        4. Young package (< 14 days) or 0 releases (+0.15).
        5. Evidence table hit (+0.30).
        6. Established, mature package discount (-0.30).
        """
        risk = 0.0
        reasons = []

        # Existence
        if not features.get("exists_on_pypi", 0):
            risk += 0.65
            reasons.append("Package does not exist on PyPI")

        # Evidence table
        if features.get("is_in_evidence_table", 0):
            freq = features.get("evidence_model_frequency", 1)
            risk += min(0.35, 0.20 + 0.05 * freq)
            reasons.append(f"Recorded in hallucination evidence corpus ({freq} models)")

        # AI Affix
        if features.get("ai_affix_match", 0):
            risk += 0.15
            reasons.append("Matches known AI-hallucination naming pattern/affix")

        # Typosquat
        edit_dist = features.get("min_edit_distance_popular", 99.0)
        sim_ratio = features.get("similarity_ratio_popular", 0.0)
        if 1 <= edit_dist <= 2 and sim_ratio >= 80.0:
            risk += 0.25
            reasons.append("Suspicious typosquat proximity to popular package")

        # Package maturity
        age = features.get("package_age_days", 0)
        releases = features.get("total_releases", 0)
        has_repo = features.get("has_repository_url", 0)

        if features.get("exists_on_pypi", 0):
            if age < 14:
                risk += 0.15
                reasons.append("Very recently registered on PyPI (< 14 days)")
            if releases <= 1:
                risk += 0.05
            if not has_repo:
                risk += 0.10
                reasons.append("Missing source code repository link")

            # Maturity discounts
            if age > 180 and releases >= 3 and has_repo:
                risk -= 0.30

        # Clamp between 0.0 and 1.0
        final_score = max(0.0, min(1.0, round(risk, 4)))

        if final_score >= self.block_thresh:
            decision = "block"
        elif final_score >= self.allow_thresh:
            decision = "warn"
        else:
            decision = "allow"

        return {
            "score": final_score,
            "decision": decision,
            "reasons": reasons
        }

    def predict_proba(self, df: pd.DataFrame) -> List[float]:
        scores = []
        for _, row in df.iterrows():
            res = self.score_single(row.to_dict())
            scores.append(res["score"])
        return scores

    def predict(self, df: pd.DataFrame) -> List[int]:
        scores = self.predict_proba(df)
        return [1 if s >= self.block_thresh else 0 for s in scores]
