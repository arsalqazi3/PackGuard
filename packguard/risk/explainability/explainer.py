import shap
import pandas as pd
from typing import Dict, Any, List, Optional
from packguard.risk.config import FEATURE_COLUMNS
from packguard.risk.models.xgboost_model import PackGuardXGBoostModel

FEATURE_HUMAN_DESCRIPTIONS = {
    "exists_on_pypi": {
        0: "Package is not registered on PyPI",
        1: "Package exists on PyPI"
    },
    "ai_affix_match": {
        1: "Contains common AI-hallucination naming affix"
    },
    "min_edit_distance_popular": "Close typosquat distance to popular package",
    "similarity_ratio_popular": "High textual similarity to established package",
    "is_in_evidence_table": "Recorded in LLM hallucination evidence corpus",
    "package_age_days": "Low package age / newly created",
    "has_repository_url": {
        0: "No public source repository link provided"
    },
    "total_releases": "Very low release count (< 2)",
    "maintainer_count": {
        0: "No verified maintainer/author listed"
    }
}

class RiskExplainer:
    """
    Computes local feature attribution using SHAP (SHapley Additive exPlanations).
    Translates mathematical tree values into human-readable security reasons.
    """
    def __init__(self, risk_model: PackGuardXGBoostModel):
        self.risk_model = risk_model
        if risk_model.model is not None:
            self.explainer = shap.TreeExplainer(risk_model.model)
        else:
            self.explainer = None

    def explain_single(self, features: Dict[str, Any], top_n: int = 3) -> List[str]:
        """
        Calculates the top contributing features for the risk score
        and returns human-readable security reasons.
        """
        if self.explainer is None:
            # Fallback to heuristic explanations if SHAP explainer is not active
            return self._heuristic_reasons(features)

        df = pd.DataFrame([features], columns=FEATURE_COLUMNS)
        shap_values = self.explainer.shap_values(df)

        if isinstance(shap_values, list):
            # Binary classification [class 0, class 1]
            values = shap_values[1][0]
        else:
            values = shap_values[0]

        contributions = []
        for col, val in zip(FEATURE_COLUMNS, values):
            feat_val = features.get(col, 0)
            contributions.append((col, float(val), feat_val))

        # Sort by highest positive contribution to risk (val > 0 means increased risk)
        positive_risk = [c for c in contributions if c[1] > 0.01]
        positive_risk.sort(key=lambda x: x[1], reverse=True)

        reasons = []
        for col, shap_val, feat_val in positive_risk[:top_n]:
            desc = self._format_reason(col, feat_val, shap_val)
            if desc:
                reasons.append(desc)

        if not reasons:
            reasons.append("Standard package profile with normal operational signals")

        return reasons

    def _format_reason(self, feature_name: str, val: Any, shap_val: float) -> Optional[str]:
        mapping = FEATURE_HUMAN_DESCRIPTIONS.get(feature_name)
        if isinstance(mapping, dict):
            text = mapping.get(val)
            if text:
                return f"{text} (SHAP impact: +{shap_val:.2f})"
        elif isinstance(mapping, str):
            return f"{mapping} (SHAP impact: +{shap_val:.2f})"

        return f"Signal '{feature_name}' raised suspicion (impact: +{shap_val:.2f})"

    def _heuristic_reasons(self, features: Dict[str, Any]) -> List[str]:
        reasons = []
        if not features.get("exists_on_pypi", 0):
            reasons.append("Package is not registered on PyPI")
        if features.get("ai_affix_match", 0):
            reasons.append("Matches known AI-hallucination suffix")
        if features.get("is_in_evidence_table", 0):
            reasons.append("Found in multi-model hallucination evidence table")
        return reasons or ["No critical risk signals detected"]
