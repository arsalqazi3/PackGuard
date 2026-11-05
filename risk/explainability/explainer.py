from typing import Any, Callable, Dict, List

from risk.models.xgboost_model import PackGuardXGBoostModel

# A positive SHAP value means this value raised the risk, so each text states the
# value itself and does not assume it is high or low.
FEATURE_DESCRIPTIONS: Dict[str, Callable[[Any], str]] = {
    "exists_on_pypi": lambda v: "package exists on PyPI" if v else "package is not registered on PyPI",
    "name_length": lambda v: f"name length is {v}",
    "name_entropy": lambda v: f"name randomness (entropy) is {v}",
    "has_hyphen_or_underscore": lambda v: "name has a separator" if v else "name has no separator",
    "ai_affix_match": lambda v: "name has a common AI-hallucination word" if v else "name has no common AI-hallucination word",
    "min_edit_distance_popular": lambda v: f"edit distance to the closest popular package is {v:g}",
    "similarity_ratio_popular": lambda v: f"similarity to the closest popular package is {v:g}%",
    "is_in_evidence_table": lambda v: "name is in the hallucination evidence table" if v else "name is not in the hallucination evidence table",
    "evidence_model_frequency": lambda v: f"{v} AI models hallucinated this name",
    "package_age_days": lambda v: f"package age is {v} days",
    "total_releases": lambda v: f"release count is {v}",
    "days_since_last_release": lambda v: f"last release was {v} days ago",
    "maintainer_count": lambda v: "author is listed" if v else "no author listed",
    "has_repository_url": lambda v: "source repository is linked" if v else "no source repository linked",
    "has_documentation_url": lambda v: "documentation is linked" if v else "no documentation linked",
    "description_length": lambda v: f"description length is {v}",
}


class RiskExplainer:
    """
    Translates TreeSHAP feature attributions into human-readable security reasons.
    """
    def __init__(self, risk_model: PackGuardXGBoostModel):
        self.risk_model = risk_model

    def explain_single(self, features: Dict[str, Any], top_n: int = 3) -> List[str]:
        """
        Returns the features that raised the risk score the most.
        """
        contributions = self.risk_model.contributions(features)
        raising = sorted((c for c in contributions if c[1] > 0.01), key=lambda c: c[1], reverse=True)
        return [
            f"{FEATURE_DESCRIPTIONS[col](features[col])} (SHAP impact: +{value:.2f})"
            for col, value in raising[:top_n]
        ]
