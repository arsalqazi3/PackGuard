import logging
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from packguard.risk.config import SAVED_MODELS_DIR
from packguard.risk.features.pipeline import RiskFeaturePipeline
from packguard.risk.models.xgboost_model import PackGuardXGBoostModel
from packguard.risk.explainability.explainer import RiskExplainer
from packguard.risk.models.baseline import RuleBasedBaseline

logger = logging.getLogger(__name__)

class ScoreRequest(BaseModel):
    name: str
    version: Optional[str] = None

class ScoreResponse(BaseModel):
    name: str
    version: Optional[str] = None
    score: float
    decision: str
    reasons: list[str]
    signals: Dict[str, Any]

class RiskScoringEngine:
    """
    Unified Scoring Engine serving predictions with SHAP explainability.
    Falls back gracefully to Rule-Based baseline if model is not yet compiled.
    """
    _instance = None

    def __init__(self):
        self.pipeline = RiskFeaturePipeline()
        model_path = SAVED_MODELS_DIR / "packguard_xgboost.joblib"
        if model_path.exists():
            try:
                self.model = PackGuardXGBoostModel.load(model_path)
                self.explainer = RiskExplainer(self.model)
                logger.info("Loaded trained PackGuard XGBoost model.")
            except Exception as e:
                logger.warning(f"Error loading XGBoost model: {e}. Using baseline fallback.")
                self.model = None
                self.explainer = None
        else:
            self.model = None
            self.explainer = None

        self.baseline = RuleBasedBaseline()

    def evaluate(self, package_name: str, version: Optional[str] = None) -> Dict[str, Any]:
        # 1. Feature extraction
        features = self.pipeline.extract_single(package_name)

        # 2. Model Scoring & Decision
        if self.model is not None:
            score_res = self.model.score_single(features)
            reasons = self.explainer.explain_single(features, top_n=3)
        else:
            score_res = self.baseline.score_single(features)
            reasons = score_res["reasons"]

        return {
            "name": package_name,
            "version": version,
            "score": score_res["score"],
            "decision": score_res["decision"],
            "reasons": reasons,
            "signals": {
                "exists_on_pypi": bool(features.get("exists_on_pypi", 0)),
                "min_edit_distance": float(features.get("min_edit_distance_popular", 99.0)),
                "similarity_ratio": float(features.get("similarity_ratio_popular", 0.0)),
                "ai_affix_match": bool(features.get("ai_affix_match", 0)),
                "package_age_days": int(features.get("package_age_days", 0)),
                "total_releases": int(features.get("total_releases", 0)),
                "is_in_evidence_table": bool(features.get("is_in_evidence_table", 0))
            }
        }

# Global singleton engine instance
engine = RiskScoringEngine()

def score_package(package_name: str, version: Optional[str] = None) -> Dict[str, Any]:
    """Direct Python callable function for internal gateway integration."""
    return engine.evaluate(package_name, version)

# FastAPI Application for Microservice / HTTP Integration
app = FastAPI(
    title="PackGuard AI Risk Prediction API",
    description="Machine Learning Risk Scoring Service for AI Hallucinations & Dependency Risks",
    version="1.0.0"
)

@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": engine.model is not None}

@app.post("/score", response_model=ScoreResponse)
def score_endpoint(request: ScoreRequest):
    try:
        result = engine.evaluate(request.name, request.version)
        return result
    except Exception as e:
        logger.error(f"Error scoring package {request.name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
