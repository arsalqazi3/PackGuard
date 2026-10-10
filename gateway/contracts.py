from typing import Any, Literal

from pydantic import BaseModel, Field


class EvaluateRequest(BaseModel):
    name: str
    version: str | None = None


class EvaluateResponse(BaseModel):
    """Result for one package.

    Keys the gateway puts in `signals` (each one only when its check ran):
      exists_on_pypi          bool, from core_guard.checks.exists
      metadata                dict, from core_guard.checks.metadata (JSON safe values only)
      typosquat_of            list[str], from core_guard.checks.typosquat
      security                dict, from core_guard.checks.security
      hallucination_evidence  {"count", "models", "sources"}, from the evidence table
      baseline_score          float, from core_guard.checks.baseline_score
      model_score             float, from risk.model.score
      cached                  True if exists/metadata came from the packages table
      not_implemented         list of checks that are not written yet
      errors                  {check: message} for checks that crashed
    """

    decision: Literal["allow", "warn", "block"]
    score: float = Field(ge=0.0, le=1.0, description="0 = safe, 1 = risky")
    reasons: list[str] = []
    signals: dict[str, Any] = {}
