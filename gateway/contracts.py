from typing import Any, Literal

from pydantic import BaseModel, Field


class EvaluateRequest(BaseModel):
    name: str
    version: str | None = None


class EvaluateResponse(BaseModel):
    decision: Literal["allow", "warn", "block"]
    score: float = Field(ge=0.0, le=1.0, description="0 = safe, 1 = risky")
    reasons: list[str] = []
    signals: dict[str, Any] = {}
