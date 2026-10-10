import os

from gateway.contracts import EvaluateResponse

# "or" so an empty value in .env still falls back to the default.
WARN_THRESHOLD = float(os.getenv("WARN_THRESHOLD") or 0.5)
BLOCK_THRESHOLD = float(os.getenv("BLOCK_THRESHOLD") or 0.8)

# Temporary list so the block path can be tested end to end.
TEST_BLOCKLIST = {"evil-test-pkg"}


def decide(score: float) -> str:
    if score >= BLOCK_THRESHOLD:
        return "block"
    if score >= WARN_THRESHOLD:
        return "warn"
    return "allow"


def evaluate(name: str, version: str | None = None) -> EvaluateResponse:
    # TODO: call core_guard.checks (exists, typosquat, metadata, baseline_score)
    # and risk.model.score here, then combine them into one score and signals.
    if name in TEST_BLOCKLIST:
        score = 1.0
        return EvaluateResponse(
            decision=decide(score), score=score, reasons=["test blocklist"], signals={}
        )
    score = 0.0
    return EvaluateResponse(decision=decide(score), score=score, reasons=[], signals={})
