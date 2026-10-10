"""Combines Core Guard checks and the AI risk model into one decision.

Checks that are not written yet (NotImplementedError) are skipped and listed in
signals["not_implemented"]. Checks that crash are listed in signals["errors"].
Either way the gateway keeps working.
"""
import logging
import os
from pathlib import Path

from core_guard import checks
from gateway import db
from gateway.contracts import EvaluateResponse
from risk import model

log = logging.getLogger("packguard.evaluate")

# "or" so an empty value in .env still falls back to the default.
WARN_THRESHOLD = float(os.getenv("WARN_THRESHOLD") or 0.5)
BLOCK_THRESHOLD = float(os.getenv("BLOCK_THRESHOLD") or 0.8)

# Temporary list so the block path can be tested end to end.
TEST_BLOCKLIST = {"evil-test-pkg"}

# One package name per line, lines starting with # are ignored. Filled by Core Guard.
TOP_PACKAGES_FILE = Path(__file__).resolve().parent.parent / "core_guard" / "data" / "top_packages.txt"


def load_top_packages(path: Path = TOP_PACKAGES_FILE) -> list[str]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


TOP_PACKAGES = load_top_packages()


def decide(score: float) -> str:
    if score >= BLOCK_THRESHOLD:
        return "block"
    if score >= WARN_THRESHOLD:
        return "warn"
    return "allow"


def _run(signals: dict, check: str, fn, *args):
    """Run one check. Return its result, or None if it is not ready or it failed."""
    try:
        return fn(*args)
    except NotImplementedError:
        signals.setdefault("not_implemented", []).append(check)
    except Exception as e:
        log.warning("check %s failed: %s: %s", check, type(e).__name__, e)
        signals.setdefault("errors", {})[check] = f"{type(e).__name__}: {e}"
    return None


def collect_signals(name: str) -> dict:
    signals: dict = {}

    cached = db.get_cached_package(name)
    if cached:
        signals["exists_on_pypi"] = cached["exists_on_pypi"]
        if cached["metadata"] is not None:
            signals["metadata"] = cached["metadata"]
        signals["cached"] = True
    else:
        exists = _run(signals, "exists", checks.exists, name)
        if exists is not None:
            signals["exists_on_pypi"] = exists
        if exists:
            meta = _run(signals, "metadata", checks.metadata, name)
            if meta is not None:
                signals["metadata"] = meta
        # Only cache complete results, so a half finished check is not stuck in the cache.
        if exists is False or (exists and "metadata" in signals):
            db.save_package(name, exists, signals.get("metadata"))

    similar = _run(signals, "typosquat", checks.typosquat, name, TOP_PACKAGES)
    if similar is not None:
        signals["typosquat_of"] = similar

    security = _run(signals, "security", checks.security, name)
    if security is not None:
        signals["security"] = security

    rows = db.get_evidence(name)
    if rows is not None:
        signals["hallucination_evidence"] = {
            "count": len(rows),
            "models": sorted({r["model"] for r in rows if r["model"]}),
            "sources": sorted({r["source"] for r in rows}),
        }
    return signals


def combine_score(signals: dict) -> float:
    """Take the higher of the rule based baseline and the AI model score.

    Using the max means the model can raise the risk but never hide what the
    rules found. Missing scores are skipped, and no scores at all gives 0.
    """
    scores = []
    baseline = _run(signals, "baseline_score", checks.baseline_score, signals)
    if baseline is not None:
        signals["baseline_score"] = baseline
        scores.append(baseline)
    model_score = _run(signals, "risk_model", model.score, signals)
    if model_score is not None:
        signals["model_score"] = model_score
        scores.append(model_score)
    score = max(scores, default=0.0)
    return min(max(float(score), 0.0), 1.0)


def build_reasons(signals: dict) -> list[str]:
    reasons = []
    if signals.get("exists_on_pypi") is False:
        reasons.append("not found on PyPI")
    if signals.get("typosquat_of"):
        reasons.append("name is close to popular package: " + ", ".join(signals["typosquat_of"]))
    security = signals.get("security") or {}
    if security.get("known_malicious"):
        reasons.append("listed as a known malicious package")
    if security.get("vulnerabilities"):
        reasons.append(f"{len(security['vulnerabilities'])} known vulnerabilities")
    evidence = signals.get("hallucination_evidence")
    if evidence and evidence["count"]:
        reasons.append(f"name seen in AI hallucination data ({len(evidence['models'])} models)")
    for check in signals.get("errors", {}):
        reasons.append(f"{check} check failed")
    return reasons


def evaluate(name: str, version: str | None = None) -> EvaluateResponse:
    if name in TEST_BLOCKLIST:
        score = 1.0
        return EvaluateResponse(
            decision=decide(score), score=score, reasons=["test blocklist"], signals={}
        )
    signals = collect_signals(name)
    score = combine_score(signals)
    return EvaluateResponse(
        decision=decide(score), score=score, reasons=build_reasons(signals), signals=signals
    )
