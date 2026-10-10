import logging
import os
import re

import httpx
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse, Response

from gateway.contracts import EvaluateRequest, EvaluateResponse
from gateway.evaluate import evaluate

PYPI_SIMPLE_URL = (os.getenv("PYPI_SIMPLE_URL") or "https://pypi.org/simple").rstrip("/")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("packguard")

app = FastAPI(title="PackGuard")


def normalize(name: str) -> str:
    """PEP 503 name normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/evaluate", response_model=EvaluateResponse)
def evaluate_route(req: EvaluateRequest):
    return evaluate(normalize(req.name), req.version)


@app.get("/simple/{name}/")
async def simple(name: str):
    name = normalize(name)
    result = evaluate(name)
    log.info(
        "package=%s decision=%s score=%.2f reasons=%s",
        name, result.decision, result.score, result.reasons,
    )
    # TODO: save the decision to the Postgres decisions table.

    if result.decision == "block":
        return PlainTextResponse(
            f"Blocked by PackGuard: {name} ({', '.join(result.reasons)})",
            status_code=403,
        )

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        upstream = await client.get(f"{PYPI_SIMPLE_URL}/{name}/", headers={"Accept": "text/html"})
    return Response(content=upstream.content, status_code=upstream.status_code, media_type="text/html")
