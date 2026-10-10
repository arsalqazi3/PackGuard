import logging
import os
import re
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse, Response

from gateway import db
from gateway.contracts import EvaluateRequest, EvaluateResponse
from gateway.evaluate import evaluate

PYPI_SIMPLE_URL = (os.getenv("PYPI_SIMPLE_URL") or "https://pypi.org/simple").rstrip("/")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("packguard")

# Shared client so connections to PyPI are reused between requests.
http = httpx.Client(timeout=30.0, follow_redirects=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not db.DATABASE_URL:
        log.info("DATABASE_URL not set, decisions will only be logged")
    yield
    http.close()
    db.close()


app = FastAPI(title="PackGuard", lifespan=lifespan)


def normalize(name: str) -> str:
    """PEP 503 name normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


def check(name: str, version: str | None) -> EvaluateResponse:
    result = evaluate(name, version)
    log.info(
        "package=%s decision=%s score=%.2f reasons=%s",
        name, result.decision, result.score, result.reasons,
    )
    db.save_decision(name, version, result)
    return result


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/evaluate", response_model=EvaluateResponse)
def evaluate_route(req: EvaluateRequest):
    return check(normalize(req.name), req.version)


# Plain def (not async) so FastAPI runs it in a thread pool and the blocking
# checks and database calls do not hold up other requests.
@app.get("/simple/{name}/")
def simple(name: str):
    name = normalize(name)
    result = check(name, None)
    headers = {"X-PackGuard-Decision": result.decision, "X-PackGuard-Score": f"{result.score:.2f}"}

    if result.decision == "block":
        return PlainTextResponse(
            f"Blocked by PackGuard: {name} ({', '.join(result.reasons)})",
            status_code=403,
            headers=headers,
        )

    try:
        upstream = http.get(f"{PYPI_SIMPLE_URL}/{name}/", headers={"Accept": "text/html"})
    except httpx.HTTPError as e:
        log.warning("could not reach PyPI for %s: %s", name, e)
        return PlainTextResponse(
            f"PackGuard could not reach PyPI for {name}", status_code=502, headers=headers
        )
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type="text/html",
        headers=headers,
    )
