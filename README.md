# PackGuard

PackGuard is an install time security gateway for Python packages. You point pip at PackGuard as its package index. Every package request is checked first, and only safe packages are passed through to PyPI. Risky ones are blocked before anything is downloaded.

FYP-I scope: Core Guard (the gateway and its checks) and a first version of AI Risk Prediction.

## Folders and owners

| Folder | What it is | Owner |
|---|---|---|
| `gateway/` | FastAPI app that pip talks to | Arslan |
| `core_guard/` | Package checks (exists, typosquat, metadata, baseline score) | Asad |
| `risk/` | AI risk model (dataset, features, XGBoost) | Ammar |
| `db/` | Postgres schema | Arslan |
| `tests/` | Pytest tests | Everyone |

## Run locally

Needs Python 3.13.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
uvicorn gateway.main:app --port 8000
```

## Run with Docker

```bash
cp .env.example .env             # then fill in the values
docker compose up --build
```

The database tables are created from `db/schema.sql` the first time the db container starts.

## Test with pip

With the gateway running on port 8000, use a separate venv:

```bash
pip install --no-cache-dir --index-url http://localhost:8000/simple six            # installs
pip install --no-cache-dir --index-url http://localhost:8000/simple evil-test-pkg  # blocked
```

## Run tests

```bash
pytest -q
```

## The /evaluate contract

Request:

```json
{"name": "requests", "version": "2.32.0"}
```

`version` is optional.

Response:

```json
{"decision": "allow", "score": 0.0, "reasons": [], "signals": {}}
```

- `decision` is `allow`, `warn` or `block`
- `score` is between 0 and 1, where 1 means risky
- `reasons` is a list of short human readable reasons
- `signals` is the raw data from the checks

Thresholds come from `WARN_THRESHOLD` (default 0.5) and `BLOCK_THRESHOLD` (default 0.8).

## Team rules

- Work on your own branch, never push straight to main.
- Open a PR and merge only when CI passes.
- Never commit `.env` or any API key. This repo is public.
- Never train on the held-out test set in `risk/data/test/`, and never use it for the evidence table.
