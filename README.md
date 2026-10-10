# PackGuard

PackGuard is an install time security gateway for Python packages. You point pip at PackGuard as its package index. Every package request is checked first, and only safe packages are passed through to PyPI. Risky ones are blocked before anything is downloaded.

FYP-I scope: Core Guard (the gateway and its checks) and a first version of AI Risk Prediction.

## Folders and owners

| Folder | What it is | Owner |
|---|---|---|
| `gateway/` | FastAPI app that pip talks to | Arslan |
| `core_guard/` | Package checks (exists, typosquat, metadata, security, baseline score) | Asad |
| `risk/` | AI risk model (evidence collection, dataset, features, XGBoost) | Ammar |
| `db/` | Postgres schema | Arslan |
| `docs/` | Threat model and project notes | Arslan |
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

The database tests are skipped unless `TEST_DATABASE_URL` points at a throwaway Postgres. CI starts one for you. The tests empty its tables, so never point it at a real database.

## How the gateway decides

For every package the gateway runs the Core Guard checks (`exists`, `metadata`, `typosquat`, `security`), looks up AI hallucination evidence in the `evidence` table, and then takes the higher of `baseline_score` and the AI model score. A check that is not written yet is skipped and listed in `signals["not_implemented"]`, so each person can finish their part without breaking the gateway. The signal keys are listed in `gateway/contracts.py`.

PyPI lookups are cached in the `packages` table for `PACKAGE_CACHE_TTL_HOURS` (default 24). Every decision is saved in the `decisions` table. Without `DATABASE_URL` the gateway still works and only logs decisions.

The `/simple/` responses also carry `X-PackGuard-Decision` and `X-PackGuard-Score` headers. See `docs/threat-model.md` for what PackGuard does and does not protect against.

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
