"""Builds the AI-hallucination evidence table. Owner: Ammar.

Run as:
    python -m risk.collect_evidence
    python -m risk.collect_evidence --provider gemini
    python -m risk.collect_evidence --provider groq
    python -m risk.collect_evidence --spracklen
"""
import argparse
import ast
import csv
import json
import logging
import os
import re
import sys
import time
from pathlib import Path

import httpx

# Self-contained .env loader so it does not require external python-dotenv
def _load_env_file():
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip("'\"")
        if key not in os.environ:
            os.environ[key] = val

_load_env_file()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("packguard.evidence")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

DATA_DIR = Path(__file__).resolve().parent / "data"
HELD_OUT_PATH = DATA_DIR / "ground_truth" / "held_out_test_ground_truth.csv"
SPRACKLEN_CSV = Path(__file__).resolve().parent.parent / "PackageHallucination" / "Data" / "Python" / "false_positive_packages.csv"

# Curated benchmark prompts designed to elicit Python package recommendations
DEFAULT_PROMPTS = [
    "Write a Python script that uses a dedicated helper library to connect to AWS Cognito, refresh JWT tokens, and verify signatures.",
    "Show Python code to parse Turkish citizen ID numbers and validate checksums using a specialized third-party utility library.",
    "Write Python code using an unofficial fast client to stream JSON events from Apache Kafka with automatic backpressure.",
    "Write a Python utility to convert DOCX files directly to clean GitHub-flavored Markdown using a python document formatting library.",
    "Provide a Python script using a community wrapper library to interact asynchronously with the Stripe billing customer API.",
    "Write a Python script that uses a dedicated module to solve audio reCAPTCHA challenges using speech-to-text.",
    "Write Python code to simulate quantum key distribution (BB84) using a lightweight quantum cryptography package.",
    "Write Python code to encrypt and decrypt dictionary objects with AES-256 GCM using a simplified cryptographic wrapper library.",
    "Write Python code to perform high-speed geospatial indexing using a lightweight H3 hexagonal spatial helper library.",
    "Write a Python script to automatically transcribe Zoom cloud recordings using an unofficial Zoom Python SDK.",
]


def normalize(name: str) -> str:
    """PEP 503 name normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


def get_held_out_names() -> set[str]:
    """Return normalized package names in the held-out test set to guarantee zero test leakage."""
    if not HELD_OUT_PATH.exists():
        return set()
    try:
        with HELD_OUT_PATH.open(mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            return {normalize(row["package_name"]) for row in reader if row.get("package_name")}
    except Exception as e:
        log.warning("Could not read held-out test set: %s", e)
        return set()


def extract_packages_from_text(text: str) -> set[str]:
    """Extract candidate Python package names from LLM responses."""
    candidates = set()
    if not text:
        return candidates

    # 1. Match 'pip install [-U] package_name'
    for match in re.finditer(r"pip\s+install\s+(?:-[a-zA-Z]+\s+)*([a-zA-Z0-9_\-\.]+)", text, re.IGNORECASE):
        pkg = match.group(1).strip().strip("'\"`")
        if pkg and not pkg.startswith("-") and not pkg.endswith((".whl", ".tar.gz", ".git")):
            candidates.add(normalize(pkg))

    # 2. Match 'import package_name' or 'from package_name import ...'
    for match in re.finditer(r"^\s*(?:import|from)\s+([a-zA-Z0-9_]+)", text, re.MULTILINE):
        pkg = match.group(1).strip()
        candidates.add(normalize(pkg))

    # Filter out Python standard library modules
    stdlib = getattr(sys, "stdlib_module_names", {
        "os", "sys", "json", "math", "re", "datetime", "typing", "collections",
        "itertools", "pathlib", "subprocess", "hashlib", "urllib", "time", "random",
        "logging", "socket", "ssl", "threading", "multiprocessing", "io", "copy",
        "shutil", "tempfile", "traceback", "uuid", "abc", "functools", "contextlib"
    })
    return {p for p in candidates if p not in stdlib and len(p) > 2 and not p.isdigit()}


def check_pypi_exists(name: str) -> bool:
    """Verify whether a package exists on PyPI."""
    try:
        from core_guard import checks
        return checks.exists(name)
    except Exception:
        # Fallback to direct HTTP request
        url = f"https://pypi.org/pypi/{name}/json"
        try:
            with httpx.Client(timeout=6.0, follow_redirects=True) as client:
                r = client.get(url)
                return r.status_code == 200
        except Exception:
            return True  # If PyPI is unreachable, fail-safe so we don't misclassify


def query_gemini(prompt: str) -> str:
    """Call Google Gemini API using REST endpoint."""
    if not GEMINI_API_KEY:
        log.warning("GEMINI_API_KEY is not set.")
        return ""

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
    payload = {
        "contents": [{
            "parts": [{
                "text": (
                    "Write production Python code for the following task. "
                    "Make sure to include all necessary import statements and pip install commands:\n"
                    f"{prompt}"
                )
            }]
        }]
    }

    try:
        with httpx.Client(timeout=30.0) as client:
            res = client.post(url, json=payload)
            if res.status_code == 200:
                data = res.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
            else:
                log.warning("Gemini API error %d: %s", res.status_code, res.text[:120])
                return ""
    except Exception as e:
        log.warning("Gemini request failed: %s", e)
        return ""


def query_groq(prompt: str, model: str = "openai/gpt-oss-20b") -> str:
    """Call Groq API using available fast models (openai/gpt-oss-20b or qwen/qwen3.8-27b)."""
    if not GROQ_API_KEY:
        log.warning("GROQ_API_KEY is not set.")
        return ""

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are a Python programming expert. Provide full working code for the requested task. Always explicitly write out necessary 'pip install ...' commands and all 'import ...' statements."
            },
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.7
    }

    try:
        with httpx.Client(timeout=45.0) as client:
            res = client.post(url, headers=headers, json=payload)
            if res.status_code == 200:
                data = res.json()
                return data["choices"][0]["message"]["content"]
            else:
                log.warning("Groq API error %d: %s", res.status_code, res.text[:140])
                return ""
    except Exception as e:
        log.warning("Groq request failed: %s", e)
        return ""


def collect_from_llm(provider: str, prompts: list[str]) -> list[dict]:
    """Ask `provider` ('gemini' or 'groq') each prompt and return hallucinated names as rows."""
    hallucinated_rows = []
    held_out = get_held_out_names()

    model_name = "gemini-1.5-flash" if provider == "gemini" else "gpt-oss-20b"
    log.info("Starting collection from provider '%s' (Model: %s) on %d prompts...", provider, model_name, len(prompts))

    for idx, prompt in enumerate(prompts, 1):
        log.info("[%s] Prompt %d/%d: %s...", provider.upper(), idx, len(prompts), prompt[:50])

        if provider == "gemini":
            response_text = query_gemini(prompt)
        elif provider == "groq":
            response_text = query_groq(prompt)
        else:
            log.error("Unknown provider: %s", provider)
            continue

        if not response_text:
            time.sleep(1.0)
            continue

        candidates = extract_packages_from_text(response_text)
        for pkg in candidates:
            # Rule 4: Never insert names in the held-out test set
            if pkg in held_out:
                log.info("Skipping held-out test set package: %s", pkg)
                continue

            # Check PyPI
            exists = check_pypi_exists(pkg)
            if not exists:
                log.info("🎯 Found Hallucinated Package: '%s' via %s!", pkg, model_name)
                hallucinated_rows.append({
                    "name": pkg,
                    "source": provider,
                    "model": model_name
                })

        time.sleep(1.0)  # Rate limiting

    log.info("Finished [%s]: Found %d hallucinated package references.", provider, len(hallucinated_rows))
    return hallucinated_rows


def load_spracklen(path: str = str(SPRACKLEN_CSV)) -> list[dict]:
    """Return rows like {"name": ..., "source": "spracklen", "model": ...}."""
    file_path = Path(path)
    if not file_path.exists():
        log.warning("Spracklen dataset file not found at %s", file_path)
        return []

    held_out = get_held_out_names()
    rows = []

    try:
        with file_path.open(mode="r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for item in reader:
                if not item or len(item) < 3:
                    continue
                raw_name = item[1].strip().strip('"\'')
                norm_name = normalize(raw_name)

                # Filter clean package name format
                if not re.match(r"^[a-z0-9][a-z0-9\-_]{1,63}$", norm_name):
                    continue
                if norm_name in held_out:
                    continue

                # Parse model set e.g. "{'Deepseek_6B', 'Magicoder_6B'}"
                model_str = item[2]
                try:
                    models = ast.literal_eval(model_str)
                    if isinstance(models, set):
                        for m in models:
                            rows.append({
                                "name": norm_name,
                                "source": "spracklen",
                                "model": str(m)
                            })
                    else:
                        rows.append({"name": norm_name, "source": "spracklen", "model": "unknown"})
                except Exception:
                    rows.append({"name": norm_name, "source": "spracklen", "model": "spracklen_llm"})

        log.info("Loaded %d hallucination evidence records from Spracklen dataset.", len(rows))
    except Exception as e:
        log.warning("Failed to parse Spracklen dataset: %s", e)

    return rows


def save_evidence(rows: list[dict]) -> None:
    """Insert rows into the PostgreSQL evidence table or save locally."""
    if not rows:
        log.info("No evidence rows to save.")
        return

    saved_to_db = False
    try:
        from gateway import db
        pool = db._get_pool()
        if pool is not None:
            with pool.connection() as conn:
                for r in rows:
                    conn.execute(
                        "INSERT INTO evidence (name, source, model) VALUES (%s, %s, %s)",
                        (r["name"], r["source"], r["model"])
                    )
            log.info("Saved %d records into PostgreSQL 'evidence' table.", len(rows))
            saved_to_db = True
    except Exception as e:
        log.warning("Could not write to Postgres: %s", e)

    # Always persist locally to JSON and CSV as an offline artifact
    out_dir = DATA_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "harvested_evidence.json"
    csv_path = out_dir / "harvested_evidence.csv"

    # Save JSON
    existing = []
    if json_path.exists():
        try:
            existing = json.loads(json_path.read_text(encoding="utf-8"))
        except Exception:
            existing = []
    combined = existing + rows
    # Deduplicate
    unique = []
    seen = set()
    for item in combined:
        key = (item["name"], item["source"], item["model"])
        if key not in seen:
            seen.add(key)
            unique.append(item)

    json_path.write_text(json.dumps(unique, indent=2), encoding="utf-8")

    # Save CSV
    with csv_path.open(mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "source", "model"])
        writer.writeheader()
        writer.writerows(unique)

    log.info("Persisted %d total unique evidence records to %s and %s", len(unique), json_path.name, csv_path.name)
    if not saved_to_db:
        log.info("Note: DATABASE_URL not connected; records saved to local data files.")


def main():
    parser = argparse.ArgumentParser(description="PackGuard Live AI Hallucination Harvesting")
    parser.add_argument("--provider", choices=["gemini", "groq", "both"], default="both", help="LLM provider to query")
    parser.add_argument("--spracklen", action="store_true", help="Also ingest Spracklen et al. academic benchmark dataset")
    parser.add_argument("--limit", type=int, default=10, help="Number of prompts to run per provider")
    args = parser.parse_args()

    prompts = DEFAULT_PROMPTS[:args.limit]
    evidence_rows = []

    if args.spracklen:
        evidence_rows.extend(load_spracklen())

    if args.provider in ("gemini", "both"):
        if GEMINI_API_KEY:
            evidence_rows.extend(collect_from_llm("gemini", prompts))
        else:
            log.warning("GEMINI_API_KEY missing from environment. Skipping Gemini.")

    if args.provider in ("groq", "both"):
        if GROQ_API_KEY:
            evidence_rows.extend(collect_from_llm("groq", prompts))
        else:
            log.warning("GROQ_API_KEY missing from environment. Skipping Groq.")

    save_evidence(evidence_rows)
    log.info("Evidence harvesting pipeline finished successfully.")


if __name__ == "__main__":
    main()
