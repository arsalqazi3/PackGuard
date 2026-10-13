import os
import random
import json
import pandas as pd
from pathlib import Path
from typing import List, Tuple, Dict
from packguard.risk.config import (
    GROUND_TRUTH_DIR,
    PYPI_MASTER_LIST_PATH,
    AI_SUSPICIOUS_AFFIXES
)
from packguard.risk.features.lexical import normalize_package_name

# Fix random seed for reproducibility (essential for academic evaluation)
RANDOM_SEED = 42
random.seed(RANDOM_SEED)

# Core popular libraries commonly used by developers
BASE_POPULAR_LIBRARIES = [
    "requests", "flask", "django", "numpy", "pandas", "scipy", "scikit-learn",
    "torch", "tensorflow", "fastapi", "pydantic", "sqlalchemy", "celery",
    "redis", "pytest", "boto3", "httpx", "aiohttp", "pillow", "matplotlib",
    "jwt", "pyjwt", "cryptography", "paramiko", "docker", "beautifulsoup4",
    "selenium", "psycopg2", "mysqlclient", "grpcio", "protobuf", "urllib3",
    "click", "typer", "jinja2", "uvicorn", "gunicorn", "spacy", "nltk",
    "transformers", "huggingface-hub", "langchain", "openai", "anthropic"
]

def generate_synthetic_hallucinations(count: int = 1500) -> List[str]:
    """
    Generates realistic AI-hallucinated package names following observed empirical distributions
    from LLM studies (e.g., library-affix, task-specific affixes, phantom combinations).
    Examples: 'flask-jwt-helper', 'requests-oauth-util', 'pytorch-vision-core'.
    """
    hallucinations = set()
    affixes = list(AI_SUSPICIOUS_AFFIXES)

    prefixes = [
        "py", "python", "ai", "ml", "fast", "smart", "easy", "simple",
        "quick", "super", "micro", "deep", "auto", "async"
    ]

    domains = [
        "auth", "jwt", "oauth", "cache", "token", "crypto", "sql", "db",
        "mongo", "redis", "s3", "storage", "email", "sms", "scraper",
        "crawler", "parser", "validator", "serializer", "logger", "metrics",
        "tracer", "limiter", "router", "webhook", "exporter", "loader"
    ]

    while len(hallucinations) < count:
        strategy = random.randint(1, 6)
        if strategy == 1:
            # Base + Domain + Affix: flask-jwt-helper
            lib = random.choice(BASE_POPULAR_LIBRARIES)
            domain = random.choice(domains)
            affix = random.choice(affixes)
            name = f"{lib}-{domain}-{affix}"
        elif strategy == 2:
            # Base + Affix: requests-utils, pandas-helper
            lib = random.choice(BASE_POPULAR_LIBRARIES)
            affix = random.choice(affixes)
            name = f"{lib}-{affix}"
        elif strategy == 3:
            # Prefix + Domain + Affix: py-auth-helper, fast-cache-tools
            prefix = random.choice(prefixes)
            domain = random.choice(domains)
            affix = random.choice(affixes)
            name = f"{prefix}-{domain}-{affix}"
        elif strategy == 4:
            # Typosquat with Affix: reuqests-helper, fastappi-core
            lib = random.choice(BASE_POPULAR_LIBRARIES)
            if len(lib) > 4:
                idx = random.randint(1, len(lib) - 2)
                typo_lib = lib[:idx] + lib[idx+1] + lib[idx] + lib[idx+2:]
            else:
                typo_lib = lib + "s"
            affix = random.choice(affixes)
            name = f"{typo_lib}-{affix}"
        elif strategy == 5:
            # Pure Typosquats of popular packages (NO affix!)
            lib = random.choice(BASE_POPULAR_LIBRARIES)
            if len(lib) > 4:
                idx = random.randint(1, len(lib) - 2)
                name = lib[:idx] + lib[idx+1] + lib[idx] + lib[idx+2:]
            else:
                name = lib + random.choice(["s", "x", "z", "1"])
        else:
            # Phantom unregistered packages without affixes
            p1 = random.choice(prefixes)
            d1 = random.choice(domains)
            d2 = random.choice(domains)
            name = f"{p1}-{d1}-{d2}"

        norm = normalize_package_name(name)
        if norm:
            hallucinations.add(norm)

    return list(hallucinations)


def load_legitimate_packages(sample_size: int = 3000) -> List[str]:
    """Loads a representative sample of legitimate PyPI packages."""
    legitimate = set()

    # 1. Include core popular packages first
    for lib in BASE_POPULAR_LIBRARIES:
        norm = normalize_package_name(lib)
        if norm:
            legitimate.add(norm)

    # 2. Sample from PyPI master list
    if PYPI_MASTER_LIST_PATH.exists():
        with open(PYPI_MASTER_LIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
            all_lines = [line.strip().lower() for line in f if line.strip()]
        
        # Take a random sample from the 500k packages
        sampled = random.sample(all_lines, min(sample_size, len(all_lines)))
        for s in sampled:
            norm = normalize_package_name(s)
            if norm:
                legitimate.add(norm)

    return list(legitimate)


def build_and_split_dataset(total_samples: int = 4000) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Constructs the ground truth dataset and partitions into:
    - Train (70%)
    - Validation (15%)
    - Held-out Test (15%)
    Saves them to disk in GROUND_TRUTH_DIR.
    """
    half_samples = total_samples // 2
    legit_names = load_legitimate_packages(sample_size=half_samples)
    hallucinated_names = generate_synthetic_hallucinations(count=half_samples)

    # Ensure zero overlap
    overlap = set(legit_names).intersection(set(hallucinated_names))
    hallucinated_names = [h for h in hallucinated_names if h not in overlap]

    records = []
    for name in legit_names:
        records.append({"package_name": name, "label": 0, "type": "legitimate"})
    for name in hallucinated_names:
        records.append({"package_name": name, "label": 1, "type": "hallucinated"})

    df = pd.DataFrame(records)
    # Shuffle
    df = df.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)

    n_total = len(df)
    n_train = int(n_total * 0.70)
    n_val = int(n_total * 0.15)

    train_df = df.iloc[:n_train].copy()
    val_df = df.iloc[n_train:n_train + n_val].copy()
    test_df = df.iloc[n_train + n_val:].copy()

    # Save to disk
    train_path = GROUND_TRUTH_DIR / "train_ground_truth.csv"
    val_path = GROUND_TRUTH_DIR / "val_ground_truth.csv"
    test_path = GROUND_TRUTH_DIR / "held_out_test_ground_truth.csv"

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)

    print(f"Dataset generated successfully:")
    print(f" - Train: {len(train_df)} samples ({train_path})")
    print(f" - Val:   {len(val_df)} samples ({val_path})")
    print(f" - Test:  {len(test_df)} samples ({test_path})")

    return train_df, val_df, test_df

if __name__ == "__main__":
    build_and_split_dataset()
