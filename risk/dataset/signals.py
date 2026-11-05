import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd

from gateway.evaluate import collect_signals
from risk.config import FEATURE_COLUMNS, SIGNAL_CACHE_DB
from risk.features.pipeline import extract_features


class SignalCache:
    """
    Saves the gateway's signals for each training package in a local SQLite file.
    Only complete results are saved, so a rerun retries the ones that failed.
    """
    def __init__(self, db_path: Path = SIGNAL_CACHE_DB):
        self.db_path = str(db_path)
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS signals (name TEXT PRIMARY KEY, data TEXT NOT NULL)")

    def get_many(self, names: List[str], workers: int = 8) -> Dict[str, dict]:
        with sqlite3.connect(self.db_path) as conn:
            found = {name: json.loads(data) for name, data in conn.execute("SELECT name, data FROM signals")}
        results = {name: found[name] for name in names if name in found}

        missing = [name for name in names if name not in found]
        if missing:
            print(f"Collecting signals for {len(missing)} packages (cached: {len(results)})...")
            with ThreadPoolExecutor(workers) as pool, sqlite3.connect(self.db_path) as conn:
                for name, signals in zip(missing, pool.map(collect_signals, missing)):
                    results[name] = signals
                    if not signals.get("errors"):
                        conn.execute(
                            "INSERT OR REPLACE INTO signals (name, data) VALUES (?, ?)",
                            (name, json.dumps(signals, default=str))
                        )
                        conn.commit()
        return results


def build_feature_table(
    df: pd.DataFrame, cache: Optional[SignalCache] = None
) -> Tuple[pd.DataFrame, pd.Series, List[dict]]:
    """
    Returns features, labels and raw signals for a package_name,label table.
    Packages whose signals are incomplete are left out and counted.
    """
    cache = cache or SignalCache()
    all_signals = cache.get_many(df["package_name"].tolist())

    rows, labels, kept_signals = [], [], []
    for name, label in zip(df["package_name"], df["label"]):
        signals = all_signals[name]
        features = extract_features(signals)
        if features is None:
            continue
        rows.append(features)
        labels.append(label)
        kept_signals.append(signals)

    dropped = len(df) - len(rows)
    if dropped:
        print(f"Left out {dropped} of {len(df)} packages with incomplete signals. Run again to retry them.")
    return pd.DataFrame(rows, columns=FEATURE_COLUMNS), pd.Series(labels, name="label"), kept_signals
