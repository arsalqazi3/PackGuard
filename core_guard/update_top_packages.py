"""Rebuild core_guard/data/top_packages.txt, the list typosquat() compares against.

Run as: python -m core_guard.update_top_packages [count]

Source: https://hugovk.github.io/top-pypi-packages/ (most downloaded PyPI
packages over the last 30 days, built from the public PyPI BigQuery data).
"""
import sys
from pathlib import Path

import httpx

from core_guard.checks import _normalize

SOURCE_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
OUT_FILE = Path(__file__).resolve().parent / "data" / "top_packages.txt"


def main(count: int = 5000) -> None:
    r = httpx.get(SOURCE_URL, timeout=60, follow_redirects=True)
    r.raise_for_status()
    data = r.json()
    names = [_normalize(row["project"]) for row in data["rows"][:count]]
    OUT_FILE.parent.mkdir(exist_ok=True)
    header = f"# Top {len(names)} PyPI packages by downloads, last 30 days, updated {data['last_update']}\n"
    header += f"# Source: {SOURCE_URL}\n"
    OUT_FILE.write_text(header + "\n".join(names) + "\n", encoding="utf-8")
    print(f"wrote {len(names)} names to {OUT_FILE}")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 5000)
