"""Postgres access for the gateway.

If DATABASE_URL is not set, every function here does nothing, so the gateway
and the tests still run without a database. Database errors are logged and
never crash a pip request.
"""
import json
import logging
import os
import threading
from datetime import timedelta

from psycopg.types.json import Jsonb

log = logging.getLogger("packguard.db")

DATABASE_URL = os.getenv("DATABASE_URL") or ""
CACHE_TTL = timedelta(hours=float(os.getenv("PACKAGE_CACHE_TTL_HOURS") or 24))

_pool = None
_lock = threading.Lock()


def _json(value):
    # default=str so dates and other odd values do not break the insert.
    return Jsonb(value, dumps=lambda v: json.dumps(v, default=str))


def _get_pool():
    global _pool
    if not DATABASE_URL:
        return None
    with _lock:
        if _pool is None:
            from psycopg_pool import ConnectionPool

            _pool = ConnectionPool(DATABASE_URL, min_size=1, max_size=5, timeout=3, open=True)
    return _pool


def close():
    global _pool
    with _lock:
        if _pool is not None:
            _pool.close()
            _pool = None


def save_decision(name: str, version: str | None, result) -> None:
    pool = _get_pool()
    if pool is None:
        return
    try:
        with pool.connection() as conn:
            conn.execute(
                "INSERT INTO decisions (name, version, decision, score, reasons, signals)"
                " VALUES (%s, %s, %s, %s, %s, %s)",
                (name, version, result.decision, result.score, _json(result.reasons), _json(result.signals)),
            )
    except Exception as e:
        log.warning("could not save decision for %s: %s", name, e)


def get_cached_package(name: str) -> dict | None:
    """Return {"exists_on_pypi", "metadata"} if checked within CACHE_TTL, else None."""
    pool = _get_pool()
    if pool is None:
        return None
    try:
        with pool.connection() as conn:
            row = conn.execute(
                "SELECT exists_on_pypi, metadata FROM packages"
                " WHERE name = %s AND last_checked > now() - %s",
                (name, CACHE_TTL),
            ).fetchone()
    except Exception as e:
        log.warning("could not read package cache for %s: %s", name, e)
        return None
    if row is None:
        return None
    return {"exists_on_pypi": row[0], "metadata": row[1]}


def save_package(name: str, exists_on_pypi: bool, metadata: dict | None) -> None:
    pool = _get_pool()
    if pool is None:
        return
    try:
        with pool.connection() as conn:
            conn.execute(
                "INSERT INTO packages (name, exists_on_pypi, metadata, last_checked)"
                " VALUES (%s, %s, %s, now())"
                " ON CONFLICT (name) DO UPDATE SET exists_on_pypi = EXCLUDED.exists_on_pypi,"
                " metadata = EXCLUDED.metadata, last_checked = now()",
                (name, exists_on_pypi, _json(metadata)),
            )
    except Exception as e:
        log.warning("could not save package %s: %s", name, e)


def get_evidence(name: str) -> list[dict] | None:
    """Return hallucination evidence rows for a normalized name.

    None means there is no database, which is different from "no evidence" ([]).
    """
    pool = _get_pool()
    if pool is None:
        return None
    try:
        with pool.connection() as conn:
            rows = conn.execute("SELECT source, model FROM evidence WHERE name = %s", (name,)).fetchall()
    except Exception as e:
        log.warning("could not read evidence for %s: %s", name, e)
        return None
    return [{"source": r[0], "model": r[1]} for r in rows]
