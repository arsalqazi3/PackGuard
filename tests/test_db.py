"""Database tests. They run only when TEST_DATABASE_URL points at a throwaway
Postgres (CI sets this up). The tables are emptied before each test."""
import os
from pathlib import Path

import pytest

from gateway import db
from gateway.contracts import EvaluateResponse

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_DATABASE_URL, reason="TEST_DATABASE_URL not set")

SCHEMA = Path(__file__).resolve().parent.parent / "db" / "schema.sql"


@pytest.fixture
def conn(monkeypatch):
    import psycopg

    with psycopg.connect(TEST_DATABASE_URL, autocommit=True) as c:
        c.execute(SCHEMA.read_text())
        c.execute("TRUNCATE packages, evidence, decisions")
        monkeypatch.setattr(db, "DATABASE_URL", TEST_DATABASE_URL)
        monkeypatch.setattr(db, "_pool", None)
        yield c
        db.close()


def test_save_decision(conn):
    result = EvaluateResponse(decision="warn", score=0.6, reasons=["r"], signals={"a": 1})
    db.save_decision("six", "1.17.0", result)
    row = conn.execute("SELECT name, version, decision, score, reasons, signals FROM decisions").fetchone()
    assert row == ("six", "1.17.0", "warn", pytest.approx(0.6), ["r"], {"a": 1})


def test_package_cache(conn):
    assert db.get_cached_package("six") is None
    db.save_package("six", True, {"first_upload": "2010-01-01"})
    assert db.get_cached_package("six") == {"exists_on_pypi": True, "metadata": {"first_upload": "2010-01-01"}}
    db.save_package("six", False, None)  # upsert, not a duplicate row
    assert db.get_cached_package("six") == {"exists_on_pypi": False, "metadata": None}
    conn.execute("UPDATE packages SET last_checked = now() - interval '1000 hours'")
    assert db.get_cached_package("six") is None


def test_evidence(conn):
    assert db.get_evidence("fakepkg") == []
    conn.execute("INSERT INTO evidence (name, source, model) VALUES ('fakepkg', 'gemini', 'g1'), ('fakepkg', 'spracklen', NULL)")
    assert sorted(db.get_evidence("fakepkg"), key=lambda r: r["source"]) == [
        {"source": "gemini", "model": "g1"},
        {"source": "spracklen", "model": None},
    ]


def test_bad_database_does_not_crash(monkeypatch):
    monkeypatch.setattr(db, "DATABASE_URL", "postgresql://nobody:nothing@127.0.0.1:1/none")
    monkeypatch.setattr(db, "_pool", None)
    db.save_decision("six", None, EvaluateResponse(decision="allow", score=0.0))
    assert db.get_cached_package("six") is None
    assert db.get_evidence("six") is None
    db.close()
