import httpx
import pytest
from fastapi.testclient import TestClient

from core_guard import checks
from gateway import db, main
from gateway.evaluate import decide, evaluate
from gateway.main import app, normalize
from risk import model

client = TestClient(app)


def not_ready(*args):
    raise NotImplementedError


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    """No network and no database: every check starts as 'not implemented'."""
    monkeypatch.setattr(db, "DATABASE_URL", "")
    monkeypatch.setattr(db, "_pool", None)
    for fn in ("exists", "typosquat", "metadata", "security", "baseline_score"):
        monkeypatch.setattr(checks, fn, not_ready)
    monkeypatch.setattr(model, "score", not_ready)


@pytest.fixture
def fake_pypi(monkeypatch):
    def handler(request):
        return httpx.Response(200, text=f"<html>links for {request.url.path}</html>")

    monkeypatch.setattr(main, "http", httpx.Client(transport=httpx.MockTransport(handler)))


def test_normalize():
    assert normalize("Foo_Bar") == "foo-bar"
    assert normalize("foo.bar--baz") == "foo-bar-baz"
    assert normalize("Six") == "six"


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_blocked_package_returns_403():
    r = client.get("/simple/Evil_Test.Pkg/")
    assert r.status_code == 403
    assert "Blocked by PackGuard: evil-test-pkg" in r.text
    assert r.headers["X-PackGuard-Decision"] == "block"


def test_evaluate_contract_keys():
    r = client.post("/evaluate", json={"name": "six"})
    assert r.status_code == 200
    assert set(r.json().keys()) == {"decision", "score", "reasons", "signals"}


def test_thresholds():
    assert decide(0.1) == "allow"
    assert decide(0.6) == "warn"
    assert decide(0.9) == "block"


def test_unwritten_checks_are_skipped():
    result = evaluate("six")
    assert result.decision == "allow"
    assert result.score == 0.0
    assert set(result.signals["not_implemented"]) == {
        "exists", "typosquat", "security", "baseline_score", "risk_model"
    }


def test_score_is_max_of_baseline_and_model(monkeypatch):
    monkeypatch.setattr(checks, "baseline_score", lambda s: 0.3)
    monkeypatch.setattr(model, "score", lambda s: 0.9)
    result = evaluate("six")
    assert result.score == 0.9
    assert result.decision == "block"
    assert result.signals["baseline_score"] == 0.3
    assert result.signals["model_score"] == 0.9


def test_score_is_clamped(monkeypatch):
    monkeypatch.setattr(checks, "baseline_score", lambda s: 1.7)
    assert evaluate("six").score == 1.0


def test_signals_and_reasons(monkeypatch):
    monkeypatch.setattr(checks, "exists", lambda n: False)
    monkeypatch.setattr(checks, "typosquat", lambda n, top: ["requests"])
    monkeypatch.setattr(checks, "security", lambda n: {"known_malicious": True, "vulnerabilities": []})
    monkeypatch.setattr(db, "get_evidence", lambda n: [
        {"source": "spracklen", "model": "gpt-4"},
        {"source": "gemini", "model": "gemini-2.5"},
        {"source": "groq", "model": "gpt-4"},
    ])
    result = evaluate("reqeusts")
    assert result.signals["exists_on_pypi"] is False
    assert "metadata" not in result.signals  # not fetched for a missing package
    assert result.signals["hallucination_evidence"] == {
        "count": 3, "models": ["gemini-2.5", "gpt-4"], "sources": ["gemini", "groq", "spracklen"]
    }
    assert result.reasons == [
        "not found on PyPI",
        "name is close to popular package: requests",
        "listed as a known malicious package",
        "name seen in AI hallucination data (2 models)",
    ]


def test_crashing_check_is_reported(monkeypatch):
    def boom(name):
        raise TimeoutError("pypi slow")

    monkeypatch.setattr(checks, "exists", boom)
    result = evaluate("six")
    assert result.signals["errors"]["exists"] == "TimeoutError: pypi slow"
    assert "exists check failed" in result.reasons


def test_cached_package_skips_pypi_lookup(monkeypatch):
    monkeypatch.setattr(db, "get_cached_package", lambda n: {"exists_on_pypi": True, "metadata": {"releases": 5}})
    # exists is still not_ready, so if it were called it would show in not_implemented
    result = evaluate("six")
    assert result.signals["cached"] is True
    assert result.signals["metadata"] == {"releases": 5}
    assert "exists" not in result.signals["not_implemented"]


def test_only_complete_lookups_are_cached(monkeypatch):
    saved = []
    monkeypatch.setattr(db, "save_package", lambda *a: saved.append(a))
    monkeypatch.setattr(checks, "exists", lambda n: True)
    evaluate("six")  # metadata not written yet, so nothing is cached
    assert saved == []
    monkeypatch.setattr(checks, "metadata", lambda n: {"releases": 5})
    evaluate("six")
    assert saved == [("six", True, {"releases": 5})]


def test_allowed_package_is_proxied(fake_pypi):
    r = client.get("/simple/Six/")
    assert r.status_code == 200
    assert r.text == "<html>links for /simple/six/</html>"
    assert r.headers["content-type"].startswith("text/html")
    assert r.headers["X-PackGuard-Decision"] == "allow"


def test_pypi_down_returns_502(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("no route")

    monkeypatch.setattr(main, "http", httpx.Client(transport=httpx.MockTransport(handler)))
    r = client.get("/simple/six/")
    assert r.status_code == 502
    assert "could not reach PyPI" in r.text
