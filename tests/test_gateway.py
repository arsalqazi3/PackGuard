from fastapi.testclient import TestClient

from gateway.evaluate import decide
from gateway.main import app, normalize

client = TestClient(app)


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


def test_evaluate_contract_keys():
    r = client.post("/evaluate", json={"name": "six"})
    assert r.status_code == 200
    assert set(r.json().keys()) == {"decision", "score", "reasons", "signals"}


def test_thresholds():
    assert decide(0.1) == "allow"
    assert decide(0.6) == "warn"
    assert decide(0.9) == "block"
