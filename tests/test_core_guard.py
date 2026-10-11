from datetime import datetime, timedelta, timezone

import httpx
import pytest

from core_guard import checks

SIX_JSON = {
    "info": {
        "name": "six",
        "summary": "Python 2 and 3 compatibility utilities",
        "description": "long text " * 50,
        "author": "Benjamin Peterson",
        "home_page": "",
        "project_urls": {"Homepage": "https://github.com/benjaminp/six"},
    },
    "releases": {
        "1.0.0": [{"upload_time_iso_8601": "2011-01-01T00:00:00.000000Z", "yanked": False}],
        "1.17.0": [
            {"upload_time_iso_8601": "2024-12-04T17:35:26.475339Z", "yanked": False},
            {"upload_time_iso_8601": "2024-12-04T17:35:28.174328Z", "yanked": False},
        ],
        "1.1.0b1": [{"upload_time_iso_8601": "2012-01-01T00:00:00.000000Z", "yanked": True}],
        "0.0.0": [],  # empty release, should not count
    },
}

OSV = {
    "ctx": {"vulns": [
        {"id": "GHSA-4g82-3jcr-q52w", "summary": "Malware in ctx"},
        {"id": "GHSA-67r3-h899-9w95", "summary": "Embedded Malicious Code in ctx"},
        {"id": "PYSEC-2022-199", "summary": ""},
    ]},
    "requests": {"vulns": [
        {"id": "GHSA-9hjg-9r4m-mvj7", "summary": "Requests vulnerable to .netrc credentials leak via malicious URLs"},
        {"id": "GHSA-x", "summary": "Bug", "database_specific": {"cwe_ids": ["CWE-200"]}},
    ]},
    "evilpkg": {"vulns": [{"id": "MAL-2024-1234", "summary": "Malicious code in evilpkg (PyPI)"}]},
    "taggedpkg": {"vulns": [{"id": "GHSA-y", "summary": "Bad", "database_specific": {"cwe_ids": ["CWE-506"]}}]},
}


@pytest.fixture(autouse=True)
def fake_network(monkeypatch):
    calls = []

    def handler(request: httpx.Request):
        calls.append(request.url.path)
        if request.url.host == "pypi.org":
            name = request.url.path.split("/")[2]
            if name == "six":
                return httpx.Response(200, json=SIX_JSON)
            if name == "broken":
                return httpx.Response(503)
            return httpx.Response(404, json={"message": "Not Found"})
        if request.url.host == "api.osv.dev":
            body = httpx.Request("POST", "x", content=request.content).read()
            import json

            payload = json.loads(body)
            name = payload["package"]["name"]
            if name == "paged":
                if "page_token" not in payload:
                    return httpx.Response(200, json={"vulns": [{"id": "A-1"}], "next_page_token": "t"})
                return httpx.Response(200, json={"vulns": [{"id": "MAL-2"}]})
            return httpx.Response(200, json=OSV.get(name, {}))
        return httpx.Response(500)

    checks.clear_cache()
    monkeypatch.setattr(checks, "http", httpx.Client(transport=httpx.MockTransport(handler)))
    yield calls
    checks.clear_cache()


# exists


def test_exists_true_and_false():
    assert checks.exists("six") is True
    assert checks.exists("does-not-exist") is False


def test_exists_raises_on_server_error():
    with pytest.raises(httpx.HTTPStatusError):
        checks.exists("broken")


def test_exists_and_metadata_share_one_request(fake_network):
    checks.exists("six")
    checks.metadata("six")
    assert fake_network == ["/pypi/six/json"]


# metadata


def test_metadata():
    meta = checks.metadata("six")
    assert meta["releases"] == 3
    assert meta["yanked_releases"] == 1
    assert meta["first_upload"] == "2011-01-01T00:00:00.000000Z"
    assert meta["latest_upload"] == "2024-12-04T17:35:28.174328Z"
    assert meta["has_repository"] is True
    assert meta["repository_url"] == "https://github.com/benjaminp/six"
    assert meta["author"] == "Benjamin Peterson"
    assert meta["description_length"] == len("long text " * 50)


def test_metadata_missing_package():
    assert checks.metadata("does-not-exist") == {}


# typosquat

TOP = ["requests", "numpy", "python-dateutil", "six", "boto3", "urllib3", "Django"]


def test_typosquat_close_names():
    assert checks.typosquat("reqeusts", TOP) == ["requests"]  # distance 2
    assert checks.typosquat("requestss", TOP) == ["requests"]  # distance 1
    assert checks.typosquat("djang0", TOP) == ["django"]


def test_typosquat_exact_and_normalized_are_not_typosquats():
    assert checks.typosquat("requests", TOP) == []
    assert checks.typosquat("Python_Dateutil", TOP) == []
    assert checks.typosquat("DJANGO", TOP) == []


def test_typosquat_popular_package_is_never_flagged():
    # urllib3 is distance 1 from "urllib2"-like names but is itself popular
    assert checks.typosquat("urllib3", TOP + ["urllib2"]) == []


def test_typosquat_short_names_only_distance_one():
    assert checks.typosquat("nunpy", TOP) == ["numpy"]  # distance 1
    assert checks.typosquat("nmupy", TOP) == []  # distance 2, but short name
    assert checks.typosquat("sxx", TOP) == ["six"]  # distance 1
    assert checks.typosquat("sxy", TOP) == []  # distance 2


def test_typosquat_unrelated_and_empty_list():
    assert checks.typosquat("flask", TOP) == []
    assert checks.typosquat("reqeusts", []) == []


# security


def test_security_known_malicious_by_summary():
    s = checks.security("ctx")
    assert s["known_malicious"] is True
    assert s["malicious_ids"] == ["GHSA-4g82-3jcr-q52w", "GHSA-67r3-h899-9w95"]
    assert s["vulnerabilities"] == ["PYSEC-2022-199"]


def test_security_normal_vulns_are_not_malicious():
    s = checks.security("requests")
    assert s["known_malicious"] is False
    assert s["vulnerabilities"] == ["GHSA-9hjg-9r4m-mvj7", "GHSA-x"]


def test_security_mal_id_and_cwe_tag():
    assert checks.security("evilpkg")["known_malicious"] is True
    assert checks.security("taggedpkg")["known_malicious"] is True


def test_security_clean_package():
    assert checks.security("six") == {"known_malicious": False, "malicious_ids": [], "vulnerabilities": []}


def test_security_follows_pages():
    s = checks.security("paged")
    assert s["malicious_ids"] == ["MAL-2"]
    assert s["vulnerabilities"] == ["A-1"]


# baseline_score


def iso_days_ago(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


OLD_GOOD = {"releases": 30, "first_upload": iso_days_ago(4000), "has_repository": True}
NEW_SMALL = {"releases": 1, "first_upload": iso_days_ago(3), "has_repository": False}
YOUNG_GOOD = {"releases": 8, "first_upload": iso_days_ago(200), "has_repository": True}
OLD_ONE_RELEASE = {"releases": 1, "first_upload": iso_days_ago(2000), "has_repository": True}


@pytest.mark.parametrize(
    "signals, expected, rules",
    [
        ({}, 0.0, []),
        ({"exists_on_pypi": True, "metadata": OLD_GOOD}, 0.0, []),
        ({"exists_on_pypi": True, "metadata": NEW_SMALL}, 0.352,
         ["new_package", "single_release", "no_repository"]),
        # established package that only looks like a popular name (httpie vs httpx)
        ({"exists_on_pypi": True, "metadata": OLD_GOOD, "typosquat_of": ["httpx"]}, 0.0, []),
        ({"exists_on_pypi": True, "metadata": YOUNG_GOOD, "typosquat_of": ["requests"]}, 0.7, ["typosquat"]),
        # old but only one release is not established
        ({"exists_on_pypi": True, "metadata": OLD_ONE_RELEASE, "typosquat_of": ["requests"]}, 0.73,
         ["typosquat", "single_release"]),
        # metadata check failed, so typosquat still counts
        ({"typosquat_of": ["requests"]}, 0.7, ["typosquat"]),
        ({"exists_on_pypi": True, "metadata": NEW_SMALL, "typosquat_of": ["requests"]}, 0.8056,
         ["typosquat", "new_package", "single_release", "no_repository"]),
        ({"exists_on_pypi": False}, 0.9, ["not_on_pypi"]),
        ({"exists_on_pypi": True, "security": {"known_malicious": True}}, 1.0, ["known_malicious"]),
        ({"hallucination_evidence": {"count": 1, "models": ["a"]}}, 0.5, ["hallucinated"]),
        ({"hallucination_evidence": {"count": 3, "models": ["a", "b"]}}, 0.7, ["hallucinated_multi_model"]),
        ({"exists_on_pypi": True, "metadata": NEW_SMALL,
          "hallucination_evidence": {"count": 2, "models": ["a", "b"]}}, 0.8056,
         ["hallucinated_multi_model", "new_package", "single_release", "no_repository"]),
    ],
)
def test_baseline_score(signals, expected, rules):
    assert checks.baseline_rules(signals) == rules
    assert checks.baseline_score(signals) == pytest.approx(expected, abs=1e-4)


def test_baseline_ignores_vulnerabilities():
    # Old CVEs say nothing about slopsquatting, and pip may pick a fixed version.
    assert checks.baseline_score({"security": {"known_malicious": False, "vulnerabilities": ["X"] * 50}}) == 0.0


def test_top_packages_file_is_valid():
    from gateway.evaluate import TOP_PACKAGES

    assert len(TOP_PACKAGES) >= 1000
    assert "requests" in TOP_PACKAGES
    assert all(name == checks._normalize(name) for name in TOP_PACKAGES)
