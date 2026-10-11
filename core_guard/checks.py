"""Core Guard checks. Owner: Asad.

Each check returns plain data (signals). The gateway combines them into a
decision, and the signal keys are listed in gateway/contracts.py.

Network errors are not caught here on purpose. The gateway records a failed
check in signals["errors"] and keeps going.
"""
import re
import threading
import time
from datetime import datetime, timezone

import httpx
from rapidfuzz import process
from rapidfuzz.distance import Levenshtein

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# Short timeouts so a slow PyPI or OSV cannot hold up pip for long.
http = httpx.Client(timeout=httpx.Timeout(8.0, connect=4.0), follow_redirects=True)

# Small in-memory cache, so exists() and metadata() share one PyPI call and a
# pip run that asks for the same package twice does not hit OSV twice.
CACHE_SECONDS = 300
_cache: dict[tuple[str, str], tuple[float, object]] = {}
_cache_lock = threading.Lock()

REPO_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "sr.ht")
NEW_PACKAGE_DAYS = 30


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _cached(kind: str, name: str, fetch):
    key = (kind, name)
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < CACHE_SECONDS:
            return hit[1]
    value = fetch()
    with _cache_lock:
        _cache[key] = (now, value)
    return value


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


def _pypi_json(name: str) -> dict | None:
    """PyPI JSON for the package, or None if PyPI says 404."""

    def fetch():
        r = http.get(PYPI_JSON_URL.format(name=name))
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    return _cached("pypi", name, fetch)


def exists(name: str) -> bool:
    """True if the package exists on PyPI (200), False if PyPI says 404.

    Any other status or a timeout raises, so the gateway shows the check as failed
    instead of guessing.
    """
    return _pypi_json(name) is not None


def metadata(name: str) -> dict:
    """Facts about the package from the PyPI JSON API. All values are JSON safe.

    Keys: releases, first_upload, latest_upload (ISO strings or None),
    has_repository, repository_url, author, summary, description_length,
    yanked_releases.
    """
    data = _pypi_json(name)
    if data is None:
        return {}
    info = data.get("info") or {}

    uploads = []
    releases = 0
    yanked = 0
    for files in (data.get("releases") or {}).values():
        if not files:
            continue
        releases += 1
        if all(f.get("yanked") for f in files):
            yanked += 1
        uploads += [f["upload_time_iso_8601"] for f in files if f.get("upload_time_iso_8601")]
    uploads.sort()

    urls = [info.get("home_page") or ""] + list((info.get("project_urls") or {}).values())
    repo = next((u for u in urls if u and any(h in u.lower() for h in REPO_HOSTS)), None)

    return {
        "releases": releases,
        "yanked_releases": yanked,
        "first_upload": uploads[0] if uploads else None,
        "latest_upload": uploads[-1] if uploads else None,
        "has_repository": repo is not None,
        "repository_url": repo,
        "author": info.get("author") or info.get("author_email") or None,
        "summary": info.get("summary") or "",
        "description_length": len(info.get("description") or ""),
    }


def typosquat(name: str, top_packages: list[str]) -> list[str]:
    """Popular package names that `name` is suspiciously close to.

    Names are compared after PEP 503 normalization, so "Requests" and
    "requests" are the same and "python_dateutil" is the real "python-dateutil".
    Close means Levenshtein distance 1 to 2. For short names (5 letters or
    fewer) only distance 1 counts, because almost every short name is within 2
    of some other short name. A name that is itself a popular package is never
    a typosquat.
    """
    name = _normalize(name)
    top, top_set = _prepare_top(top_packages)
    if name in top_set:
        return []
    max_distance = 1 if len(name) <= 5 else 2
    matches = process.extract(
        name, top, scorer=Levenshtein.distance, score_cutoff=max_distance, limit=None
    )
    matches = sorted((d, c) for c, d, _ in matches if 0 < d <= max_distance)
    return [c for _, c in matches[:5]]


_top_memo: dict[int, tuple[list, list[str], set[str]]] = {}


def _prepare_top(top_packages: list[str]) -> tuple[list[str], set[str]]:
    # The gateway passes the same list every time, so normalize it only once.
    hit = _top_memo.get(id(top_packages))
    if hit and hit[0] is top_packages and len(hit[1]) == len(top_packages):
        return hit[1], hit[2]
    top = [_normalize(t) for t in top_packages]
    _top_memo.clear()
    _top_memo[id(top_packages)] = (top_packages, top, set(top))
    return top, set(top)


MALWARE_SUMMARY = re.compile(r"^\s*(malware|malicious code|embedded malicious code)\b", re.I)


def _is_malicious(vuln: dict) -> bool:
    """True only for advisories about the package itself being malware.

    MAL- ids come from the OpenSSF malicious-packages repo. Older malware
    reports are GitHub advisories tagged CWE-506 or titled "Malware in ...".
    A plain keyword search is not enough: normal bugs often say things like
    "malicious URLs" (requests) or "malicious filenames" (jinja2).
    """
    if vuln.get("id", "").startswith("MAL-"):
        return True
    if "CWE-506" in ((vuln.get("database_specific") or {}).get("cwe_ids") or []):
        return True
    return bool(MALWARE_SUMMARY.match(vuln.get("summary") or ""))


def security(name: str) -> dict:
    """Known security problems from OSV (includes the OpenSSF malicious-packages data).

    Returns {"known_malicious": bool, "malicious_ids": [...], "vulnerabilities": [...]}.
    The vulnerability list covers all versions, because pip asks the index by
    name only and we do not know which version it will pick.
    """

    def fetch():
        payload = {"package": {"name": name, "ecosystem": "PyPI"}}
        vulns = []
        for _ in range(10):  # OSV pages large results, 10 pages is plenty
            r = http.post(OSV_QUERY_URL, json=payload)
            r.raise_for_status()
            body = r.json()
            vulns += body.get("vulns", [])
            token = body.get("next_page_token")
            if not token:
                break
            payload["page_token"] = token
        malicious = sorted(v["id"] for v in vulns if _is_malicious(v))
        others = sorted(v["id"] for v in vulns if not _is_malicious(v))
        return {"known_malicious": bool(malicious), "malicious_ids": malicious, "vulnerabilities": others}

    return _cached("osv", name, fetch)


def _age_days(iso: str | None) -> float | None:
    if not iso:
        return None
    first = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - first).total_seconds() / 86400


# Weight of each rule. They are combined as 1 - (1 - w1)(1 - w2)..., so each
# rule that fires pushes the score towards 1 and it never goes past 1.
RULES = {
    "known_malicious": 1.0,
    "not_on_pypi": 0.9,
    "hallucinated_multi_model": 0.7,
    "typosquat": 0.7,
    "hallucinated": 0.5,
    "new_package": 0.2,
    "single_release": 0.1,
    "no_repository": 0.1,
}


ESTABLISHED_DAYS = 365
ESTABLISHED_RELEASES = 3


def is_established(meta: dict) -> bool:
    """Old package with several releases. Used to stop typosquat false positives.

    About 11% of real packages ranked 5001 to 15000 on PyPI have a name within
    the typosquat distance of a top 5000 package (httpie vs httpx, willow vs
    pillow), but 97% of those are older than a year with 3 or more releases.
    Real typosquats are almost always new with one or two releases.
    """
    if not meta:
        return False
    age = _age_days(meta.get("first_upload"))
    return age is not None and age > ESTABLISHED_DAYS and meta.get("releases", 0) >= ESTABLISHED_RELEASES


def baseline_rules(signals: dict) -> list[str]:
    """Names of the rules in RULES that fire for these signals."""
    fired = []
    meta = signals.get("metadata") or {}
    if (signals.get("security") or {}).get("known_malicious"):
        fired.append("known_malicious")
    if signals.get("exists_on_pypi") is False:
        fired.append("not_on_pypi")
    # typosquat_of stays in the signals for the AI model either way.
    if signals.get("typosquat_of") and not is_established(meta):
        fired.append("typosquat")

    evidence = signals.get("hallucination_evidence") or {}
    if len(evidence.get("models") or []) >= 2:
        fired.append("hallucinated_multi_model")
    elif evidence.get("count"):
        fired.append("hallucinated")

    if meta:
        age = _age_days(meta.get("first_upload"))
        if age is not None and age < NEW_PACKAGE_DAYS:
            fired.append("new_package")
        if meta.get("releases", 0) <= 1:
            fired.append("single_release")
        if not meta.get("has_repository"):
            fired.append("no_repository")
    return fired


def baseline_score(signals: dict) -> float:
    """Rule based risk score between 0 and 1 (1 = risky).

    Examples with the default thresholds (warn 0.5, block 0.8):
    an old package with a repo scores 0 (allow), a new small package with one
    release and no repo scores 0.35 (allow), a typosquat that is not
    established scores at least 0.7 (warn), a fresh typosquat with one release
    and no repo scores 0.81 (block), a name that is not on PyPI scores 0.9 (block).
    An established package that only looks like a popular name scores 0.
    This is also the baseline the AI model is compared against.
    """
    safe = 1.0
    for rule in baseline_rules(signals):
        safe *= 1.0 - RULES[rule]
    return round(1.0 - safe, 4)
