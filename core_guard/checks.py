"""Core Guard checks. Owner: Asad.

Each check returns plain data (signals). The gateway combines them into a decision.
"""


def exists(name: str) -> bool:
    """Return True if the package exists on PyPI.

    Hint: GET https://pypi.org/pypi/{name}/json with httpx.
    200 means it exists, 404 means not found. Handle timeouts and other
    errors so the gateway does not crash.
    """
    raise NotImplementedError


def typosquat(name: str, top_packages: list[str]) -> list[str]:
    """Return popular package names that `name` looks like a typo of.

    Hint: use rapidfuzz.distance.Levenshtein.distance(name, top).
    A distance of 1 to 2 is suspicious. An exact match (distance 0)
    is the real package, so it is not a typosquat.
    rapidfuzz is not in requirements.txt yet, add it when you implement this.
    """
    raise NotImplementedError


def metadata(name: str) -> dict:
    """Return useful metadata for the package.

    Hint: reuse the PyPI JSON response. Useful fields: first upload date,
    number of releases, author, home page or repository URL, description length.
    """
    raise NotImplementedError


def baseline_score(signals: dict) -> float:
    """Rule based risk score from the signals, between 0 and 1 (1 = risky).

    Hint: not on PyPI means high risk, a typosquat match means high risk,
    a very new package with one release and no repository means medium risk.
    This is also the baseline that the AI model is compared against.
    """
    raise NotImplementedError
