# PackGuard threat model (FYP-I)

Owner: Arslan. This covers the installation path that FYP-I builds: pip, the PackGuard gateway, PyPI, and the Postgres database. The runtime sandbox and the dashboard come in FYP-II and get their own section then.

## What we protect

- The developer machine or CI runner that runs `pip install`. Installing a package can run its code (setup.py, build hooks) and the code runs again at import.
- The project that the package ends up in.
- PackGuard's own decision record, so an audit can trust it.

## How a request flows

1. pip is set up once with `--index-url http://<packguard>/simple` (or `PIP_INDEX_URL`, or pip.conf).
2. pip asks `GET /simple/<name>/`.
3. PackGuard normalizes the name, collects signals (PyPI registry, metadata, typosquat, security advisories, AI hallucination evidence), scores it, and decides.
4. Block gives 403, and pip stops. Allow and warn pass the PyPI page through, and pip downloads the file from PyPI's file host.
5. Every decision is written to the `decisions` table.

## Attackers and what they want

| Attacker | Goal |
|---|---|
| Slopsquatter | Registers a name that AI assistants hallucinate, so developers who trust the AI install malware. This is the main threat. |
| Typosquatter | Registers a name one or two letters off a popular package (`reqeusts`). |
| Malicious publisher | Publishes a package that looks useful but steals secrets or opens a backdoor at install or import time. |
| Dependency attacker | Hides the bad package as a dependency of a harmless one, so it is never typed by the developer. |
| Network attacker | Sits between pip and PackGuard, or between PackGuard and PyPI, and changes responses. |
| Attacker against PackGuard | Tries to get PackGuard to allow a bad package, crash it, or fill the database with junk. |

## Threats and how PackGuard handles them

| # | Threat | What we do now (FYP-I) | Left for later |
|---|---|---|---|
| T1 | Developer installs an AI-hallucinated name that an attacker registered | Evidence table from the Spracklen dataset and our own Gemini/Groq prompts, with cross-model counting. AI risk model scores it. | Keep the evidence table updated. |
| T2 | Name does not exist yet (attacker may register it later) | `exists` check flags it, and it is still recorded, so we notice if it shows up later. | Alert when a flagged name gets registered. |
| T3 | Typosquat of a popular package | `typosquat` check against the top packages list. | |
| T4 | Known malicious or vulnerable package | `security` check against OSV and the OpenSSF malicious-packages list. | |
| T5 | New package with suspicious metadata (one release, no repo, very new) | `metadata` check and the baseline score. | |
| T6 | Bad package pulled in as a dependency | pip asks the index for every dependency too, so each one goes through the same checks. | Show the dependency tree on the dashboard. |
| T7 | Behaviour that only shows up when the code runs | Not covered in FYP-I. Metadata only. | Runtime sandbox for uncertain packages (FYP-II). |
| T8 | PyPI is slow or down | Gateway returns 502 instead of hanging or crashing. A check that fails is shown in the reasons. | Decide on fail open vs fail closed per project policy. |
| T9 | A check crashes or is not finished | Skipped and listed in the signals, gateway keeps working. | |
| T10 | Package changes after we checked it (new malicious release) | Cache lasts `PACKAGE_CACHE_TTL_HOURS` (default 24). | Check the specific version and file hashes. |
| T11 | Tampering between pip and PackGuard | Local or private network only in FYP-I. | HTTPS in front of the gateway for the AWS deployment. |
| T12 | Tampering between PackGuard and PyPI | HTTPS to pypi.org. pip checks the file hashes listed on the page. | |
| T13 | Developer bypasses PackGuard (`--index-url` back to PyPI) | Out of scope. PackGuard is a guard rail, not a lock. | CI demo that only allows installs through PackGuard. |
| T14 | Secrets leak (API keys, database password) | `.env` is git ignored, only `.env.example` with empty values is committed. Repo is public. | Secret scanning in CI. |
| T15 | Junk or very long names sent to fill the database | Names are normalized. | Rate limits and name length limits. |
| T16 | Training data leaks into the test set and makes results look better than they are | Held-out test set locked in `risk/data/test/`, never used for training or the evidence table. | |

## Known gaps in FYP-I

- `warn` behaves like `allow` for pip, because pip cannot show a message from the index. The warning is in the gateway log, the `X-PackGuard-Decision` header and the decisions table.
- Only the package name is checked, not the exact version pip picks, because pip asks the index by name.
- If the database is down, decisions are only logged. pip installs are not blocked by a database problem.
