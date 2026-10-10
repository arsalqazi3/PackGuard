"""Builds the AI-hallucination evidence table. Owner: Ammar.

Run as: python -m risk.collect_evidence

Plan:
1. Load the Spracklen et al. dataset (MIT licence,
   https://github.com/Spracks/PackageHallucination) and insert each
   hallucinated name with source='spracklen' and the model it came from.
2. Run a curated prompt set (keep it in risk/data/prompts/) through Gemini
   (GEMINI_API_KEY) and Groq (GROQ_API_KEY). Pull the package names out of
   each answer (pip install lines and import lines), check them against PyPI,
   and insert the ones that do not exist with source='gemini' or 'groq'.
3. Store names normalized the PEP 503 way (gateway.main.normalize), because the
   gateway looks evidence up by normalized name.
4. Never insert names that are in the held-out test set in risk/data/test/.

A name that shows up from more than one model is cross-model evidence. The
gateway already counts distinct models per name in signals["hallucination_evidence"].
"""


def load_spracklen(path: str) -> list[dict]:
    """Return rows like {"name": ..., "source": "spracklen", "model": ...}."""
    raise NotImplementedError


def collect_from_llm(provider: str, prompts: list[str]) -> list[dict]:
    """Ask `provider` ("gemini" or "groq") each prompt and return hallucinated names as rows."""
    raise NotImplementedError


def save_evidence(rows: list[dict]) -> None:
    """Insert rows into the evidence table using DATABASE_URL."""
    raise NotImplementedError


if __name__ == "__main__":
    raise SystemExit("Not implemented yet, see the plan at the top of this file.")
