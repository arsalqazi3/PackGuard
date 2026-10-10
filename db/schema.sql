-- PackGuard schema (Postgres 16)

CREATE TABLE IF NOT EXISTS packages (
    name            TEXT PRIMARY KEY,
    exists_on_pypi  BOOLEAN,
    metadata        JSONB,
    last_checked    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS evidence (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    source      TEXT NOT NULL,  -- for example spracklen, gemini, groq
    model       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_evidence_name ON evidence (name);

CREATE TABLE IF NOT EXISTS decisions (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    version     TEXT,
    decision    TEXT NOT NULL CHECK (decision IN ('allow', 'warn', 'block')),
    score       REAL NOT NULL,
    reasons     JSONB NOT NULL DEFAULT '[]',
    signals     JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_decisions_created_at ON decisions (created_at DESC);
