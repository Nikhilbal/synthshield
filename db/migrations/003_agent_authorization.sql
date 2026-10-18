
-- SYNTHSHIELD Phase 10.3A
-- Trusted coalition scope and agent credentials.

CREATE TABLE IF NOT EXISTS coalition_scopes (
    scope_id UUID PRIMARY KEY,
    requested_task TEXT NOT NULL
        CHECK (length(btrim(requested_task)) > 0),
    accessed_sources TEXT[] NOT NULL
        DEFAULT ARRAY[]::TEXT[],
    created_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS authorized_agent_workflows (
    workflow_id UUID PRIMARY KEY,

    scope_id UUID NOT NULL
        REFERENCES coalition_scopes(scope_id)
        ON DELETE CASCADE,

    agent_id TEXT NOT NULL
        CHECK (length(btrim(agent_id)) > 0),

    credential_hash TEXT NOT NULL UNIQUE
        CHECK (
            credential_hash ~ '^[0-9a-f]{64}$'
        ),

    allowed_sources TEXT[] NOT NULL
        CHECK (cardinality(allowed_sources) > 0),

    active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS
    idx_authorized_workflows_scope
ON authorized_agent_workflows (scope_id);
