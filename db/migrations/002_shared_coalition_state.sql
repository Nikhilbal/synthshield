
-- SYNTHSHIELD - Phase 9D
-- PostgreSQL-backed shared workflow state.
-- This migration does not modify security_events.

CREATE TABLE IF NOT EXISTS workflow_coalitions (
    workflow_id UUID PRIMARY KEY,

    requested_task TEXT NOT NULL
        CHECK (length(btrim(requested_task)) > 0),

    accessed_sources TEXT[] NOT NULL
        DEFAULT ARRAY[]::TEXT[],

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS
    idx_workflow_coalitions_updated
ON workflow_coalitions (updated_at DESC);
