
-- =====================================================
-- SYNTHSHIELD
-- Stage 7: PostgreSQL Security Events Schema
-- =====================================================

CREATE TABLE IF NOT EXISTS security_events (

    event_id UUID PRIMARY KEY,

    timestamp_utc TIMESTAMPTZ NOT NULL,

    agent_id TEXT NOT NULL,

    source_names TEXT[] NOT NULL,

    source_count INTEGER NOT NULL
        CHECK (source_count > 0),

    sensitive_inference BOOLEAN NOT NULL,

    purpose_drift BOOLEAN NOT NULL,

    risk_level TEXT NOT NULL
        CHECK (
            risk_level IN (
                'MINIMAL',
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL'
            )
        ),

    decision TEXT NOT NULL
        CHECK (
            decision IN (
                'ALLOW',
                'BLOCK'
            )
        ),

    recorded_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_source_count
        CHECK (
            source_count = cardinality(source_names)
        )
);


-- Quickly find events associated with an AI agent.

CREATE INDEX IF NOT EXISTS idx_security_events_agent
ON security_events (agent_id, timestamp_utc DESC);


-- Quickly find blocked or allowed events.

CREATE INDEX IF NOT EXISTS idx_security_events_decision
ON security_events (decision, timestamp_utc DESC);
