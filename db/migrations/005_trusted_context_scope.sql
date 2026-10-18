
-- SYNTHSHIELD Phase 10.3L
-- Trusted information-sharing contexts

BEGIN;

-- Existing coalition scopes remain valid.
-- Historical records will have NULL context_id.

ALTER TABLE coalition_scopes
ADD COLUMN IF NOT EXISTS context_id UUID;

-- Every assigned context maps to exactly
-- one coalition scope.

CREATE UNIQUE INDEX IF NOT EXISTS
    ux_coalition_scopes_context_id
ON coalition_scopes (context_id)
WHERE context_id IS NOT NULL;

COMMIT;
