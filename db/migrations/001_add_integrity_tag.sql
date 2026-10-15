
-- =====================================================
-- SYNTHSHIELD
-- Stage 8.4.2 - Audit Integrity Database Migration
-- =====================================================

-- Add a new column for HMAC-SHA256 integrity tags.
-- Existing security events remain unchanged.

ALTER TABLE security_events
ADD COLUMN IF NOT EXISTS integrity_tag TEXT;


-- Ensure that new non-NULL tags are valid
-- 64-character lowercase hexadecimal strings.
--
-- NULL remains permitted for historical events
-- created before integrity signing was enabled.

DO $$
BEGIN

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'valid_integrity_tag'
          AND conrelid = 'security_events'::regclass
    ) THEN

        ALTER TABLE security_events
        ADD CONSTRAINT valid_integrity_tag
        CHECK (
            integrity_tag IS NULL
            OR integrity_tag ~ '^[0-9a-f]{64}$'
        );

    END IF;

END
$$;


-- Display the current integrity-signing status.

SELECT
    COUNT(*) AS total_events,
    COUNT(integrity_tag) AS signed_events,
    COUNT(*) FILTER (
        WHERE integrity_tag IS NULL
    ) AS legacy_unsigned_events
FROM security_events;
