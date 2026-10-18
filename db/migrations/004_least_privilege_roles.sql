
-- =====================================================
-- SYNTHSHIELD - PHASE 10.3E
-- PostgreSQL Least-Privilege Database Roles
-- =====================================================
--
-- Creates restricted service roles.
--
-- Does not modify or delete existing audit data.
-- Does not change the existing synthshield account.
--
-- Roles initially have NOLOGIN.
-- Passwords and login access will be configured
-- separately after permissions are verified.
-- =====================================================


-- STEP 1: CREATE ROLES IF THEY DO NOT EXIST

DO $roles$
BEGIN

    IF NOT EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = 'synth_policy_runtime'
    ) THEN
        CREATE ROLE synth_policy_runtime
            NOLOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOBYPASSRLS;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = 'synth_tool_runtime'
    ) THEN
        CREATE ROLE synth_tool_runtime
            NOLOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOBYPASSRLS;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = 'synth_coordinator'
    ) THEN
        CREATE ROLE synth_coordinator
            NOLOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOBYPASSRLS;
    END IF;

END
$roles$;


-- STEP 2: ALLOW DATABASE CONNECTIONS

GRANT CONNECT ON DATABASE synthshield
TO
    synth_policy_runtime,
    synth_tool_runtime,
    synth_coordinator;


GRANT USAGE ON SCHEMA public
TO
    synth_policy_runtime,
    synth_tool_runtime,
    synth_coordinator;


-- STEP 3: POLICY API PERMISSIONS

-- The policy service needs to write new audit events
-- and read existing records for verified retrieval.

GRANT SELECT, INSERT
ON TABLE security_events
TO synth_policy_runtime;


-- STEP 4: TRUSTED TOOL SERVICE PERMISSIONS

-- Credential verification.
-- No INSERT, DELETE or UPDATE privileges on
-- agent membership records.

GRANT SELECT (
    scope_id,
    credential_hash,
    allowed_sources,
    active
)
ON TABLE authorized_agent_workflows
TO synth_tool_runtime;


-- Read coalition scope and accumulated sources.

GRANT SELECT (
    scope_id,
    requested_task,
    accessed_sources
)
ON TABLE coalition_scopes
TO synth_tool_runtime;


-- Permit reservation of approved sources.
-- Required for the current FOR UPDATE workflow.
--
-- The tool service cannot modify the approved
-- task or insert new coalition scopes.

GRANT UPDATE (
    accessed_sources
)
ON TABLE coalition_scopes
TO synth_tool_runtime;


-- STEP 5: TRUSTED COORDINATOR PERMISSIONS

-- Coordinator can provision new coalition scopes
-- and agent workflow membership records.

GRANT INSERT, SELECT, DELETE
ON TABLE coalition_scopes
TO synth_coordinator;


GRANT INSERT, SELECT, DELETE
ON TABLE authorized_agent_workflows
TO synth_coordinator;


-- Coordinator may revoke agent credentials.

GRANT UPDATE (
    active
)
ON TABLE authorized_agent_workflows
TO synth_coordinator;


-- STEP 6: DO NOT GRANT ANY APPLICATION ROLE
-- SUPERUSER, CREATEDB, CREATEROLE,
-- SECURITY EVENT DELETION OR OWNERSHIP.
