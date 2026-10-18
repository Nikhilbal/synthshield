
"""
SYNTHSHIELD - Phase 10.3L

Credential-Verified Multi-Agent Coalition Gateway
with Trusted Context Scope Reuse.

SECURITY FEATURES
-----------------
1. Secure agent credential hashing.
2. Restricted coordinator database access.
3. Trusted information-sharing contexts.
4. One coalition scope per trusted context.
5. Agent-specific source permissions.
6. Credential-based workflow authorization.
7. Shared PostgreSQL coalition tracking.
8. Sensitive inference and Purpose Lock evaluation.
9. Fail-closed security decisions.
10. Protected tool execution after authorization.

DATABASE IDENTITIES
-------------------
Coordinator:
    synth_coordinator

Trusted tool runtime:
    synth_tool_runtime

SECURITY REQUIREMENTS
---------------------
- Only trusted orchestration assigns context IDs.
- Untrusted agents cannot create coalition scopes.
- Agents cannot directly access PostgreSQL.
- Protected tools must use the authorized gateway.
- Coordinator credentials must remain outside
  untrusted runtime containers.

The legacy create_coalition_scope() function is
retained for compatibility with existing tests.
New related workflows should use
get_or_create_coalition_scope().
"""

import hashlib
import secrets

from uuid import UUID, uuid4

from src.database import (
    get_database_connection,
    get_coordinator_connection,
)

from src.agent_gateway import (
    AccessDenied,
    PolicyUnavailable,
    evaluate_with_synthshield,
    validate_agent_request,
    validate_security_decision,
)


# =========================================================
# CONFIGURATION
# =========================================================

VALID_SOURCES = frozenset({
    "calendar",
    "travel",
    "finance",
})


# =========================================================
# 1. AGENT CREDENTIAL HASHING
# =========================================================

def credential_digest(token):
    """
    Generate a SHA-256 digest of an agent credential.

    Plaintext agent credentials are never stored
    directly in PostgreSQL.

    Credentials are generated using a
    cryptographically secure random generator.
    """

    if not isinstance(token, str) or not token:
        raise AccessDenied(
            "Missing agent credential."
        )

    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


# =========================================================
# 2. LEGACY COALITION SCOPE CREATION
# =========================================================

def create_coalition_scope(task):
    """
    Create a new coalition scope.

    Coordinator-only operation.

    IMPORTANT:
    This creates a new scope every time.

    Retained for compatibility with existing
    tests and local demonstrations.

    Related multi-agent workflows should use
    get_or_create_coalition_scope() instead.

    Database identity:
        synth_coordinator
    """

    if (
        not isinstance(task, str)
        or not task.strip()
    ):
        raise ValueError(
            "Invalid approved task."
        )

    scope_id = uuid4()

    with get_coordinator_connection() as connection:

        with connection.cursor() as cursor:

            cursor.execute(
                """
                INSERT INTO coalition_scopes (
                    scope_id,
                    requested_task
                )
                VALUES (%s, %s)
                """,
                (
                    scope_id,
                    task,
                ),
            )

    return str(scope_id)


# =========================================================
# 3. TRUSTED CONTEXT SCOPE REUSE
# =========================================================

def get_or_create_coalition_scope(
    *,
    context_id,
    task,
):
    """
    Get or create the authoritative coalition scope
    for one trusted information-sharing context.

    Example:

        Context A:
            Finance agent
            Travel agent
            Calendar agent

    All related agents must share the same scope.

    SECURITY REQUIREMENTS
    ---------------------
    - context_id is assigned by trusted orchestration.
    - Agents must not choose their own context IDs.
    - One context maps to one coalition scope.
    - The approved task cannot change for a context.
    - Concurrent calls must reuse the same scope.

    DATABASE REQUIREMENT
    --------------------
    Migration 005_trusted_context_scope.sql
    must already be applied.

    Database identity:
        synth_coordinator
    """

    # -----------------------------------------------------
    # Validate trusted context identifier
    # -----------------------------------------------------

    try:
        context_uuid = UUID(
            str(context_id)
        )

    except (
        TypeError,
        ValueError,
        AttributeError,
    ):
        raise ValueError(
            "Invalid trusted context ID."
        ) from None

    # -----------------------------------------------------
    # Validate approved task
    # -----------------------------------------------------

    if (
        not isinstance(task, str)
        or not task.strip()
    ):
        raise ValueError(
            "Invalid approved task."
        )

    approved_task = task.strip()

    # -----------------------------------------------------
    # Connect using restricted coordinator credentials
    # -----------------------------------------------------

    with get_coordinator_connection() as connection:

        with connection.cursor() as cursor:

            # PostgreSQL prevents duplicate scopes
            # for the same non-NULL context_id.

            cursor.execute(
                """
                INSERT INTO coalition_scopes (
                    scope_id,
                    context_id,
                    requested_task
                )
                VALUES (%s, %s, %s)

                ON CONFLICT (context_id)
                    WHERE context_id IS NOT NULL
                DO NOTHING
                """,
                (
                    uuid4(),
                    context_uuid,
                    approved_task,
                ),
            )

            # Retrieve the existing or newly
            # created authoritative coalition scope.

            cursor.execute(
                """
                SELECT
                    scope_id,
                    requested_task

                FROM coalition_scopes

                WHERE context_id = %s
                """,
                (
                    context_uuid,
                ),
            )

            row = cursor.fetchone()

            if row is None:
                raise RuntimeError(
                    "Trusted coalition scope unavailable."
                )

            scope_id, stored_task = row

            # Prevent one context from being
            # silently reassigned to another task.

            if stored_task != approved_task:
                raise ValueError(
                    "Trusted context has a different "
                    "approved task."
                )

    return str(scope_id)


# =========================================================
# 4. PROVISION AUTHORIZED WORKFLOW AGENT
# =========================================================

def provision_workflow_agent(
    scope_id,
    agent_id,
    allowed_sources,
):
    """
    Issue a secure credential for an authorized agent.

    The agent is bound to one coordinator-assigned
    coalition scope.

    PARAMETERS
    ----------
    scope_id:
        Existing trusted coalition scope.

    agent_id:
        Trusted agent identifier.

    allowed_sources:
        List containing permitted data sources.

    RETURNS
    -------
    {
        "workflow_id": "...",
        "credential": "..."
    }

    SECURITY
    --------
    - Only trusted coordinator code may call this.
    - Never print or log the returned credential.
    - Store only the credential digest.
    - Agent workflows must receive the correct scope.

    Database identity:
        synth_coordinator
    """

    # -----------------------------------------------------
    # Validate coalition scope
    # -----------------------------------------------------

    try:
        scope_uuid = UUID(
            str(scope_id)
        )

    except (
        TypeError,
        ValueError,
        AttributeError,
    ):
        raise ValueError(
            "Invalid coalition scope UUID."
        ) from None

    # -----------------------------------------------------
    # Validate agent ID
    # -----------------------------------------------------

    if (
        not isinstance(agent_id, str)
        or not agent_id.strip()
    ):
        raise ValueError(
            "Invalid agent ID."
        )

    # -----------------------------------------------------
    # Validate source permissions
    # -----------------------------------------------------

    if (
        not isinstance(allowed_sources, list)
        or not allowed_sources
        or any(
            not isinstance(source, str)
            or source not in VALID_SOURCES
            for source in allowed_sources
        )
        or len(allowed_sources)
        != len(set(allowed_sources))
    ):
        raise ValueError(
            "Invalid source permissions."
        )

    # -----------------------------------------------------
    # Generate secure agent credential
    # -----------------------------------------------------

    token = secrets.token_urlsafe(32)

    workflow_id = uuid4()

    token_hash = credential_digest(
        token
    )

    # -----------------------------------------------------
    # Store authenticated agent membership
    # -----------------------------------------------------

    with get_coordinator_connection() as connection:

        with connection.cursor() as cursor:

            cursor.execute(
                """
                INSERT INTO authorized_agent_workflows (
                    workflow_id,
                    scope_id,
                    agent_id,
                    credential_hash,
                    allowed_sources
                )
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    workflow_id,
                    scope_uuid,
                    agent_id,
                    token_hash,
                    allowed_sources,
                ),
            )

    # Never log the plaintext credential.

    return {
        "workflow_id": str(workflow_id),
        "credential": token,
    }


# =========================================================
# 5. AUTHORIZED AGENT SECURITY GATEWAY
# =========================================================

class AuthorizedAgentGateway:
    """
    Credential-verified agent tool authorization.

    The requesting agent cannot choose a
    workflow ID or coalition scope.

    Membership is resolved using its
    credential digest stored in PostgreSQL.

    Only approved tools may execute.
    """

    # -----------------------------------------------------
    # Initialize authenticated gateway
    # -----------------------------------------------------

    def __init__(
        self,
        *,
        credential,
        tools,
        evaluator=None,
    ):

        self._credential_hash = credential_digest(
            credential
        )

        if not isinstance(tools, dict):
            raise ValueError(
                "Tools must be a dictionary."
            )

        self.tools = tools

        self.evaluator = (
            evaluator
            if evaluator is not None
            else evaluate_with_synthshield
        )

        if not callable(self.evaluator):
            raise ValueError(
                "Evaluator must be callable."
            )

    # =====================================================
    # 6. PROTECTED TOOL ACCESS
    # =====================================================

    def access(self, source):
        """
        Authenticate and authorize a protected tool.

        AUTHORIZATION WORKFLOW
        ----------------------
        1. Validate the requested tool.
        2. Resolve the agent's stored credential.
        3. Verify active workflow membership.
        4. Check source permissions.
        5. Lock the shared coalition scope.
        6. Read previously accessed sources.
        7. Build the proposed information coalition.
        8. Evaluate SYNTHSHIELD security policy.
        9. Reject unsafe access.
        10. Reserve approved access in PostgreSQL.
        11. Commit the authorization transaction.
        12. Execute the approved tool.

        Security:
        Protected tools never execute when
        authorization fails.

        Failed tool operations preserve their
        previously committed source reservation.
        """

        # -------------------------------------------------
        # Validate requested source and tool
        # -------------------------------------------------

        validate_agent_request(
            "credential-verified access",
            [source],
            self.tools,
        )

        # -------------------------------------------------
        # Start authorization transaction
        # -------------------------------------------------

        try:

            # This connection uses synth_tool_runtime
            # inside the trusted-tool container.

            with get_database_connection() as connection:

                with connection.cursor() as cursor:

                    # -------------------------------------
                    # Authenticate agent credential
                    # -------------------------------------

                    cursor.execute(
                        """
                        SELECT
                            scope_id,
                            allowed_sources

                        FROM authorized_agent_workflows

                        WHERE credential_hash = %s
                          AND active = TRUE
                        """,
                        (
                            self._credential_hash,
                        ),
                    )

                    membership = cursor.fetchone()

                    if membership is None:
                        raise AccessDenied(
                            "Unknown or revoked agent credential."
                        )

                    scope_id, allowed_sources = membership

                    # -------------------------------------
                    # Enforce source permissions
                    # -------------------------------------

                    if source not in allowed_sources:
                        raise AccessDenied(
                            "Agent lacks source permission."
                        )

                    # -------------------------------------
                    # Lock shared coalition history
                    # -------------------------------------

                    cursor.execute(
                        """
                        SELECT
                            requested_task,
                            accessed_sources

                        FROM coalition_scopes

                        WHERE scope_id = %s

                        FOR UPDATE
                        """,
                        (
                            scope_id,
                        ),
                    )

                    row = cursor.fetchone()

                    if row is None:
                        raise PolicyUnavailable(
                            "Coalition scope unavailable."
                        )

                    task, existing_sources = row

                    # -------------------------------------
                    # Build proposed coalition
                    # -------------------------------------

                    proposed_sources = list(
                        existing_sources
                    )

                    if source not in proposed_sources:
                        proposed_sources.append(
                            source
                        )

                    # -------------------------------------
                    # Evaluate SYNTHSHIELD security policy
                    # -------------------------------------

                    try:

                        decision = self.evaluator(
                            task,
                            proposed_sources,
                        )

                    except (
                        AccessDenied,
                        PolicyUnavailable,
                    ):
                        raise

                    except Exception as exc:
                        raise PolicyUnavailable(
                            "Coalition policy evaluation failed."
                        ) from exc

                    # -------------------------------------
                    # Validate security decision
                    # -------------------------------------

                    validate_security_decision(
                        decision,
                        proposed_sources,
                    )

                    # -------------------------------------
                    # Reserve approved source access
                    # -------------------------------------

                    if source not in existing_sources:

                        cursor.execute(
                            """
                            UPDATE coalition_scopes

                            SET accessed_sources = %s

                            WHERE scope_id = %s
                            """,
                            (
                                proposed_sources,
                                scope_id,
                            ),
                        )

            # Successful transaction commits here.

        except (
            AccessDenied,
            PolicyUnavailable,
        ):
            raise

        except Exception as exc:

            # Fail closed when authorization storage
            # or another internal dependency fails.

            raise PolicyUnavailable(
                "Authorization storage unavailable."
            ) from exc

        # -------------------------------------------------
        # Execute approved tool
        # -------------------------------------------------

        # Execute only after the transaction commits.
        # Tool failures do not erase the reservation.

        return self.tools[source]()


# =========================================================
# 7. COALITION SOURCE HISTORY INSPECTION
# =========================================================

def get_coalition_sources(scope_id):
    """
    Retrieve a coalition's accessed source history.

    Trusted local inspection helper only.

    Do not expose directly to untrusted agents
    or unauthenticated public API requests.

    Returns a tuple of sources or None.
    """

    try:
        scope_uuid = UUID(
            str(scope_id)
        )

    except (
        TypeError,
        ValueError,
        AttributeError,
    ):
        raise ValueError(
            "Invalid coalition scope UUID."
        ) from None

    with get_database_connection() as connection:

        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT accessed_sources

                FROM coalition_scopes

                WHERE scope_id = %s
                """,
                (
                    scope_uuid,
                ),
            )

            row = cursor.fetchone()

    if row is None:
        return None

    return tuple(row[0])
