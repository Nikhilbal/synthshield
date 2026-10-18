
"""
SYNTHSHIELD - Phase 9D
PostgreSQL-Backed Multi-Agent Coalition Gateway

PURPOSE
-------
Coordinate data-source access across multiple
agents participating in the same workflow.

SECURITY FEATURES
-----------------
1. Shared PostgreSQL workflow history.
2. Coalition evaluation before tool execution.
3. PostgreSQL row-level locking.
4. Cross-agent sensitive coalition detection.
5. Purpose and task consistency checks.
6. Fail-closed security decisions.
7. Conservative access reservations.
8. Duplicate source prevention.
9. Workflow history retrieval.

LIMITATIONS
-----------
This is a local research prototype.

- All agents must use this gateway.
- Workflow IDs must come from a trusted coordinator.
- Actual tool execution cannot be rolled back.
- Access reservations are committed before execution.
- Agent authentication is not implemented here.
- Cross-workflow information sharing is not tracked.
"""

from uuid import UUID

from src.database import get_database_connection

from src.agent_gateway import (
    AccessDenied,
    PolicyUnavailable,
    evaluate_with_synthshield,
    validate_agent_request,
    validate_security_decision,
)


# =========================================================
# SHARED AGENT SECURITY GATEWAY
# =========================================================

class SharedAgentGateway:
    """
    Coordinate security decisions for multiple agents
    participating in one PostgreSQL-backed workflow.

    Agents using the same workflow_id share
    accumulated data-source history.
    """

    # -----------------------------------------------------
    # INITIALIZATION
    # -----------------------------------------------------

    def __init__(
        self,
        *,
        workflow_id,
        task,
        tools,
        evaluator=None,
    ):

        # Validate workflow identity.

        try:
            self.workflow_id = UUID(
                str(workflow_id)
            )

        except (
            ValueError,
            TypeError,
            AttributeError,
        ):
            raise ValueError(
                "workflow_id must be a valid UUID."
            ) from None

        # Validate requested task.

        if (
            not isinstance(task, str)
            or not task.strip()
        ):
            raise ValueError(
                "Task must be a non-empty string."
            )

        # Validate tool registry.

        if not isinstance(tools, dict):
            raise ValueError(
                "Tools must be a dictionary."
            )

        self.task = task
        self.tools = tools

        # Select policy evaluator.
        #
        # By default, use the real SYNTHSHIELD API.
        # Tests can inject a synthetic evaluator.

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
    # GUARDED DATA ACCESS
    # =====================================================

    def access(self, source):
        """
        Request access to a registered data source.

        Security workflow:

        1. Validate requested tool.
        2. Begin PostgreSQL transaction.
        3. Create workflow state if absent.
        4. Lock workflow state with FOR UPDATE.
        5. Read previously accessed sources.
        6. Construct proposed source coalition.
        7. Evaluate coalition using SYNTHSHIELD.
        8. Validate the security decision.
        9. Reserve the authorized source.
        10. Commit the database transaction.
        11. Execute the approved tool.

        A blocked request never executes its tool.

        If tool execution fails after authorization,
        the source remains conservatively recorded.
        """

        # -------------------------------------------------
        # STEP 1 - VALIDATE REQUEST
        # -------------------------------------------------

        validate_agent_request(
            self.task,
            [source],
            self.tools,
        )

        # -------------------------------------------------
        # STEP 2 - POSTGRESQL SECURITY TRANSACTION
        # -------------------------------------------------

        try:

            with get_database_connection() as connection:

                with connection.cursor() as cursor:

                    # -------------------------------------
                    # STEP 3 - INITIALIZE WORKFLOW
                    # -------------------------------------

                    cursor.execute(
                        """
                        INSERT INTO workflow_coalitions (
                            workflow_id,
                            requested_task
                        )
                        VALUES (%s, %s)

                        ON CONFLICT (workflow_id)
                        DO NOTHING
                        """,
                        (
                            self.workflow_id,
                            self.task,
                        ),
                    )

                    # -------------------------------------
                    # STEP 4 - LOCK SHARED WORKFLOW
                    # -------------------------------------

                    cursor.execute(
                        """
                        SELECT
                            requested_task,
                            accessed_sources

                        FROM workflow_coalitions

                        WHERE workflow_id = %s

                        FOR UPDATE
                        """,
                        (
                            self.workflow_id,
                        ),
                    )

                    row = cursor.fetchone()

                    if row is None:
                        raise PolicyUnavailable(
                            "Shared workflow state "
                            "is unavailable."
                        )

                    stored_task, accessed_sources = row

                    # -------------------------------------
                    # STEP 5 - VERIFY WORKFLOW TASK
                    # -------------------------------------

                    if stored_task != self.task:
                        raise AccessDenied(
                            "Shared workflow task mismatch."
                        )

                    # -------------------------------------
                    # STEP 6 - BUILD SOURCE COALITION
                    # -------------------------------------

                    proposed_sources = list(
                        accessed_sources
                    )

                    # Add requested source only if
                    # it has not already been recorded.

                    if source not in proposed_sources:
                        proposed_sources.append(source)

                    # -------------------------------------
                    # STEP 7 - EVALUATE SECURITY POLICY
                    # -------------------------------------

                    try:

                        result = self.evaluator(
                            self.task,
                            proposed_sources,
                        )

                    except (
                        AccessDenied,
                        PolicyUnavailable,
                    ):
                        raise

                    except Exception as exc:
                        raise PolicyUnavailable(
                            "Shared security evaluation "
                            "failed."
                        ) from exc

                    # -------------------------------------
                    # STEP 8 - VALIDATE SECURITY DECISION
                    # -------------------------------------

                    # This function enforces:
                    #
                    # - decision == ALLOW
                    # - risk_level == LOW
                    # - sensitive_inference == False
                    # - purpose_drift == False
                    # - returned sources match request
                    # - event ID is present

                    validate_security_decision(
                        result,
                        proposed_sources,
                    )

                    # -------------------------------------
                    # STEP 9 - RESERVE AUTHORIZED SOURCE
                    # -------------------------------------

                    if source not in accessed_sources:

                        cursor.execute(
                            """
                            UPDATE workflow_coalitions

                            SET
                                accessed_sources = %s,
                                updated_at = CURRENT_TIMESTAMP

                            WHERE workflow_id = %s
                            """,
                            (
                                proposed_sources,
                                self.workflow_id,
                            ),
                        )

            # ---------------------------------------------
            # STEP 10 - DATABASE TRANSACTION COMMITTED
            # ---------------------------------------------

            # Leaving the connection context commits
            # the approved source reservation.
            #
            # The tool has NOT executed yet.

        except (
            AccessDenied,
            PolicyUnavailable,
        ):
            # Preserve security-related exceptions.
            raise

        except Exception as exc:
            # Fail closed on unexpected database
            # or transaction errors.
            raise PolicyUnavailable(
                "Shared workflow database unavailable "
                "or security evaluation failed."
            ) from exc

        # -------------------------------------------------
        # STEP 11 - EXECUTE APPROVED TOOL
        # -------------------------------------------------

        # IMPORTANT:
        #
        # Tool execution is OUTSIDE the database
        # exception-handling block.
        #
        # If a tool raises RuntimeError,
        # that original RuntimeError propagates.
        #
        # The approved source remains recorded
        # in PostgreSQL even when execution fails.

        return self.tools[source]()


# =========================================================
# WORKFLOW HISTORY RETRIEVAL
# =========================================================

def get_workflow_sources(workflow_id):
    """
    Retrieve data sources previously recorded
    for a particular shared workflow.

    Args:
        workflow_id:
            Valid workflow UUID.

    Returns:
        Tuple of accessed sources, or None
        if the workflow does not exist.

    This helper is intended for local verification
    and integration tests.

    It is not an authenticated public API endpoint.
    """

    # -----------------------------------------------------
    # STEP 1 - VALIDATE WORKFLOW ID
    # -----------------------------------------------------

    try:
        workflow_uuid = UUID(
            str(workflow_id)
        )

    except (
        ValueError,
        TypeError,
        AttributeError,
    ):
        raise ValueError(
            "workflow_id must be a valid UUID."
        ) from None

    # -----------------------------------------------------
    # STEP 2 - QUERY POSTGRESQL
    # -----------------------------------------------------

    with get_database_connection() as connection:

        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT accessed_sources

                FROM workflow_coalitions

                WHERE workflow_id = %s
                """,
                (
                    workflow_uuid,
                ),
            )

            row = cursor.fetchone()

    # -----------------------------------------------------
    # STEP 3 - RETURN RESULT
    # -----------------------------------------------------

    if row is None:
        return None

    # Immutable snapshot of source history.

    return tuple(row[0])
