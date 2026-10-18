
"""
SYNTHSHIELD - Phase 10.3M

Trusted-Context Agent Gateway Demonstration

Features:
- Trusted context assignment
- Shared coalition scope
- Coordinator-issued agent credentials
- Unknown credential rejection
- Finance and travel authorization
- Calendar access denial
- PostgreSQL coalition history verification
- Automatic test-data cleanup

Uses synthetic tools only.
"""

from uuid import uuid4

from src.agent_gateway import AccessDenied

from src.authorized_agent_gateway import (
    AuthorizedAgentGateway,
    get_or_create_coalition_scope,
    provision_workflow_agent,
    get_coalition_sources,
)

from src.database import get_coordinator_connection


TASK = "Prepare the monthly expense report."


# =====================================================
# 1. CREATE AUTHORIZED AGENT
# =====================================================

def create_authorized_agent(
    scope_id,
    agent_name,
    source,
    executed_tools,
):
    """
    Provision a synthetic agent through the
    trusted coordinator.

    Every related agent receives the same
    authoritative coalition scope.
    """

    identity = provision_workflow_agent(
        scope_id=scope_id,
        agent_id=agent_name,
        allowed_sources=[source],
    )

    def protected_tool():
        executed_tools.append(source)
        return f"synthetic-{source}-data"

    return AuthorizedAgentGateway(
        credential=identity["credential"],
        tools={source: protected_tool},
    )


# =====================================================
# 2. MAIN SECURITY DEMONSTRATION
# =====================================================

def main():

    # Trusted coordinator creates one context.
    # Agents cannot choose or reset this ID.

    context_id = uuid4()

    scope_id = None

    executed_tools = []

    print("=" * 55)
    print("SYNTHSHIELD - TRUSTED CONTEXT AGENT DEMO")
    print("=" * 55)

    try:

        # ---------------------------------------------
        # STEP 1 - CREATE TRUSTED COALITION SCOPE
        # ---------------------------------------------

        scope_id = get_or_create_coalition_scope(
            context_id=context_id,
            task=TASK,
        )

        print("[PASS] Trusted coalition scope assigned")

        # ---------------------------------------------
        # STEP 2 - VERIFY SCOPE REUSE
        # ---------------------------------------------

        second_scope_id = get_or_create_coalition_scope(
            context_id=context_id,
            task=TASK,
        )

        assert second_scope_id == scope_id, (
            "Security failure: related workflows "
            "received different scopes"
        )

        print(
            "[PASS] Same trusted context reuses "
            "the same coalition scope"
        )

        # ---------------------------------------------
        # STEP 3 - TEST UNKNOWN CREDENTIAL
        # ---------------------------------------------

        intruder = AuthorizedAgentGateway(
            credential=f"unissued-{uuid4()}",
            tools={
                "finance": lambda: executed_tools.append(
                    "intruder"
                ),
            },
        )

        try:

            intruder.access("finance")

        except AccessDenied:

            print("[PASS] Unknown credential rejected")

        else:

            raise AssertionError(
                "Unissued credential was accepted"
            )

        assert executed_tools == []

        # ---------------------------------------------
        # STEP 4 - PROVISION AUTHORIZED AGENTS
        # ---------------------------------------------

        finance_agent = create_authorized_agent(
            scope_id,
            "finance-agent",
            "finance",
            executed_tools,
        )

        travel_agent = create_authorized_agent(
            second_scope_id,
            "travel-agent",
            "travel",
            executed_tools,
        )

        calendar_agent = create_authorized_agent(
            scope_id,
            "calendar-agent",
            "calendar",
            executed_tools,
        )

        print("[PASS] Authorized agents provisioned")

        # ---------------------------------------------
        # STEP 5 - FINANCE ACCESS
        # ---------------------------------------------

        finance_agent.access("finance")

        print("[PASS] Finance agent authorized")

        # ---------------------------------------------
        # STEP 6 - TRAVEL ACCESS
        # ---------------------------------------------

        travel_agent.access("travel")

        print("[PASS] Travel agent authorized")

        # ---------------------------------------------
        # STEP 7 - CALENDAR ACCESS ATTEMPT
        # ---------------------------------------------

        try:

            calendar_agent.access("calendar")

        except AccessDenied:

            print("[PASS] Calendar access denied")

        else:

            raise AssertionError(
                "Unsafe calendar access was allowed"
            )

        # ---------------------------------------------
        # STEP 8 - VERIFY TOOL EXECUTION
        # ---------------------------------------------

        assert executed_tools == [
            "finance",
            "travel",
        ], (
            f"Unexpected tool execution history: "
            f"{executed_tools}"
        )

        print("[PASS] Only approved tools executed")

        # ---------------------------------------------
        # STEP 9 - VERIFY POSTGRESQL COALITION STATE
        # ---------------------------------------------

        coalition_history = get_coalition_sources(
            scope_id
        )

        assert coalition_history == (
            "finance",
            "travel",
        )

        print("[PASS] Shared coalition history verified")

        # ---------------------------------------------
        # STEP 10 - FINAL RESULT
        # ---------------------------------------------

        print("=" * 55)
        print("TRUSTED CONTEXT SECURITY DEMO SUCCESSFUL")
        print("=" * 55)

    finally:

        # ---------------------------------------------
        # CLEAN UP TEMPORARY DATABASE RECORDS
        # ---------------------------------------------

        if scope_id is not None:

            with get_coordinator_connection() as connection:

                with connection.cursor() as cursor:

                    cursor.execute(
                        """
                        DELETE FROM coalition_scopes

                        WHERE scope_id = %s
                          AND context_id = %s
                        """,
                        (
                            scope_id,
                            context_id,
                        ),
                    )

            # Existing ON DELETE CASCADE removes
            # related temporary agent memberships.

            print(
                "[INFO] Temporary agent identities "
                "and coalition scope cleaned up"
            )


# =====================================================
# PROGRAM ENTRY POINT
# =====================================================

if __name__ == "__main__":
    main()
