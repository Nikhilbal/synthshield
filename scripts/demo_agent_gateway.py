
"""
SYNTHSHIELD - Phase 10.3C

Credential-Verified Agent Gateway Demonstration

Uses:
- Real local FastAPI security evaluation
- PostgreSQL coalition state
- Coordinator-issued agent credentials
- Synthetic data-access tools

No live business data is accessed.
"""

from uuid import uuid4

from src.agent_gateway import AccessDenied

from src.authorized_agent_gateway import (
    AuthorizedAgentGateway,
    create_coalition_scope,
    provision_workflow_agent,
    get_coalition_sources,
)

from src.database import get_database_connection


TASK = "Prepare the monthly expense report."

executed_tools = []


def create_authorized_agent(scope_id, agent_name, source):
    """
    Provision a synthetic agent through the
    trusted coordinator function.

    In this local demonstration, provisioning
    occurs in the same Python process.
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


def main():
    scope_id = None

    print("=" * 55)
    print("SYNTHSHIELD - AUTHORIZED AGENT SECURITY DEMO")
    print("=" * 55)

    try:
        # -----------------------------------------
        # 1. Create trusted coalition scope
        # -----------------------------------------

        scope_id = create_coalition_scope(TASK)

        print("[PASS] Coalition scope created")

        # -----------------------------------------
        # 2. Verify unknown credential is denied
        # -----------------------------------------

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
                "Unissued credential was accepted."
            )

        assert executed_tools == []

        # -----------------------------------------
        # 3. Provision authorized agents
        # -----------------------------------------

        finance_agent = create_authorized_agent(
            scope_id, "finance-agent", "finance"
        )

        travel_agent = create_authorized_agent(
            scope_id, "travel-agent", "travel"
        )

        calendar_agent = create_authorized_agent(
            scope_id, "calendar-agent", "calendar"
        )

        # -----------------------------------------
        # 4. Exercise the real policy gateway
        # -----------------------------------------

        finance_agent.access("finance")
        print("[PASS] Finance agent authorized")

        travel_agent.access("travel")
        print("[PASS] Travel agent authorized")

        try:
            calendar_agent.access("calendar")

        except AccessDenied:
            print("[PASS] Calendar access blocked")

        else:
            raise AssertionError(
                "Unsafe calendar access was allowed."
            )

        # -----------------------------------------
        # 5. Verify shared state and tool execution
        # -----------------------------------------

        assert executed_tools == [
            "finance",
            "travel",
        ]

        assert get_coalition_sources(scope_id) == (
            "finance",
            "travel",
        )

        print("[PASS] Shared coalition history verified")
        print("[PASS] No blocked tool executed")

        print("=" * 55)
        print("CREDENTIAL-VERIFIED DEMO SUCCESSFUL")
        print("=" * 55)

    finally:
        if scope_id is not None:
            with get_database_connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        DELETE FROM coalition_scopes
                        WHERE scope_id = %s
                        """,
                        (scope_id,),
                    )

            print("[INFO] Synthetic scope cleaned up")


if __name__ == "__main__":
    main()
