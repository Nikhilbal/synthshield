
"""
SYNTHSHIELD - Phase 9B

Live security-gateway demonstration.

Calls the real local FastAPI policy endpoint.
Tools return synthetic records only.

No external AI provider or real business data.
"""

from src.agent_gateway import (
    AccessDenied,
    PolicyUnavailable,
    run_guarded_task,
)


executed_tools = []


def finance_tool():
    executed_tools.append("finance")

    return {
        "monthly_expenses": 12500,
        "currency": "INR",
    }


def travel_tool():
    executed_tools.append("travel")

    return {
        "monthly_travel_cost": 3500,
        "currency": "INR",
    }


def calendar_tool():
    executed_tools.append("calendar")

    return {
        "meeting_count": 4,
    }


TOOLS = {
    "finance": finance_tool,
    "travel": travel_tool,
    "calendar": calendar_tool,
}


def run_demo():

    # --------------------------------------------------
    # SCENARIO 1 - LEGITIMATE TASK
    # --------------------------------------------------

    print("\nSCENARIO 1: Legitimate Expense Report")

    executed_tools.clear()

    try:
        result = run_guarded_task(
            task="Prepare the monthly expense report.",
            sources=["finance", "travel"],
            tools=TOOLS,
        )

        assert executed_tools == [
            "finance",
            "travel",
        ]

        assert "finance" in result
        assert "travel" in result

        print("[PASS] SYNTHSHIELD authorized access")
        print("[PASS] Finance tool executed")
        print("[PASS] Travel tool executed")

    except (AccessDenied, PolicyUnavailable):
        print("[FAIL] Legitimate task was not allowed")
        raise

    # --------------------------------------------------
    # SCENARIO 2 - SENSITIVE ACQUISITION
    # --------------------------------------------------

    print("\nSCENARIO 2: Sensitive Acquisition Analysis")

    executed_tools.clear()

    try:
        run_guarded_task(
            task=(
                "Analyze whether the company "
                "may be acquiring AlphaCorp."
            ),
            sources=[
                "calendar",
                "travel",
                "finance",
            ],
            tools=TOOLS,
        )

    except AccessDenied:
        print("[PASS] SYNTHSHIELD blocked access")

    else:
        raise AssertionError(
            "Sensitive tool request was not blocked."
        )

    assert executed_tools == []

    print("[PASS] No protected tools executed")
    print("[PASS] No source data returned")

    print("\n" + "=" * 55)
    print("LIVE AGENT GATEWAY DEMONSTRATION SUCCESSFUL")
    print("=" * 55)


if __name__ == "__main__":
    run_demo()
