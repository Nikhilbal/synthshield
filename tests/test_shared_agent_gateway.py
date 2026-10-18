
"""
SYNTHSHIELD - Phase 9D

Real PostgreSQL shared-coalition tests.

Run with:
SYNTHSHIELD_RUN_DB_TESTS=1 python -m pytest
"""

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from src.database import get_database_connection

from src.agent_gateway import (
    AccessDenied,
    PolicyUnavailable,
)

from src.shared_agent_gateway import (
    SharedAgentGateway,
    get_workflow_sources,
)


pytestmark = pytest.mark.skipif(
    os.getenv("SYNTHSHIELD_RUN_DB_TESTS") != "1",
    reason="Real PostgreSQL tests require opt-in.",
)


TASK = "Prepare the monthly expense report."


@pytest.fixture
def workflow_id():
    """
    Provide a unique workflow and clean up only
    this test's synthetic database row.
    """

    identifier = str(uuid4())

    yield identifier

    with get_database_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                DELETE FROM workflow_coalitions
                WHERE workflow_id = %s
                """,
                (identifier,),
            )


def synthetic_policy(task, sources):
    """
    All individual and two-source combinations
    are permitted.

    The three-source combination is sensitive.

    This isolates coalition detection from the
    existing finance agent's Purpose Lock.
    """

    sensitive = set(sources) == {
        "calendar",
        "travel",
        "finance",
    }

    return {
        "event_id": "synthetic-test-event",
        "sources": sources,
        "decision": (
            "BLOCK" if sensitive else "ALLOW"
        ),
        "risk_level": (
            "CRITICAL" if sensitive else "LOW"
        ),
        "sensitive_inference": sensitive,
        "purpose_drift": False,
    }


def make_gateway(
    workflow_id,
    tools,
    evaluator=synthetic_policy,
    task=TASK,
):
    return SharedAgentGateway(
        workflow_id=workflow_id,
        task=task,
        tools=tools,
        evaluator=evaluator,
    )


def test_two_agents_share_database_history(workflow_id):
    calls = []

    agent_a = make_gateway(
        workflow_id,
        {"finance": lambda: calls.append("finance")},
    )

    agent_b = make_gateway(
        workflow_id,
        {"travel": lambda: calls.append("travel")},
    )

    agent_a.access("finance")
    agent_b.access("travel")

    assert calls == ["finance", "travel"]

    assert get_workflow_sources(workflow_id) == (
        "finance",
        "travel",
    )


def test_third_agent_cannot_complete_coalition(workflow_id):
    calls = []

    agents = [
        make_gateway(
            workflow_id,
            {"finance": lambda: calls.append("finance")},
        ),
        make_gateway(
            workflow_id,
            {"travel": lambda: calls.append("travel")},
        ),
        make_gateway(
            workflow_id,
            {"calendar": lambda: calls.append("calendar")},
        ),
    ]

    agents[0].access("finance")
    agents[1].access("travel")

    with pytest.raises(AccessDenied):
        agents[2].access("calendar")

    assert calls == ["finance", "travel"]

    assert get_workflow_sources(workflow_id) == (
        "finance",
        "travel",
    )


def test_workflow_task_cannot_change(workflow_id):
    first = make_gateway(
        workflow_id,
        {"finance": lambda: "approved"},
    )

    first.access("finance")

    second = make_gateway(
        workflow_id,
        {"travel": lambda: "unapproved"},
        task="Different workflow objective",
    )

    with pytest.raises(AccessDenied):
        second.access("travel")

    assert get_workflow_sources(workflow_id) == (
        "finance",
    )


def test_policy_outage_does_not_reserve_source(workflow_id):

    def unavailable(task, sources):
        raise ConnectionError("Policy service offline")

    gateway = make_gateway(
        workflow_id,
        {"finance": lambda: "data"},
        evaluator=unavailable,
    )

    with pytest.raises(PolicyUnavailable):
        gateway.access("finance")

    # The transaction was rolled back.
    assert get_workflow_sources(workflow_id) is None


def test_failed_tool_keeps_conservative_reservation(workflow_id):

    def broken_tool():
        raise RuntimeError("Tool failed")

    gateway = make_gateway(
        workflow_id,
        {"finance": broken_tool},
    )

    with pytest.raises(RuntimeError):
        gateway.access("finance")

    assert get_workflow_sources(workflow_id) == (
        "finance",
    )


def test_concurrent_agents_cannot_bypass_coalition(workflow_id):
    calls = []

    base_agent = make_gateway(
        workflow_id,
        {"finance": lambda: calls.append("finance")},
    )

    base_agent.access("finance")

    travel_agent = make_gateway(
        workflow_id,
        {"travel": lambda: calls.append("travel")},
    )

    calendar_agent = make_gateway(
        workflow_id,
        {"calendar": lambda: calls.append("calendar")},
    )

    def attempt(agent, source):
        try:
            agent.access(source)
            return "ALLOW"
        except AccessDenied:
            return "BLOCK"

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(attempt, travel_agent, "travel"),
            pool.submit(attempt, calendar_agent, "calendar"),
        ]

        decisions = [future.result() for future in futures]

    assert sorted(decisions) == ["ALLOW", "BLOCK"]

    # Finance plus exactly one other source.
    sources = get_workflow_sources(workflow_id)

    assert len(sources) == 2
    assert "finance" in sources
    assert set(sources) != {
        "finance",
        "travel",
        "calendar",
    }
