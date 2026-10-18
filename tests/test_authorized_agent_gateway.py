
"""
SYNTHSHIELD - Phase 10.3A Security Tests.

Uses the real local PostgreSQL database.
Each test creates and cleans up its own scope.
"""

import os
from uuid import uuid4

import pytest

from src.database import get_database_connection

from src.agent_gateway import (
    AccessDenied,
    PolicyUnavailable,
)

from src.authorized_agent_gateway import (
    AuthorizedAgentGateway,
    create_coalition_scope,
    provision_workflow_agent,
    get_coalition_sources,
)


pytestmark = pytest.mark.skipif(
    os.getenv("SYNTHSHIELD_RUN_DB_TESTS") != "1",
    reason="Database integration tests require opt-in.",
)


@pytest.fixture
def scope_id():
    identifier = create_coalition_scope(
        "Authorized synthetic security research"
    )

    yield identifier

    with get_database_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                DELETE FROM coalition_scopes
                WHERE scope_id = %s
                """,
                (identifier,),
            )


def lab_policy(task, sources):
    sensitive = set(sources) == {
        "calendar",
        "travel",
        "finance",
    }

    return {
        "event_id": str(uuid4()),
        "sources": list(sources),
        "decision": "BLOCK" if sensitive else "ALLOW",
        "risk_level": "CRITICAL" if sensitive else "LOW",
        "sensitive_inference": sensitive,
        "purpose_drift": False,
    }


def make_agent(scope_id, name, source, calls):
    identity = provision_workflow_agent(
        scope_id,
        name,
        [source],
    )

    gateway = AuthorizedAgentGateway(
        credential=identity["credential"],
        tools={
            source: lambda: calls.append(source)
        },
        evaluator=lab_policy,
    )

    return gateway, identity


def test_legitimate_agent_access(scope_id):
    calls = []

    agent, _ = make_agent(
        scope_id, "agent-a", "finance", calls
    )

    agent.access("finance")

    assert calls == ["finance"]
    assert get_coalition_sources(scope_id) == (
        "finance",
    )


def test_unknown_credential_cannot_join(scope_id):
    calls = []

    # No coordinator issued this credential.
    intruder = AuthorizedAgentGateway(
        credential="unissued-test-credential",
        tools={
            "finance": lambda: calls.append("finance")
        },
        evaluator=lab_policy,
    )

    with pytest.raises(AccessDenied):
        intruder.access("finance")

    assert calls == []
    assert get_coalition_sources(scope_id) == ()


def test_agent_cannot_exceed_source_permission(scope_id):
    calls = []

    identity = provision_workflow_agent(
        scope_id,
        "finance-agent",
        ["finance"],
    )

    agent = AuthorizedAgentGateway(
        credential=identity["credential"],
        tools={
            "calendar": lambda: calls.append("calendar")
        },
        evaluator=lab_policy,
    )

    with pytest.raises(AccessDenied):
        agent.access("calendar")

    assert calls == []
    assert get_coalition_sources(scope_id) == ()


def test_different_workflows_share_coalition(scope_id):
    calls = []

    finance, finance_id = make_agent(
        scope_id, "agent-a", "finance", calls
    )

    travel, travel_id = make_agent(
        scope_id, "agent-b", "travel", calls
    )

    calendar, calendar_id = make_agent(
        scope_id, "agent-c", "calendar", calls
    )

    assert len({
        finance_id["workflow_id"],
        travel_id["workflow_id"],
        calendar_id["workflow_id"],
    }) == 3

    finance.access("finance")
    travel.access("travel")

    with pytest.raises(AccessDenied):
        calendar.access("calendar")

    assert calls == ["finance", "travel"]

    assert get_coalition_sources(scope_id) == (
        "finance",
        "travel",
    )


def test_revoked_credential_is_denied(scope_id):
    calls = []

    agent, identity = make_agent(
        scope_id, "agent-a", "finance", calls
    )

    with get_database_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE authorized_agent_workflows
                SET active = FALSE
                WHERE workflow_id = %s
                """,
                (identity["workflow_id"],),
            )

    with pytest.raises(AccessDenied):
        agent.access("finance")

    assert calls == []


def test_policy_failure_prevents_access(scope_id):
    calls = []

    identity = provision_workflow_agent(
        scope_id,
        "agent-a",
        ["finance"],
    )

    def unavailable(task, sources):
        raise ConnectionError("Synthetic policy outage")

    agent = AuthorizedAgentGateway(
        credential=identity["credential"],
        tools={
            "finance": lambda: calls.append("finance")
        },
        evaluator=unavailable,
    )

    with pytest.raises(PolicyUnavailable):
        agent.access("finance")

    assert calls == []
    assert get_coalition_sources(scope_id) == ()
