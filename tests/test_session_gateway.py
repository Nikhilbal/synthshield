
"""
SYNTHSHIELD - Phase 9C
Session-Based Coalition Security Tests
"""

import pytest

from src.agent_gateway import (
    AccessDenied,
    PolicyUnavailable,
)

from src.session_gateway import GuardedAgentSession


def policy(task, sources):
    """
    Synthetic policy evaluator.

    Individual and two-source requests are allowed.
    A complete three-source coalition is blocked.
    """

    sensitive = set(sources) == {
        "calendar",
        "travel",
        "finance",
    }

    return {
        "event_id": "synthetic-policy-event",
        "sources": sources,
        "decision": "BLOCK" if sensitive else "ALLOW",
        "risk_level": "CRITICAL" if sensitive else "LOW",
        "sensitive_inference": sensitive,
        "purpose_drift": False,
    }


def make_session(calls, evaluator=policy):

    return GuardedAgentSession(
        task="Prepare the monthly expense report.",
        tools={
            "finance": lambda: calls.append("finance"),
            "travel": lambda: calls.append("travel"),
            "calendar": lambda: calls.append("calendar"),
        },
        evaluator=evaluator,
    )


# TEST 1 - FIRST ACCESS ALLOWED

def test_first_source_allowed():
    calls = []
    session = make_session(calls)

    session.access("finance")

    assert calls == ["finance"]
    assert session.accessed_sources == ("finance",)


# TEST 2 - SECOND ACCESS ALLOWED

def test_two_sources_allowed():
    calls = []
    session = make_session(calls)

    session.access("finance")
    session.access("travel")

    assert calls == ["finance", "travel"]
    assert session.accessed_sources == (
        "finance",
        "travel",
    )


# TEST 3 - THREE-SOURCE COALITION BLOCKED

def test_sequential_sensitive_coalition_blocked():
    calls = []
    session = make_session(calls)

    session.access("finance")
    session.access("travel")

    with pytest.raises(AccessDenied):
        session.access("calendar")

    assert calls == ["finance", "travel"]
    assert session.accessed_sources == (
        "finance",
        "travel",
    )


# TEST 4 - POLICY OUTAGE BLOCKS TOOL ACCESS

def test_policy_outage_fails_closed():
    calls = []

    def unavailable(task, sources):
        raise ConnectionError("Policy service offline")

    session = make_session(
        calls,
        evaluator=unavailable,
    )

    with pytest.raises(PolicyUnavailable):
        session.access("finance")

    assert calls == []
    assert session.accessed_sources == ()


# TEST 5 - FAILED TOOL NOT RECORDED AS ACCESSED

def test_failed_tool_does_not_update_history():

    def broken_tool():
        raise RuntimeError("Tool failure")

    session = GuardedAgentSession(
        task="Prepare the monthly expense report.",
        tools={"finance": broken_tool},
        evaluator=policy,
    )

    with pytest.raises(RuntimeError):
        session.access("finance")

    assert session.accessed_sources == ()


# TEST 6 - REPEATED ACCESS DOES NOT DUPLICATE SOURCE

def test_repeated_access_keeps_unique_history():
    calls = []
    session = make_session(calls)

    session.access("finance")
    session.access("finance")

    assert calls == ["finance", "finance"]
    assert session.accessed_sources == ("finance",)
