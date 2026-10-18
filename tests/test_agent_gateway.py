
"""
SYNTHSHIELD - Phase 9A
Agent Gateway Tests
"""

import pytest

from src.agent_gateway import (
    AccessDenied,
    PolicyUnavailable,
    run_guarded_task,
)


def allow_decision(task, sources):
    return {
        "event_id": "synthetic-test-event",
        "source_names": sources,
        "decision": "ALLOW",
        "risk_level": "LOW",
        "sensitive_inference": False,
        "purpose_drift": False,
    }


def test_allowed_tools_execute():

    calls = []

    tools = {
        "finance": lambda: calls.append("finance"),
        "travel": lambda: calls.append("travel"),
    }

    run_guarded_task(
        "Prepare the monthly expense report.",
        ["finance", "travel"],
        tools,
        evaluator=allow_decision,
    )

    assert calls == ["finance", "travel"]


def test_block_prevents_tool_access():

    calls = []

    tools = {
        "calendar": lambda: calls.append("calendar"),
        "travel": lambda: calls.append("travel"),
        "finance": lambda: calls.append("finance"),
    }

    def deny(task, sources):
        return {
            "decision": "BLOCK",
            "risk_level": "CRITICAL",
            "source_names": sources,
        }

    with pytest.raises(AccessDenied):
        run_guarded_task(
            "Analyze a possible acquisition.",
            ["calendar", "travel", "finance"],
            tools,
            evaluator=deny,
        )

    assert calls == []


def test_policy_outage_fails_closed():

    calls = []

    def unavailable(task, sources):
        raise ConnectionError("Service offline")

    with pytest.raises(PolicyUnavailable):
        run_guarded_task(
            "Prepare the monthly expense report.",
            ["finance"],
            {"finance": lambda: calls.append("finance")},
            evaluator=unavailable,
        )

    assert calls == []


def test_source_mismatch_is_denied():

    with pytest.raises(AccessDenied):
        run_guarded_task(
            "Prepare the monthly expense report.",
            ["finance", "travel"],
            {
                "finance": lambda: "finance data",
                "travel": lambda: "travel data",
            },
            evaluator=lambda task, sources: {
                **allow_decision(task, sources),
                "source_names": ["finance"],
            },
        )


def test_duplicate_sources_rejected():

    with pytest.raises(ValueError):
        run_guarded_task(
            "Prepare the monthly expense report.",
            ["finance", "finance"],
            {"finance": lambda: "data"},
            evaluator=allow_decision,
        )
