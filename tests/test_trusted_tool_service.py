
"""
Phase 10.3D - Trusted Tool API Security Tests.

Uses temporary PostgreSQL coalition scopes.
Tests use a synthetic policy evaluator.
"""

import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import src.authorized_agent_gateway as authorization

from src.database import get_database_connection
from src.authorized_agent_gateway import (
    create_coalition_scope,
    provision_workflow_agent,
    get_coalition_sources,
)
from src.trusted_tool_service import app


pytestmark = pytest.mark.skipif(
    os.getenv("SYNTHSHIELD_RUN_DB_TESTS") != "1",
    reason="Database integration tests require opt-in.",
)


def lab_policy(task, sources):
    sensitive = set(sources) == {
        "finance",
        "travel",
        "calendar",
    }

    return {
        "event_id": str(uuid4()),
        "sources": list(sources),
        "decision": "BLOCK" if sensitive else "ALLOW",
        "risk_level": "CRITICAL" if sensitive else "LOW",
        "sensitive_inference": sensitive,
        "purpose_drift": False,
    }


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(
        authorization,
        "evaluate_with_synthshield",
        lab_policy,
    )

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def scope():
    scope_id = create_coalition_scope(
        "Authorized synthetic security research"
    )

    yield scope_id

    with get_database_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                DELETE FROM coalition_scopes
                WHERE scope_id = %s
                """,
                (scope_id,),
            )


def issue(scope_id, name, source):
    return provision_workflow_agent(
        scope_id,
        name,
        [source],
    )["credential"]


def invoke(client, source, credential=None):
    headers = {}

    if credential is not None:
        headers["Authorization"] = (
            f"Bearer {credential}"
        )

    return client.post(
        "/v1/agent-tools/execute",
        json={"source": source},
        headers=headers,
    )


def test_missing_credential_denied(client):
    response = invoke(client, "finance")

    assert response.status_code == 401


def test_unknown_credential_denied(client):
    response = invoke(
        client,
        "finance",
        "unissued-test-credential",
    )

    assert response.status_code == 403


def test_valid_credential_and_source_scope(client, scope):
    credential = issue(
        scope,
        "agent-a",
        "finance",
    )

    allowed = invoke(
        client,
        "finance",
        credential,
    )

    denied = invoke(
        client,
        "calendar",
        credential,
    )

    assert allowed.status_code == 200

    assert allowed.json()["result"]["category"] == (
        "finance"
    )

    assert denied.status_code == 403

    assert get_coalition_sources(scope) == (
        "finance",
    )


def test_cross_agent_coalition_blocked(client, scope):
    finance = issue(scope, "agent-a", "finance")
    travel = issue(scope, "agent-b", "travel")
    calendar = issue(scope, "agent-c", "calendar")

    first = invoke(client, "finance", finance)
    second = invoke(client, "travel", travel)
    third = invoke(client, "calendar", calendar)

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 403

    assert get_coalition_sources(scope) == (
        "finance",
        "travel",
    )
