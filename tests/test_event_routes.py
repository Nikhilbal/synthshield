
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from fastapi.testclient import TestClient

from src.api import app


TEST_API_KEY = "test-only-key-" + ("x" * 40)


@pytest.fixture
def client(monkeypatch):

    # Use an isolated test key.
    monkeypatch.setenv(
        "SYNTHSHIELD_READ_API_KEY",
        TEST_API_KEY,
    )

    with TestClient(app) as test_client:
        yield test_client


def auth_headers():
    return {
        "Authorization": f"Bearer {TEST_API_KEY}"
    }


def test_missing_api_key_is_rejected(client, monkeypatch):

    def should_not_read_database(event_id):
        pytest.fail("Database was queried without authentication")

    monkeypatch.setattr(
        "src.event_routes.get_security_event",
        should_not_read_database,
    )

    response = client.get(
        f"/v1/events/{uuid4()}"
    )

    assert response.status_code == 401


def test_incorrect_api_key_is_rejected(client):

    response = client.get(
        f"/v1/events/{uuid4()}",
        headers={
            "Authorization": "Bearer incorrect-key",
        },
    )

    assert response.status_code == 401


def test_authorized_event_can_be_retrieved(
    client,
    monkeypatch,
):

    event_id = uuid4()
    timestamp = datetime.now(timezone.utc)

    example_event = {
        "event_id": event_id,
        "timestamp_utc": timestamp,
        "agent_id": "finance-agent-001",
        "source_names": ["finance", "travel"],
        "source_count": 2,
        "sensitive_inference": False,
        "purpose_drift": False,
        "risk_level": "LOW",
        "decision": "ALLOW",
        "recorded_at": timestamp,
    }

    monkeypatch.setattr(
        "src.event_routes.get_security_event",
        lambda requested_id: example_event,
    )

    response = client.get(
        f"/v1/events/{event_id}",
        headers=auth_headers(),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["event_id"] == str(event_id)
    assert data["agent_id"] == "finance-agent-001"
    assert data["decision"] == "ALLOW"


def test_nonexistent_event_returns_404(
    client,
    monkeypatch,
):

    monkeypatch.setattr(
        "src.event_routes.get_security_event",
        lambda requested_id: None,
    )

    response = client.get(
        f"/v1/events/{uuid4()}",
        headers=auth_headers(),
    )

    assert response.status_code == 404
