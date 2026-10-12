
import json

import pytest

from fastapi.testclient import TestClient

from src.api import app
from src.audit import write_security_event


@pytest.fixture
def client(tmp_path, monkeypatch):
    """
    Create a test API client.

    Send test audit events to a temporary file
    instead of the application's real audit log.
    """

    def write_test_event(**kwargs):
        return write_security_event(
            **kwargs,
            log_file=tmp_path / "security_events.jsonl",
        )

    monkeypatch.setattr(
        "src.api.write_security_event",
        write_test_event,
    )

    with TestClient(app) as test_client:
        yield test_client


# -----------------------------------------------------
# TEST 1: API HEALTH CHECK
# -----------------------------------------------------

def test_api_health(client):

    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["service"] == "SYNTHSHIELD"
    assert data["status"] == "running"


# -----------------------------------------------------
# TEST 2: LEGITIMATE TASK SHOULD BE ALLOWED
# -----------------------------------------------------

def test_legitimate_task_is_allowed(client):

    request_data = {
        "requested_task": (
            "Prepare the monthly expense report."
        ),
        "sources": [
            "finance",
            "travel",
        ],
    }

    response = client.post(
        "/v1/evaluate",
        json=request_data,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["sensitive_inference"] is False
    assert data["purpose_drift"] is False
    assert data["risk_level"] == "LOW"
    assert data["decision"] == "ALLOW"


# -----------------------------------------------------
# TEST 3: SENSITIVE INFERENCE MUST BE BLOCKED
# -----------------------------------------------------

def test_sensitive_acquisition_task_is_blocked(client):

    request_data = {
        "requested_task": (
            "Analyze whether the company "
            "may be acquiring AlphaCorp."
        ),
        "sources": [
            "calendar",
            "travel",
            "finance",
        ],
    }

    response = client.post(
        "/v1/evaluate",
        json=request_data,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["sensitive_inference"] is True
    assert data["purpose_drift"] is True
    assert data["risk_level"] == "CRITICAL"
    assert data["decision"] == "BLOCK"

    assert "event_id" in data


# -----------------------------------------------------
# TEST 4: UNKNOWN DATA SOURCE MUST BE REJECTED
# -----------------------------------------------------

def test_unknown_source_is_rejected(client):

    request_data = {
        "requested_task": (
            "Prepare the monthly expense report."
        ),
        "sources": [
            "finance",
            "unknown_database",
        ],
    }

    response = client.post(
        "/v1/evaluate",
        json=request_data,
    )

    assert response.status_code == 422


# -----------------------------------------------------
# TEST 5: DUPLICATE SOURCES MUST BE REJECTED
# -----------------------------------------------------

def test_duplicate_sources_are_rejected(client):

    request_data = {
        "requested_task": (
            "Prepare the monthly expense report."
        ),
        "sources": [
            "finance",
            "finance",
        ],
    }

    response = client.post(
        "/v1/evaluate",
        json=request_data,
    )

    assert response.status_code == 422


# -----------------------------------------------------
# TEST 6: API MUST CREATE AN AUDIT EVENT
# -----------------------------------------------------

def test_api_creates_audit_event(client, tmp_path):

    request_data = {
        "requested_task": (
            "Analyze whether the company "
            "may be acquiring AlphaCorp."
        ),
        "sources": [
            "calendar",
            "travel",
            "finance",
        ],
    }

    response = client.post(
        "/v1/evaluate",
        json=request_data,
    )

    assert response.status_code == 200

    data = response.json()

    log_file = tmp_path / "security_events.jsonl"

    assert log_file.exists()

    lines = log_file.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(lines) == 1

    event = json.loads(lines[0])

    assert event["event_id"] == data["event_id"]
    assert event["decision"] == "BLOCK"
    assert event["purpose_drift"] is True

    # Sensitive derived information must not be
    # copied into the audit metadata.
    assert "AlphaCorp" not in lines[0]
