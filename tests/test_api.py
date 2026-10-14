
import json

import pytest

from fastapi.testclient import TestClient

from src.api import app
from src.audit import write_security_event


# =========================================================
# SYNTHSHIELD
# FASTAPI AUTOMATED SECURITY TESTS
# Stage 7.9 - PostgreSQL Audit Integration
# =========================================================


# ---------------------------------------------------------
# TEST CLIENT FIXTURE
# ---------------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    """
    Create an isolated FastAPI test client.

    1. Store JSONL audit events in a temporary folder.
    2. Mock PostgreSQL persistence to avoid modifying
       the real SYNTHSHIELD database.
    3. Restore original functions after each test.
    """

    # Create an isolated JSONL audit-writing function.

    def write_test_event(**kwargs):

        return write_security_event(
            **kwargs,
            log_file=tmp_path / "security_events.jsonl",
        )

    # Replace the real JSONL writer during testing.

    monkeypatch.setattr(
        "src.api.write_security_event",
        write_test_event,
    )

    # Replace real PostgreSQL storage with a successful
    # mock database operation.

    monkeypatch.setattr(
        "src.api.save_security_event",
        lambda event: True,
    )

    # Create the FastAPI test client.

    with TestClient(app) as test_client:
        yield test_client


# =========================================================
# TEST 1 - API HEALTH CHECK
# =========================================================

def test_api_health(client):
    """
    Verify that the SYNTHSHIELD API is responding.
    """

    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["service"] == "SYNTHSHIELD"

    assert data["status"] == "running"


# =========================================================
# TEST 2 - LEGITIMATE TASK MUST BE ALLOWED
# =========================================================

def test_legitimate_task_is_allowed(client):
    """
    Verify that an authorized expense-reporting task
    using Finance and Travel data is allowed.
    """

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

    assert "event_id" in data


# =========================================================
# TEST 3 - SENSITIVE ACQUISITION TASK MUST BE BLOCKED
# =========================================================

def test_sensitive_acquisition_task_is_blocked(client):
    """
    Verify that combining Calendar, Travel, and Finance
    data for acquisition analysis results in BLOCK.
    """

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

    assert (
        "Sensitive aggregation inference detected."
        in data["reasons"]
    )

    assert (
        "Purpose drift detected."
        in data["reasons"]
    )


# =========================================================
# TEST 4 - UNKNOWN DATA SOURCE MUST BE REJECTED
# =========================================================

def test_unknown_source_is_rejected(client):
    """
    Verify that unsupported data sources are rejected
    during API request validation.
    """

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


# =========================================================
# TEST 5 - DUPLICATE DATA SOURCES MUST BE REJECTED
# =========================================================

def test_duplicate_sources_are_rejected(client):
    """
    Verify that duplicate data sources are rejected.
    """

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


# =========================================================
# TEST 6 - API MUST CREATE A JSONL AUDIT EVENT
# =========================================================

def test_api_creates_audit_event(client, tmp_path):
    """
    Verify that an API request creates a JSONL audit event.

    The test must not store inferred confidential
    information in the audit record.
    """

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

    log_file = (
        tmp_path / "security_events.jsonl"
    )

    # Verify that the audit file exists.

    assert log_file.exists()

    # Read all audit events.

    lines = log_file.read_text(
        encoding="utf-8"
    ).splitlines()

    # Exactly one event should exist.

    assert len(lines) == 1

    # Convert the saved JSON text into a dictionary.

    event = json.loads(lines[0])

    assert event["event_id"] == data["event_id"]

    assert event["decision"] == "BLOCK"

    assert event["risk_level"] == "CRITICAL"

    assert event["purpose_drift"] is True

    assert event["sensitive_inference"] is True

    # Ensure protected inference content is not stored.

    assert "AlphaCorp" not in lines[0]

    assert (
        "Company may be acquiring AlphaCorp"
        not in lines[0]
    )


# =========================================================
# TEST 7 - API MUST SAVE SECURITY EVENT TO POSTGRESQL
# =========================================================

def test_api_saves_event_to_postgresql(
    client,
    monkeypatch,
):
    """
    Verify that FastAPI passes the generated audit event
    to the PostgreSQL storage function.

    This test mocks the database call rather than
    writing to the real PostgreSQL database.
    """

    saved_events = []

    # Create a fake PostgreSQL insert function.

    def fake_database_save(event):

        saved_events.append(
            event.copy()
        )

        return True

    # Replace the database function with our test version.

    monkeypatch.setattr(
        "src.api.save_security_event",
        fake_database_save,
    )

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

    # Confirm the database function was called once.

    assert len(saved_events) == 1

    stored_event = saved_events[0]

    # Verify that the correct event was submitted.

    assert (
        stored_event["event_id"]
        == data["event_id"]
    )

    assert (
        stored_event["agent_id"]
        == "finance-agent-001"
    )

    assert stored_event["source_names"] == [
        "calendar",
        "travel",
        "finance",
    ]

    assert (
        stored_event["sensitive_inference"]
        is True
    )

    assert (
        stored_event["purpose_drift"]
        is True
    )

    assert stored_event["risk_level"] == "CRITICAL"

    assert stored_event["decision"] == "BLOCK"


# =========================================================
# TEST 8 - POSTGRESQL FAILURE MUST RETURN HTTP 503
# =========================================================

def test_database_failure_returns_service_error(
    client,
    monkeypatch,
):
    """
    Simulate PostgreSQL being unavailable.

    SYNTHSHIELD must not return a successful ALLOW
    response when required database auditing fails.
    """

    # Create a fake function that simulates an outage.

    def simulate_database_failure(event):

        raise ConnectionError(
            "Simulated PostgreSQL database outage."
        )

    # Replace PostgreSQL save function with failure.

    monkeypatch.setattr(
        "src.api.save_security_event",
        simulate_database_failure,
    )

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

    # The API must return Service Unavailable.

    assert response.status_code == 503

    data = response.json()

    assert data["detail"] == (
        "Security audit database is unavailable."
    )
