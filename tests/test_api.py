
"""
SYNTHSHIELD
FASTAPI AUTOMATED SECURITY TESTS

Stage 8.4.3 C3 - Isolated API Tests

This test suite verifies:

1. API health
2. Legitimate task authorization
3. Sensitive inference blocking
4. Unknown source validation
5. Duplicate source validation
6. JSONL audit logging
7. PostgreSQL persistence
8. PostgreSQL failure handling
9. JSONL audit preservation during database failure
10. Recovery journal and database operation ordering
11. Recovery journal failure handling
12. Database failure after recovery journaling

IMPORTANT:
All API unit tests are isolated from real persistence:

- JSONL audit events use temporary files.
- Recovery journal writes are mocked.
- PostgreSQL inserts are mocked.

No real recovery-journal or database records should be
created by these API tests.
"""

import json

import pytest

from fastapi.testclient import TestClient

from src.api import app
from src.audit import write_security_event


# =========================================================
# TEST CLIENT FIXTURE
# =========================================================

@pytest.fixture
def client(tmp_path, monkeypatch):
    """
    Create an isolated FastAPI test client.

    JSONL logging is redirected to a temporary file.

    Recovery-journal writes and PostgreSQL persistence
    are mocked to prevent changes to real audit storage.

    Monkeypatch restores the original functions after
    each test.
    """

    # -----------------------------------------------------
    # MOCK 1: ISOLATED JSONL AUDIT LOG
    # -----------------------------------------------------

    def write_test_event(**kwargs):

        return write_security_event(
            **kwargs,
            log_file=tmp_path / "security_events.jsonl",
        )

    monkeypatch.setattr(
        "src.api.write_security_event",
        write_test_event,
    )

    # -----------------------------------------------------
    # MOCK 2: AUTHENTICATED RECOVERY JOURNAL
    # -----------------------------------------------------

    # Prevent automated API tests from writing to the
    # real audit_logs/recovery_journal.jsonl file.

    monkeypatch.setattr(
        "src.api.append_recovery_event",
        lambda event: "simulated-journal-tag",
    )

    # -----------------------------------------------------
    # MOCK 3: POSTGRESQL EVENT STORAGE
    # -----------------------------------------------------

    # Prevent API tests from inserting records
    # into the real PostgreSQL database.

    monkeypatch.setattr(
        "src.api.save_security_event",
        lambda event: True,
    )

    # -----------------------------------------------------
    # CREATE FASTAPI TEST CLIENT
    # -----------------------------------------------------

    with TestClient(app) as test_client:

        yield test_client


# =========================================================
# TEST 1 - API HEALTH CHECK
# =========================================================

def test_api_health(client):
    """
    Verify that the SYNTHSHIELD API responds correctly.
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
    A legitimate monthly expense-reporting task using
    Finance and Travel data should be allowed.
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
    Combining Calendar, Travel, and Finance data for
    sensitive acquisition analysis must result in BLOCK.
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
    Unsupported data sources must be rejected during
    request validation.
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
    The same source must not be submitted multiple times.
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
    Verify that an API request creates a JSONL event.

    The audit log must contain security metadata,
    not inferred confidential information.
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

    # Temporary audit log used by the test fixture.

    log_file = (
        tmp_path / "security_events.jsonl"
    )

    assert log_file.exists()

    lines = log_file.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(lines) == 1

    event = json.loads(lines[0])

    assert event["event_id"] == data["event_id"]

    assert event["decision"] == "BLOCK"

    assert event["risk_level"] == "CRITICAL"

    assert event["purpose_drift"] is True

    assert event["sensitive_inference"] is True

    # Confidential inference content must not
    # be written into the audit log.

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
    Verify FastAPI submits the generated audit event
    to the PostgreSQL storage function.

    The database is mocked; no real insert occurs.
    """

    saved_events = []

    def fake_database_save(event):

        saved_events.append(
            event.copy()
        )

        return True

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

    assert len(saved_events) == 1

    stored_event = saved_events[0]

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
    When PostgreSQL is unavailable, the API must
    return HTTP 503 instead of a successful response.
    """

    def simulate_database_failure(event):

        raise ConnectionError(
            "Simulated PostgreSQL database outage."
        )

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

    assert response.status_code == 503

    data = response.json()

    assert data["detail"] == (
        "Security audit database is unavailable."
    )


# =========================================================
# TEST 9 - DATABASE FAILURE LEAVES JSONL AUDIT RECORD
# =========================================================

def test_database_failure_keeps_jsonl_audit(
    client,
    tmp_path,
    monkeypatch,
):
    """
    Verify existing behavior when PostgreSQL fails
    after the JSONL audit event has been written.

    The JSONL record should remain available.
    """

    def simulated_database_outage(event):

        raise ConnectionError(
            "Simulated PostgreSQL outage."
        )

    monkeypatch.setattr(
        "src.api.save_security_event",
        simulated_database_outage,
    )

    response = client.post(
        "/v1/evaluate",
        json={
            "requested_task": (
                "Prepare the monthly expense report."
            ),
            "sources": [
                "finance",
                "travel",
            ],
        },
    )

    assert response.status_code == 503

    log_file = (
        tmp_path / "security_events.jsonl"
    )

    assert log_file.exists()

    lines = log_file.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(lines) == 1

    event = json.loads(lines[0])

    assert event["agent_id"] == "finance-agent-001"

    assert event["decision"] == "ALLOW"

    # The event remains in the temporary JSONL log.
    # The PostgreSQL insertion was simulated to fail.


# =========================================================
# TEST 10 - JOURNAL MUST RUN BEFORE POSTGRESQL
# =========================================================

def test_recovery_journal_runs_before_database(
    client,
    monkeypatch,
):
    """
    Verify that the authenticated recovery journal
    is called before PostgreSQL persistence.

    Both operations are mocked.
    """

    operations = []

    def fake_journal(event):

        operations.append(
            ("journal", event["event_id"])
        )

        return "simulated-tag"

    def fake_database(event):

        operations.append(
            ("database", event["event_id"])
        )

        return True

    monkeypatch.setattr(
        "src.api.append_recovery_event",
        fake_journal,
    )

    monkeypatch.setattr(
        "src.api.save_security_event",
        fake_database,
    )

    response = client.post(
        "/v1/evaluate",
        json={
            "requested_task": (
                "Prepare the monthly expense report."
            ),
            "sources": [
                "finance",
                "travel",
            ],
        },
    )

    assert response.status_code == 200

    event_id = response.json()["event_id"]

    assert operations == [
        ("journal", event_id),
        ("database", event_id),
    ]


# =========================================================
# TEST 11 - JOURNAL FAILURE MUST STOP DATABASE INSERT
# =========================================================

def test_journal_failure_prevents_database_insert(
    client,
    monkeypatch,
):
    """
    If recovery journaling fails, SYNTHSHIELD
    must not proceed with PostgreSQL persistence.
    """

    database_called = []

    def failed_journal(event):

        raise OSError(
            "Simulated journal disk failure."
        )

    def fake_database(event):

        database_called.append(event)

        return True

    monkeypatch.setattr(
        "src.api.append_recovery_event",
        failed_journal,
    )

    monkeypatch.setattr(
        "src.api.save_security_event",
        fake_database,
    )

    response = client.post(
        "/v1/evaluate",
        json={
            "requested_task": (
                "Prepare the monthly expense report."
            ),
            "sources": [
                "finance",
                "travel",
            ],
        },
    )

    assert response.status_code == 503

    assert response.json()["detail"] == (
        "Security recovery journal is unavailable."
    )

    assert database_called == []


# =========================================================
# TEST 12 - DATABASE OUTAGE AFTER RECOVERY JOURNAL
# =========================================================

def test_database_failure_after_recovery_journal(
    client,
    monkeypatch,
):
    """
    Simulate successful recovery journaling followed
    by a PostgreSQL failure.

    Confirm that journaling was attempted before
    the database operation failed.
    """

    journaled_events = []

    def fake_journal(event):

        journaled_events.append(
            event.copy()
        )

        return "simulated-tag"

    def failed_database(event):

        raise ConnectionError(
            "Simulated PostgreSQL outage."
        )

    monkeypatch.setattr(
        "src.api.append_recovery_event",
        fake_journal,
    )

    monkeypatch.setattr(
        "src.api.save_security_event",
        failed_database,
    )

    response = client.post(
        "/v1/evaluate",
        json={
            "requested_task": (
                "Analyze whether the company "
                "may be acquiring AlphaCorp."
            ),
            "sources": [
                "calendar",
                "travel",
                "finance",
            ],
        },
    )

    assert response.status_code == 503

    assert len(journaled_events) == 1

    assert (
        journaled_events[0]["decision"]
        == "BLOCK"
    )

    assert (
        journaled_events[0]["risk_level"]
        == "CRITICAL"
    )
