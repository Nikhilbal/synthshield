
"""
SYNTHSHIELD
Stage 8.4.2 B3

Authenticated event retrieval and
cryptographic integrity verification tests.
"""

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from fastapi.testclient import TestClient

from src.api import app

from src.integrity import (
    AuditIntegrityConfigurationError,
    sign_security_event,
)


# =========================================================
# TEST CONFIGURATION
# =========================================================

TEST_API_KEY = "test-only-key-" + ("x" * 40)

TEST_HMAC_KEY = bytes.fromhex("ab" * 32)


@pytest.fixture
def client(monkeypatch):

    # Never use the application's real API key.

    monkeypatch.setenv(
        "SYNTHSHIELD_READ_API_KEY",
        TEST_API_KEY,
    )

    # Never use the application's real HMAC key.

    monkeypatch.setenv(
        "SYNTHSHIELD_AUDIT_HMAC_KEY",
        TEST_HMAC_KEY.hex(),
    )

    with TestClient(app) as test_client:
        yield test_client


def auth_headers():

    return {
        "Authorization": f"Bearer {TEST_API_KEY}"
    }


# =========================================================
# CREATE MOCK SIGNED EVENT
# =========================================================

def create_signed_test_event():

    event_id = uuid4()
    timestamp = datetime.now(timezone.utc)

    event = {
        "event_id": event_id,
        "timestamp_utc": timestamp,
        "agent_id": "finance-agent-001",
        "source_names": [
            "finance",
            "travel",
        ],
        "source_count": 2,
        "sensitive_inference": False,
        "purpose_drift": False,
        "risk_level": "LOW",
        "decision": "ALLOW",
        "recorded_at": timestamp,
    }

    event["integrity_tag"] = sign_security_event(
        event,
        key=TEST_HMAC_KEY,
    )

    return event


# =========================================================
# TEST 1 - MISSING API KEY MUST BE REJECTED
# =========================================================

def test_missing_api_key_is_rejected(
    client,
    monkeypatch,
):

    def should_not_read_database(event_id):

        pytest.fail(
            "Database accessed without authentication."
        )

    monkeypatch.setattr(
        "src.event_routes.get_security_event",
        should_not_read_database,
    )

    response = client.get(
        f"/v1/events/{uuid4()}"
    )

    assert response.status_code == 401


# =========================================================
# TEST 2 - INCORRECT API KEY MUST BE REJECTED
# =========================================================

def test_incorrect_api_key_is_rejected(
    client,
):

    response = client.get(
        f"/v1/events/{uuid4()}",
        headers={
            "Authorization": "Bearer incorrect-key",
        },
    )

    assert response.status_code == 401


# =========================================================
# TEST 3 - AUTHORIZED SIGNED EVENT RETURNS VERIFIED
# =========================================================

def test_authorized_event_can_be_retrieved(
    client,
    monkeypatch,
):

    event = create_signed_test_event()

    monkeypatch.setattr(
        "src.event_routes.get_security_event",
        lambda event_id: event,
    )

    response = client.get(
        f"/v1/events/{event['event_id']}",
        headers=auth_headers(),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["event_id"] == str(
        event["event_id"]
    )

    assert data["agent_id"] == "finance-agent-001"

    assert data["decision"] == "ALLOW"

    assert data["integrity_status"] == "VERIFIED"


# =========================================================
# TEST 4 - UNKNOWN EVENT RETURNS 404
# =========================================================

def test_nonexistent_event_returns_404(
    client,
    monkeypatch,
):

    monkeypatch.setattr(
        "src.event_routes.get_security_event",
        lambda event_id: None,
    )

    response = client.get(
        f"/v1/events/{uuid4()}",
        headers=auth_headers(),
    )

    assert response.status_code == 404


# =========================================================
# TEST 5 - LEGACY UNSIGNED EVENT RETURNS 409
# =========================================================

def test_legacy_unsigned_event_is_rejected(
    client,
    monkeypatch,
):

    event = create_signed_test_event()

    event["integrity_tag"] = None

    monkeypatch.setattr(
        "src.event_routes.get_security_event",
        lambda event_id: event,
    )

    response = client.get(
        f"/v1/events/{event['event_id']}",
        headers=auth_headers(),
    )

    assert response.status_code == 409

    assert response.json()["detail"] == (
        "UNSIGNED_LEGACY"
    )


# =========================================================
# TEST 6 - TAMPERED EVENT RETURNS 409
# =========================================================

def test_tampered_event_is_rejected(
    client,
    monkeypatch,
):

    event = create_signed_test_event()

    # Simulate tampering after the event was signed.
    # Its original signature remains unchanged.

    event["decision"] = "BLOCK"

    monkeypatch.setattr(
        "src.event_routes.get_security_event",
        lambda event_id: event,
    )

    response = client.get(
        f"/v1/events/{event['event_id']}",
        headers=auth_headers(),
    )

    assert response.status_code == 409

    assert response.json()["detail"] == (
        "INTEGRITY_FAILURE"
    )


# =========================================================
# TEST 7 - MALFORMED SIGNATURE RETURNS 409
# =========================================================

def test_invalid_integrity_tag_is_rejected(
    client,
    monkeypatch,
):

    event = create_signed_test_event()

    event["integrity_tag"] = "invalid-tag"

    monkeypatch.setattr(
        "src.event_routes.get_security_event",
        lambda event_id: event,
    )

    response = client.get(
        f"/v1/events/{event['event_id']}",
        headers=auth_headers(),
    )

    assert response.status_code == 409

    assert response.json()["detail"] == (
        "INTEGRITY_FAILURE"
    )


# =========================================================
# TEST 8 - VERIFICATION CONFIGURATION FAILURE
# =========================================================

def test_integrity_configuration_failure_returns_503(
    client,
    monkeypatch,
):

    event = create_signed_test_event()

    monkeypatch.setattr(
        "src.event_routes.get_security_event",
        lambda event_id: event,
    )

    def simulate_integrity_configuration_failure(
        event_data,
        tag,
    ):

        raise AuditIntegrityConfigurationError(
            "Simulated missing HMAC signing key."
        )

    monkeypatch.setattr(
        "src.event_routes.verify_security_event",
        simulate_integrity_configuration_failure,
    )

    response = client.get(
        f"/v1/events/{event['event_id']}",
        headers=auth_headers(),
    )

    assert response.status_code == 503

    assert response.json()["detail"] == (
        "Audit integrity verification unavailable."
    )
