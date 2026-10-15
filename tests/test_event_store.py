
"""
SYNTHSHIELD
Stage 8.4.1 - PostgreSQL Reliability Tests

These are REAL database integration tests.

Run explicitly using:

SYNTHSHIELD_RUN_DB_TESTS=1 python -m pytest \
    tests/test_event_store.py -v

Each inserted test event is deleted after its test.
"""

import os
from datetime import datetime, timezone
from uuid import UUID, uuid4

import psycopg
import pytest

from src.database import get_database_connection

from src.event_store import (
    get_security_event,
    save_security_event,
)


# =========================================================
# DATABASE TEST SAFETY
# =========================================================

@pytest.fixture(scope="module", autouse=True)
def require_database_test_opt_in():

    if os.getenv("SYNTHSHIELD_RUN_DB_TESTS") != "1":

        pytest.skip(
            "Real database tests require "
            "SYNTHSHIELD_RUN_DB_TESTS=1"
        )


# =========================================================
# TEST EVENT FACTORY
# =========================================================

def create_test_event():

    return {
        "event_id": str(uuid4()),
        "timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "agent_id": "stage-8-reliability-test",
        "source_names": [
            "finance",
            "travel",
        ],
        "source_count": 2,
        "sensitive_inference": False,
        "purpose_drift": False,
        "risk_level": "LOW",
        "decision": "ALLOW",
    }


# =========================================================
# SAFE TEST RECORD CLEANUP
# =========================================================

@pytest.fixture
def test_event():

    event = create_test_event()

    yield event

    # Delete only this test's generated event ID.

    with get_database_connection() as connection:

        with connection.cursor() as cursor:

            cursor.execute(
                """
                DELETE FROM security_events
                WHERE event_id = %s
                AND agent_id = %s
                """,
                (
                    UUID(event["event_id"]),
                    "stage-8-reliability-test",
                ),
            )


# =========================================================
# TEST 1 - INSERT A REAL DATABASE EVENT
# =========================================================

def test_insert_security_event(test_event):

    inserted = save_security_event(
        test_event
    )

    assert inserted is True

    stored = get_security_event(
        test_event["event_id"]
    )

    assert stored is not None

    assert stored["event_id"] == UUID(
        test_event["event_id"]
    )

    assert stored["agent_id"] == (
        "stage-8-reliability-test"
    )

    assert stored["decision"] == "ALLOW"


# =========================================================
# TEST 2 - RETRIEVE ALL IMPORTANT EVENT FIELDS
# =========================================================

def test_retrieve_security_event(test_event):

    assert save_security_event(test_event) is True

    stored = get_security_event(
        test_event["event_id"]
    )

    assert stored is not None

    assert stored["source_names"] == [
        "finance",
        "travel",
    ]

    assert stored["source_count"] == 2

    assert stored["sensitive_inference"] is False

    assert stored["purpose_drift"] is False

    assert stored["risk_level"] == "LOW"

    assert stored["decision"] == "ALLOW"

    assert stored["recorded_at"] is not None


# =========================================================
# TEST 3 - PREVENT DUPLICATE SECURITY EVENTS
# =========================================================

def test_duplicate_event_is_prevented(test_event):

    first_insert = save_security_event(
        test_event
    )

    second_insert = save_security_event(
        test_event
    )

    assert first_insert is True

    assert second_insert is False

    with get_database_connection() as connection:

        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT COUNT(*)
                FROM security_events
                WHERE event_id = %s
                """,
                (UUID(test_event["event_id"]),),
            )

            count = cursor.fetchone()[0]

    assert count == 1


# =========================================================
# TEST 4 - UNKNOWN EVENT MUST RETURN NONE
# =========================================================

def test_unknown_event_returns_none():

    unknown_event_id = str(uuid4())

    result = get_security_event(
        unknown_event_id
    )

    assert result is None


# =========================================================
# TEST 5 - REJECT INCONSISTENT SOURCE COUNT
# =========================================================

def test_database_rejects_invalid_source_count(
    test_event,
):

    # The event lists two sources, but we falsely
    # claim it has three. PostgreSQL should reject it.

    test_event["source_count"] = 3

    with pytest.raises(
        psycopg.errors.CheckViolation
    ):

        save_security_event(
            test_event
        )

    # Confirm the invalid event was not saved.

    result = get_security_event(
        test_event["event_id"]
    )

    assert result is None

# =========================================================
# TEST 6 - NEW EVENT MUST HAVE A VALID HMAC TAG
# =========================================================

def test_new_event_has_valid_integrity_tag(
    test_event,
):

    from src.integrity import verify_security_event

    # Store a new event.

    inserted = save_security_event(test_event)

    assert inserted is True

    # Retrieve the real PostgreSQL record.

    stored = get_security_event(
        test_event["event_id"]
    )

    assert stored is not None

    # The record must contain an HMAC tag.

    assert stored["integrity_tag"] is not None

    assert len(stored["integrity_tag"]) == 64

    # Confirm that the HMAC matches the
    # event metadata stored in PostgreSQL.

    assert verify_security_event(
        stored,
        stored["integrity_tag"],
    ) is True


# =========================================================
# TEST 7 - MODIFIED EVENT COPY MUST FAIL VERIFICATION
# =========================================================

def test_modified_event_fails_integrity_check(
    test_event,
):

    from src.integrity import verify_security_event

    # Insert a real event into PostgreSQL.

    assert save_security_event(test_event) is True

    stored = get_security_event(
        test_event["event_id"]
    )

    assert stored is not None

    # Verify that the original event is authentic.

    assert verify_security_event(
        stored,
        stored["integrity_tag"],
    ) is True

    # Simulate tampering with a local copy.
    # Do not modify the actual database record.

    tampered_event = stored.copy()

    tampered_event["decision"] = "BLOCK"

    # The stored tag no longer matches the
    # modified security decision.

    assert verify_security_event(
        tampered_event,
        stored["integrity_tag"],
    ) is False
