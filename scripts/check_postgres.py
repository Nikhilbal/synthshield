
from datetime import datetime, timezone
from uuid import uuid4, UUID

from src.database import get_database_connection
from src.event_store import (
    save_security_event,
    get_security_event,
)


def main():

    print("=" * 60)
    print("SYNTHSHIELD - PostgreSQL Integration Check")
    print("=" * 60)

    event_id = str(uuid4())

    test_event = {
        "event_id": event_id,
        "timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "agent_id": "integration-test-agent",
        "source_names": ["finance", "travel"],
        "source_count": 2,
        "sensitive_inference": False,
        "purpose_drift": False,
        "risk_level": "LOW",
        "decision": "ALLOW",
    }

    try:

        # TEST 1: Save a new event

        inserted = save_security_event(test_event)

        assert inserted is True

        print("[PASS] New security event inserted")

        # TEST 2: Retrieve the same event

        stored_event = get_security_event(event_id)

        assert stored_event is not None

        assert stored_event["event_id"] == UUID(event_id)
        assert stored_event["agent_id"] == "integration-test-agent"
        assert stored_event["decision"] == "ALLOW"
        assert stored_event["source_names"] == [
            "finance",
            "travel",
        ]

        print("[PASS] Security event retrieved correctly")

        # TEST 3: Check duplicate prevention

        duplicate_insert = save_security_event(test_event)

        assert duplicate_insert is False

        print("[PASS] Duplicate event prevented")

    finally:

        # Remove only this test's unique event.
        # Existing security events remain untouched.

        with get_database_connection() as connection:

            with connection.cursor() as cursor:

                cursor.execute(
                    "DELETE FROM security_events WHERE event_id = %s",
                    (UUID(event_id),),
                )

        print("[INFO] Temporary test event cleaned up")

    print("=" * 60)
    print("POSTGRESQL INTEGRATION CHECK SUCCESSFUL")
    print("=" * 60)


if __name__ == "__main__":
    main()
