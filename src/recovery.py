
"""
SYNTHSHIELD
Stage 8.4.3 C3A - Controlled Recovery Planning

Read-only recovery preview.

No database inserts, updates or deletes occur.
"""

from uuid import UUID

from src.event_store import get_security_event

from src.integrity import (
    canonical_event_payload,
    verify_security_event,
)

from src.recovery_journal import read_recovery_journal


class RecoveryPlanningError(Exception):
    """Recovery planning cannot proceed safely."""


def build_recovery_plan(
    journal_file=None,
    key=None,
):
    """
    Authenticate the recovery journal and compare
    each event against PostgreSQL.

    Returns a list of recovery classifications.
    """

    # Validate the complete journal before
    # checking or considering any database changes.

    journal_events = read_recovery_journal(
        journal_file=journal_file,
        key=key,
    )

    plan = []
    seen_ids = set()

    for event in journal_events:

        event_id = str(
            UUID(str(event["event_id"]))
        )

        # Duplicate IDs are ambiguous.
        # Refuse to process such a journal.

        if event_id in seen_ids:
            raise RecoveryPlanningError(
                "Duplicate event ID in recovery journal."
            )

        seen_ids.add(event_id)

        stored = get_security_event(event_id)

        if stored is None:

            status = "MISSING_IN_DB"

        elif stored.get("integrity_tag") is None:

            status = "UNSIGNED_EXISTING"

        else:

            try:

                valid = verify_security_event(
                    stored,
                    stored["integrity_tag"],
                    key=key,
                )

            except (KeyError, ValueError, TypeError):

                valid = False

            if not valid:

                status = "DB_INTEGRITY_FAILURE"

            elif (
                canonical_event_payload(event)
                != canonical_event_payload(stored)
            ):

                status = "CONFLICT"

            else:

                status = "MATCHED"

        plan.append({
            "event_id": event_id,
            "status": status,
        })

    return plan


def main():

    print("=" * 60)
    print("SYNTHSHIELD - Recovery Dry Run")
    print("=" * 60)

    plan = build_recovery_plan()

    counts = {
        "MATCHED": 0,
        "MISSING_IN_DB": 0,
        "CONFLICT": 0,
        "DB_INTEGRITY_FAILURE": 0,
        "UNSIGNED_EXISTING": 0,
    }

    for item in plan:

        counts[item["status"]] += 1

        print(
            item["status"],
            item["event_id"],
        )

    print("-" * 60)

    for status, count in counts.items():
        print(f"{status}: {count}")

    print("=" * 60)
    print("READ-ONLY RECOVERY PREVIEW COMPLETE")


if __name__ == "__main__":
    main()
