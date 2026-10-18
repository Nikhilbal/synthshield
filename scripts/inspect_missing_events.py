
"""
SYNTHSHIELD
Stage 8.4.3 B - Missing Audit Event Investigation

Read-only investigation of JSONL events
that are absent from PostgreSQL.

Does not modify, delete, or replay records.
"""

import json

from src.reconciliation import (
    DEFAULT_AUDIT_LOG,
    reconcile_audit_events,
)


def main():

    print("=" * 65)
    print("SYNTHSHIELD - Missing Event Investigation")
    print("=" * 65)

    # Compare JSONL with PostgreSQL.

    report = reconcile_audit_events()

    missing_ids = set(
        report["missing_event_ids"]
    )

    print(
        f"\nTotal missing events: {len(missing_ids)}"
    )

    if not missing_ids:
        print("\nNo missing database events found.")
        return

    print("\nMISSING EVENT DETAILS")
    print("-" * 65)

    # Read original JSONL records.
    # Display metadata only, not sensitive content.

    with DEFAULT_AUDIT_LOG.open(
        "r",
        encoding="utf-8",
    ) as log_file:

        for line_number, line in enumerate(
            log_file,
            start=1,
        ):

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(event, dict):
                continue

            event_id = event.get("event_id")

            if event_id not in missing_ids:
                continue

            print(f"\nJSONL line  : {line_number}")

            print(
                "Event ID    :",
                event_id,
            )

            print(
                "Created UTC :",
                event.get("timestamp_utc"),
            )

            print(
                "Agent       :",
                event.get("agent_id"),
            )

            print(
                "Source count:",
                event.get("source_count"),
            )

            print(
                "Risk level  :",
                event.get("risk_level"),
            )

            print(
                "Decision    :",
                event.get("decision"),
            )

            print("-" * 65)

    print("\nINVESTIGATION COMPLETE")
    print("No database records were modified.")


if __name__ == "__main__":
    main()
