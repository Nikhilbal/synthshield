
"""
SYNTHSHIELD
Stage 8.4.3 A - Audit Reconciliation

Compare JSONL audit events against PostgreSQL.

READ-ONLY:
- Does not insert events
- Does not modify the database
- Does not delete audit records
- Does not automatically replay missing events

JSONL records are treated as untrusted evidence.
"""

import json
from pathlib import Path
from uuid import UUID

from src.event_store import get_security_event
from src.integrity import normalize_timestamp


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_AUDIT_LOG = (
    PROJECT_ROOT / "audit_logs" / "security_events.jsonl"
)


REQUIRED_FIELDS = (
    "event_id",
    "timestamp_utc",
    "agent_id",
    "source_names",
    "source_count",
    "sensitive_inference",
    "purpose_drift",
    "risk_level",
    "decision",
)

COMPARE_FIELDS = (
    "agent_id",
    "source_names",
    "source_count",
    "sensitive_inference",
    "purpose_drift",
    "risk_level",
    "decision",
)


def reconcile_audit_events(log_file=DEFAULT_AUDIT_LOG):
    """
    Identify discrepancies between the JSONL audit
    file and PostgreSQL.

    Database errors deliberately propagate rather
    than being reported as missing events.
    """

    path = Path(log_file)

    if not path.is_file():
        raise FileNotFoundError(
            f"Audit log does not exist: {path}"
        )

    report = {
        "checked_events": 0,
        "matching_events": 0,
        "missing_event_ids": [],
        "mismatched_event_ids": [],
        "invalid_lines": [],
        "duplicate_event_ids": [],
    }

    seen_event_ids = set()

    with path.open(
        "r",
        encoding="utf-8",
    ) as audit_file:

        for line_number, line in enumerate(
            audit_file,
            start=1,
        ):

            # -----------------------------------------
            # STEP 1: PARSE JSONL RECORD
            # -----------------------------------------

            try:
                event = json.loads(line)

                if not isinstance(event, dict):
                    raise ValueError(
                        "Audit entry must be a JSON object."
                    )

                if any(
                    field not in event
                    for field in REQUIRED_FIELDS
                ):
                    raise ValueError(
                        "Audit entry is missing required fields."
                    )

                event_id = str(
                    UUID(str(event["event_id"]))
                )

                event_timestamp = normalize_timestamp(
                    event["timestamp_utc"]
                )

            except (
                json.JSONDecodeError,
                ValueError,
                TypeError,
                KeyError,
            ):
                report["invalid_lines"].append(
                    line_number
                )
                continue

            # -----------------------------------------
            # STEP 2: DETECT DUPLICATE JSONL IDS
            # -----------------------------------------

            if event_id in seen_event_ids:

                report["duplicate_event_ids"].append(
                    event_id
                )

                continue

            seen_event_ids.add(event_id)

            report["checked_events"] += 1

            # -----------------------------------------
            # STEP 3: LOOK UP EVENT IN POSTGRESQL
            # -----------------------------------------

            stored_event = get_security_event(
                event_id
            )

            if stored_event is None:

                report["missing_event_ids"].append(
                    event_id
                )

                continue

            # -----------------------------------------
            # STEP 4: COMPARE EVENT METADATA
            # -----------------------------------------

            fields_match = all(
                event[field] == stored_event[field]
                for field in COMPARE_FIELDS
            )

            timestamps_match = (
                event_timestamp
                == normalize_timestamp(
                    stored_event["timestamp_utc"]
                )
            )

            if fields_match and timestamps_match:

                report["matching_events"] += 1

            else:

                report["mismatched_event_ids"].append(
                    event_id
                )

    return report


def main():

    print("=" * 60)
    print("SYNTHSHIELD - Audit Reconciliation")
    print("=" * 60)

    report = reconcile_audit_events()

    print(
        "Checked events   :",
        report["checked_events"],
    )

    print(
        "Matching events  :",
        report["matching_events"],
    )

    print(
        "Missing in DB    :",
        len(report["missing_event_ids"]),
    )

    print(
        "Metadata mismatch:",
        len(report["mismatched_event_ids"]),
    )

    print(
        "Invalid JSONL lines:",
        report["invalid_lines"],
    )

    print(
        "Duplicate IDs    :",
        len(report["duplicate_event_ids"]),
    )

    # Report discrepancies without exposing
    # complete audit metadata or secret values.

    for event_id in report["missing_event_ids"]:
        print("MISSING_IN_DB:", event_id)

    for event_id in report["mismatched_event_ids"]:
        print("METADATA_MISMATCH:", event_id)

    print("=" * 60)

    print(
        "READ-ONLY RECONCILIATION COMPLETE"
    )


if __name__ == "__main__":
    main()
