
"""
SYNTHSHIELD
Stage 8.4.3 C3C - Controlled PostgreSQL Recovery

Safely preview or recover one authenticated
security event from an isolated recovery journal.

Safety controls:
- Dry-run by default
- Explicit event ID required
- Explicit approval required for writes
- Live recovery journal is prohibited
- HMAC verification before recovery
- Existing database records are verified
- Conflicting records are never overwritten
- Duplicate event IDs are handled safely

No bulk or automatic recovery.
"""

import argparse
import json

from pathlib import Path
from uuid import UUID

from src.event_store import (
    get_security_event,
    save_security_event,
)

from src.integrity import (
    canonical_event_payload,
    verify_security_event,
)

from src.recovery_journal import (
    DEFAULT_JOURNAL,
    read_recovery_journal,
)


class RecoveryExecutionError(Exception):
    """
    Recovery cannot be completed safely.
    """


# =========================================================
# STEP 1 - VALIDATE RECOVERY JOURNAL PATH
# =========================================================

def _validated_journal(journal_file):

    if journal_file is None:
        raise RecoveryExecutionError(
            "An explicit journal path is required."
        )

    path = Path(journal_file)

    # The operational recovery journal must
    # never be replayed through this tool.

    if path.resolve() == Path(DEFAULT_JOURNAL).resolve():
        raise RecoveryExecutionError(
            "The live recovery journal is protected. "
            "Use an isolated test journal."
        )

    if path.is_symlink():
        raise RecoveryExecutionError(
            "Journal symlinks are not allowed."
        )

    if not path.is_file():
        raise RecoveryExecutionError(
            "Journal file does not exist."
        )

    return path


# =========================================================
# STEP 2 - LOAD ONE AUTHENTICATED EVENT
# =========================================================

def _load_selected_event(path, event_id):

    # Authenticates all records before any
    # database operations occur.

    journal_events = read_recovery_journal(
        journal_file=path,
    )

    seen = set()
    selected = None

    for event in journal_events:

        try:
            record_id = str(
                UUID(str(event["event_id"]))
            )

        except (
            KeyError,
            ValueError,
            TypeError,
        ) as exc:

            raise RecoveryExecutionError(
                "Journal contains an invalid event ID."
            ) from exc

        # Duplicate event IDs create ambiguity.

        if record_id in seen:
            raise RecoveryExecutionError(
                "Duplicate event ID in journal."
            )

        seen.add(record_id)

        if record_id == event_id:
            selected = event

    if selected is None:
        raise RecoveryExecutionError(
            "Requested event is absent from the journal."
        )

    return selected


# =========================================================
# STEP 3 - VERIFY EXISTING POSTGRESQL RECORD
# =========================================================

def _verify_existing(stored, expected):

    integrity_tag = stored.get(
        "integrity_tag"
    )

    if not integrity_tag:
        raise RecoveryExecutionError(
            "Existing database event is unsigned."
        )

    try:
        valid = verify_security_event(
            stored,
            integrity_tag,
        )

    except (
        KeyError,
        ValueError,
        TypeError,
    ) as exc:

        raise RecoveryExecutionError(
            "Existing database event is malformed."
        ) from exc

    if not valid:
        raise RecoveryExecutionError(
            "Existing database event failed "
            "HMAC verification."
        )

    # A correctly signed record can still be
    # different from the selected journal event.

    if (
        canonical_event_payload(stored)
        != canonical_event_payload(expected)
    ):
        raise RecoveryExecutionError(
            "Existing database event conflicts "
            "with the journal."
        )


# =========================================================
# STEP 4 - EXECUTE ONE CONTROLLED RECOVERY
# =========================================================

def recover_one_event(
    *,
    journal_file,
    event_id,
    apply=False,
    approve_event_id=None,
):
    """
    Preview or recover exactly one event.

    By default no database modification occurs.

    To enable insertion:
        apply=True
        approve_event_id=<same event UUID>

    Returns:
        event_id
        status
        written
    """

    # -----------------------------------------
    # VALIDATE THE REQUESTED EVENT ID
    # -----------------------------------------

    try:
        target_id = str(
            UUID(str(event_id))
        )

    except (
        ValueError,
        TypeError,
    ) as exc:

        raise RecoveryExecutionError(
            "Invalid requested event ID."
        ) from exc

    # -----------------------------------------
    # REQUIRE EXPLICIT WRITE APPROVAL
    # -----------------------------------------

    if apply and approve_event_id != target_id:

        raise RecoveryExecutionError(
            "Write not approved: "
            "--approve-event-id must match --event-id."
        )

    # -----------------------------------------
    # AUTHENTICATE THE JOURNAL
    # -----------------------------------------

    path = _validated_journal(
        journal_file
    )

    event = _load_selected_event(
        path,
        target_id,
    )

    # -----------------------------------------
    # CHECK POSTGRESQL
    # -----------------------------------------

    stored = get_security_event(
        target_id
    )

    # Existing record:
    # Verify it and skip insertion.

    if stored is not None:

        _verify_existing(
            stored,
            event,
        )

        return {
            "event_id": target_id,
            "status": "MATCHED",
            "written": False,
        }

    # -----------------------------------------
    # DEFAULT: DRY RUN ONLY
    # -----------------------------------------

    if not apply:

        return {
            "event_id": target_id,
            "status": "READY_TO_RECOVER",
            "written": False,
        }

    # -----------------------------------------
    # INSERT INTO POSTGRESQL
    # -----------------------------------------

    # save_security_event uses:
    # ON CONFLICT (event_id) DO NOTHING
    #
    # This prevents duplicate primary keys.

    inserted = save_security_event(
        event
    )

    # -----------------------------------------
    # VERIFY AFTER INSERT ATTEMPT
    # -----------------------------------------

    # Always retrieve the event again.
    # Another process might have inserted it
    # between our initial check and the insert.

    stored = get_security_event(
        target_id
    )

    if stored is None:
        raise RecoveryExecutionError(
            "Event was not found after "
            "the insert attempt."
        )

    _verify_existing(
        stored,
        event,
    )

    # -----------------------------------------
    # RETURN FINAL RESULT
    # -----------------------------------------

    return {
        "event_id": target_id,
        "status": (
            "RECOVERED"
            if inserted
            else "MATCHED_AFTER_RACE"
        ),
        "written": bool(inserted),
    }


# =========================================================
# STEP 5 - COMMAND-LINE INTERFACE
# =========================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "SYNTHSHIELD single-event recovery"
        )
    )

    parser.add_argument(
        "--journal",
        required=True,
        help="Isolated JSONL journal path",
    )

    parser.add_argument(
        "--event-id",
        required=True,
        help="One UUID to preview or recover",
    )

    parser.add_argument(
        "--apply",
        action="store_true",
        help="Enable a database insert",
    )

    parser.add_argument(
        "--approve-event-id",
        help=(
            "Repeat UUID to approve "
            "a database write"
        ),
    )

    args = parser.parse_args()

    try:
        result = recover_one_event(
            journal_file=args.journal,
            event_id=args.event_id,
            apply=args.apply,
            approve_event_id=args.approve_event_id,
        )

    except RecoveryExecutionError as exc:

        parser.exit(
            2,
            f"Recovery stopped: {exc}\n",
        )

    except Exception:

        # Do not print complete database
        # connection strings or credentials.

        parser.exit(
            2,
            "Recovery stopped: journal verification "
            "or database access failed.\n",
        )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
