
"""
SYNTHSHIELD
Stage 8.4.3 C1 - Authenticated Recovery Journal

This module:
1. Signs event metadata with HMAC-SHA256.
2. Appends journal records to a private file.
3. Flushes writes to disk using fsync().
4. Verifies records before returning them.

No automatic PostgreSQL replay is performed.
"""

import fcntl
import json
import os
import stat

from pathlib import Path

from src.integrity import (
    canonical_event_payload,
    sign_security_event,
    verify_security_event,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_JOURNAL = (
    PROJECT_ROOT
    / "audit_logs"
    / "recovery_journal.jsonl"
)


class RecoveryJournalError(Exception):
    """Base journal exception."""


class RecoveryJournalIntegrityError(RecoveryJournalError):
    """A journal record failed authentication."""


class RecoveryJournalFormatError(RecoveryJournalError):
    """A journal record has an invalid format."""


def append_recovery_event(
    event,
    journal_file=None,
    key=None,
):
    """
    Append an authenticated event to the journal.

    Only the approved audit fields are stored.
    Caller-supplied integrity tags are ignored.
    """

    path = Path(journal_file or DEFAULT_JOURNAL)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )

    canonical_event = json.loads(
        canonical_event_payload(event)
    )

    integrity_tag = sign_security_event(
        canonical_event,
        key=key,
    )

    journal_record = {
        "version": 1,
        "event": canonical_event,
        "integrity_tag": integrity_tag,
    }

    serialized = (
        json.dumps(
            journal_record,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")

    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_APPEND
        | getattr(os, "O_NOFOLLOW", 0)
    )

    fd = os.open(
        path,
        flags,
        0o600,
    )

    try:
        permissions = stat.S_IMODE(
            os.fstat(fd).st_mode
        )

        if permissions & 0o077:
            raise PermissionError(
                "Recovery journal permissions are too open."
            )

        # Prevent cooperating local processes from
        # interleaving writes to this journal.

        fcntl.flock(
            fd,
            fcntl.LOCK_EX,
        )

        try:
            remaining = memoryview(serialized)

            while remaining:
                written = os.write(fd, remaining)

                if written <= 0:
                    raise OSError(
                        "Recovery journal write failed."
                    )

                remaining = remaining[written:]

            # Request that the operating system flush
            # the written journal data to storage.

            os.fsync(fd)

        finally:
            fcntl.flock(
                fd,
                fcntl.LOCK_UN,
            )

    finally:
        os.close(fd)

    return integrity_tag


def read_recovery_journal(
    journal_file=None,
    key=None,
):
    """
    Read and authenticate every journal record.

    Fail closed on invalid JSON, unsupported format,
    or invalid HMAC.

    No database modifications occur.
    """

    path = Path(journal_file or DEFAULT_JOURNAL)

    if not path.exists():
        return []

    verified_events = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as journal:

        for line_number, line in enumerate(
            journal,
            start=1,
        ):

            try:
                record = json.loads(line)

                if (
                    not isinstance(record, dict)
                    or record.get("version") != 1
                    or not isinstance(
                        record.get("event"),
                        dict,
                    )
                ):
                    raise RecoveryJournalFormatError(
                        f"Invalid record at line {line_number}."
                    )

                event = record["event"]
                tag = record.get("integrity_tag")

                valid = verify_security_event(
                    event,
                    tag,
                    key=key,
                )

            except (
                json.JSONDecodeError,
                KeyError,
                ValueError,
                TypeError,
                RecoveryJournalFormatError,
            ) as exc:
                raise RecoveryJournalFormatError(
                    f"Malformed journal line {line_number}."
                ) from exc

            if not valid:
                raise RecoveryJournalIntegrityError(
                    f"Integrity failure at line {line_number}."
                )

            verified_events.append(event)

    return verified_events
