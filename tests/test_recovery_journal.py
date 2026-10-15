
"""
SYNTHSHIELD
Stage 8.4.3 C1 - Recovery Journal Tests
"""

import json
import stat

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from src.recovery_journal import (
    RecoveryJournalFormatError,
    RecoveryJournalIntegrityError,
    append_recovery_event,
    read_recovery_journal,
)


TEST_KEY = bytes.fromhex("ab" * 32)


@pytest.fixture
def event():

    return {
        "event_id": str(uuid4()),
        "timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "agent_id": "recovery-test-agent",
        "source_names": ["finance", "travel"],
        "source_count": 2,
        "sensitive_inference": False,
        "purpose_drift": False,
        "risk_level": "LOW",
        "decision": "ALLOW",
    }


# TEST 1 - EVENT CAN BE WRITTEN AND VERIFIED

def test_journal_write_and_read(tmp_path, event):

    path = tmp_path / "journal.jsonl"

    append_recovery_event(
        event,
        journal_file=path,
        key=TEST_KEY,
    )

    events = read_recovery_journal(
        journal_file=path,
        key=TEST_KEY,
    )

    assert len(events) == 1
    assert events[0]["event_id"] == event["event_id"]
    assert events[0]["decision"] == "ALLOW"


# TEST 2 - SENSITIVE EXTRA FIELDS ARE NOT SAVED

def test_only_approved_metadata_is_stored(
    tmp_path,
    event,
):

    path = tmp_path / "journal.jsonl"

    event["derived_information"] = (
        "CONFIDENTIAL_TEST_SECRET"
    )

    append_recovery_event(
        event,
        journal_file=path,
        key=TEST_KEY,
    )

    content = path.read_text(encoding="utf-8")

    assert "CONFIDENTIAL_TEST_SECRET" not in content


# TEST 3 - TAMPERING MUST BE DETECTED

def test_modified_journal_event_is_rejected(
    tmp_path,
    event,
):

    path = tmp_path / "journal.jsonl"

    append_recovery_event(
        event,
        journal_file=path,
        key=TEST_KEY,
    )

    record = json.loads(
        path.read_text(encoding="utf-8")
    )

    record["event"]["decision"] = "BLOCK"

    path.write_text(
        json.dumps(record) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        RecoveryJournalIntegrityError
    ):
        read_recovery_journal(
            journal_file=path,
            key=TEST_KEY,
        )


# TEST 4 - INCORRECT HMAC KEY MUST FAIL

def test_wrong_key_is_rejected(tmp_path, event):

    path = tmp_path / "journal.jsonl"

    append_recovery_event(
        event,
        journal_file=path,
        key=TEST_KEY,
    )

    wrong_key = bytes.fromhex("cd" * 32)

    with pytest.raises(
        RecoveryJournalIntegrityError
    ):
        read_recovery_journal(
            journal_file=path,
            key=wrong_key,
        )


# TEST 5 - CORRUPTED LINE MUST FAIL CLOSED

def test_corrupted_journal_line_is_rejected(
    tmp_path,
):

    path = tmp_path / "journal.jsonl"

    path.write_text(
        '{"event": incomplete\n',
        encoding="utf-8",
    )

    with pytest.raises(
        RecoveryJournalFormatError
    ):
        read_recovery_journal(
            journal_file=path,
            key=TEST_KEY,
        )


# TEST 6 - JOURNAL FILE MUST BE PRIVATE

def test_journal_permissions_are_private(
    tmp_path,
    event,
):

    path = tmp_path / "journal.jsonl"

    append_recovery_event(
        event,
        journal_file=path,
        key=TEST_KEY,
    )

    mode = stat.S_IMODE(path.stat().st_mode)

    assert mode == 0o600
