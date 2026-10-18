
"""
SYNTHSHIELD
Stage 8.4.3 C3C - Recovery Executor Tests

All tests use:
- Temporary recovery journals
- Synthetic event metadata
- Mocked database operations
- A disposable test signing key

No real PostgreSQL records are modified.
"""

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from src.integrity import sign_security_event

from src.recovery_executor import (
    RecoveryExecutionError,
    recover_one_event,
)

from src.recovery_journal import (
    DEFAULT_JOURNAL,
    RecoveryJournalIntegrityError,
    append_recovery_event,
)


# =========================================================
# FIXTURE - SYNTHETIC EVENT AND JOURNAL
# =========================================================

@pytest.fixture
def event_and_journal(tmp_path, monkeypatch):

    monkeypatch.setenv(
        "SYNTHSHIELD_AUDIT_HMAC_KEY",
        "ab" * 32,
    )

    event = {
        "event_id": str(uuid4()),
        "timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "agent_id": "isolated-recovery-test",
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

    journal = (
        tmp_path / "isolated_recovery.jsonl"
    )

    append_recovery_event(
        event,
        journal_file=journal,
    )

    return event, journal


# =========================================================
# HELPER - MOCK POSTGRESQL STORAGE
# =========================================================

def fake_database(monkeypatch, database):

    def get_event(event_id):
        return database.get(
            str(event_id)
        )

    def save_event(event):

        event_id = event["event_id"]

        if event_id in database:
            return False

        database[event_id] = {
            **event,
            "integrity_tag": sign_security_event(
                event
            ),
        }

        return True

    monkeypatch.setattr(
        "src.recovery_executor.get_security_event",
        get_event,
    )

    monkeypatch.setattr(
        "src.recovery_executor.save_security_event",
        save_event,
    )


# =========================================================
# TEST 1 - DRY RUN MUST NOT INSERT
# =========================================================

def test_preview_never_writes(
    event_and_journal,
    monkeypatch,
):

    event, journal = event_and_journal

    database = {}

    fake_database(
        monkeypatch,
        database,
    )

    result = recover_one_event(
        journal_file=journal,
        event_id=event["event_id"],
    )

    assert result["status"] == (
        "READY_TO_RECOVER"
    )

    assert result["written"] is False

    assert database == {}


# =========================================================
# TEST 2 - EXPLICIT APPROVAL REQUIRED
# =========================================================

def test_apply_requires_exact_approval(
    event_and_journal,
    monkeypatch,
):

    event, journal = event_and_journal

    fake_database(
        monkeypatch,
        {},
    )

    with pytest.raises(
        RecoveryExecutionError,
        match="not approved",
    ):

        recover_one_event(
            journal_file=journal,
            event_id=event["event_id"],
            apply=True,
        )


# =========================================================
# TEST 3 - RECOVER ONE EVENT
# =========================================================

def test_apply_recovers_exactly_one_event(
    event_and_journal,
    monkeypatch,
):

    event, journal = event_and_journal

    database = {}

    fake_database(
        monkeypatch,
        database,
    )

    result = recover_one_event(
        journal_file=journal,
        event_id=event["event_id"],
        apply=True,
        approve_event_id=event["event_id"],
    )

    assert result["status"] == "RECOVERED"

    assert result["written"] is True

    assert len(database) == 1


# =========================================================
# TEST 4 - REPEATED RECOVERY MUST BE IDEMPOTENT
# =========================================================

def test_repeat_is_idempotent(
    event_and_journal,
    monkeypatch,
):

    event, journal = event_and_journal

    database = {}

    fake_database(
        monkeypatch,
        database,
    )

    arguments = {
        "journal_file": journal,
        "event_id": event["event_id"],
        "apply": True,
        "approve_event_id": event["event_id"],
    }

    first = recover_one_event(
        **arguments
    )

    second = recover_one_event(
        **arguments
    )

    assert first["status"] == "RECOVERED"

    assert second["status"] == "MATCHED"

    assert len(database) == 1


# =========================================================
# TEST 5 - CONFLICTING DATABASE RECORD
# =========================================================

def test_conflicting_signed_record_refused(
    event_and_journal,
    monkeypatch,
):

    event, journal = event_and_journal

    conflicting = {
        **event,
        "decision": "BLOCK",
    }

    database = {
        event["event_id"]: {
            **conflicting,
            "integrity_tag": sign_security_event(
                conflicting
            ),
        }
    }

    fake_database(
        monkeypatch,
        database,
    )

    with pytest.raises(
        RecoveryExecutionError,
        match="conflicts",
    ):

        recover_one_event(
            journal_file=journal,
            event_id=event["event_id"],
        )


# =========================================================
# TEST 6 - TAMPERED DATABASE RECORD
# =========================================================

def test_tampered_db_record_refused(
    event_and_journal,
    monkeypatch,
):

    event, journal = event_and_journal

    database = {
        event["event_id"]: {
            **event,
            "decision": "BLOCK",
            "integrity_tag": sign_security_event(
                event
            ),
        }
    }

    fake_database(
        monkeypatch,
        database,
    )

    with pytest.raises(
        RecoveryExecutionError,
        match="HMAC",
    ):

        recover_one_event(
            journal_file=journal,
            event_id=event["event_id"],
        )


# =========================================================
# TEST 7 - DUPLICATE JOURNAL EVENT
# =========================================================

def test_duplicate_journal_ids_refused(
    event_and_journal,
    monkeypatch,
):

    event, journal = event_and_journal

    fake_database(
        monkeypatch,
        {},
    )

    append_recovery_event(
        event,
        journal_file=journal,
    )

    with pytest.raises(
        RecoveryExecutionError,
        match="Duplicate",
    ):

        recover_one_event(
            journal_file=journal,
            event_id=event["event_id"],
        )


# =========================================================
# TEST 8 - LIVE JOURNAL IS PROTECTED
# =========================================================

def test_live_journal_refused(
    event_and_journal,
):

    event, _journal = event_and_journal

    with pytest.raises(
        RecoveryExecutionError,
        match="live recovery journal",
    ):

        recover_one_event(
            journal_file=DEFAULT_JOURNAL,
            event_id=event["event_id"],
        )


# =========================================================
# TEST 9 - INVALID JOURNAL SIGNATURE
# =========================================================

def test_invalid_journal_hmac_refused(
    event_and_journal,
    monkeypatch,
):

    event, journal = event_and_journal

    fake_database(
        monkeypatch,
        {},
    )

    # Change the signing key after the
    # journal was originally created.

    monkeypatch.setenv(
        "SYNTHSHIELD_AUDIT_HMAC_KEY",
        "cd" * 32,
    )

    with pytest.raises(
        RecoveryJournalIntegrityError
    ):

        recover_one_event(
            journal_file=journal,
            event_id=event["event_id"],
        )


# =========================================================
# TEST 10 - CONCURRENT INSERT RACE
# =========================================================

def test_race_with_matching_insert_is_safe(
    event_and_journal,
    monkeypatch,
):

    event, journal = event_and_journal

    database = {}

    get_calls = 0

    def fake_get(event_id):

        nonlocal get_calls

        get_calls += 1

        # First lookup returns no event.
        # Later lookup finds a matching event.

        if get_calls == 1:
            return None

        return database.get(event_id)

    def fake_save(record):

        # Simulate another writer inserting
        # the matching record first.

        database[record["event_id"]] = {
            **record,
            "integrity_tag": sign_security_event(
                record
            ),
        }

        return False

    monkeypatch.setattr(
        "src.recovery_executor.get_security_event",
        fake_get,
    )

    monkeypatch.setattr(
        "src.recovery_executor.save_security_event",
        fake_save,
    )

    result = recover_one_event(
        journal_file=journal,
        event_id=event["event_id"],
        apply=True,
        approve_event_id=event["event_id"],
    )

    assert result["status"] == (
        "MATCHED_AFTER_RACE"
    )

    assert result["written"] is False
