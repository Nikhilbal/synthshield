"""
SYNTHSHIELD
Stage 8.4.3 C3A - Recovery Planning Tests

Tests use temporary journals and mocked database lookups.
No real PostgreSQL records or recovery logs are modified.
"""

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from src.integrity import sign_security_event
from src.recovery import RecoveryPlanningError, build_recovery_plan
from src.recovery_journal import append_recovery_event


TEST_KEY = bytes.fromhex("ab" * 32)


@pytest.fixture
def event():
    return {
        "event_id": str(uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "agent_id": "recovery-test-agent",
        "source_names": ["finance", "travel"],
        "source_count": 2,
        "sensitive_inference": False,
        "purpose_drift": False,
        "risk_level": "LOW",
        "decision": "ALLOW",
    }


def create_journal(tmp_path, event):
    path = tmp_path / "recovery.jsonl"

    append_recovery_event(
        event,
        journal_file=path,
        key=TEST_KEY,
    )

    return path


def signed_db_event(event):
    stored = event.copy()

    stored["integrity_tag"] = sign_security_event(
        stored,
        key=TEST_KEY,
    )

    return stored


# TEST 1 - EXISTING VERIFIED EVENT

def test_existing_verified_event_is_matched(
    tmp_path,
    monkeypatch,
    event,
):
    path = create_journal(tmp_path, event)
    stored = signed_db_event(event)

    monkeypatch.setattr(
        "src.recovery.get_security_event",
        lambda event_id: stored,
    )

    plan = build_recovery_plan(
        journal_file=path,
        key=TEST_KEY,
    )

    assert len(plan) == 1
    assert plan[0]["status"] == "MATCHED"


# TEST 2 - EVENT MISSING FROM DATABASE

def test_missing_event_is_identified(
    tmp_path,
    monkeypatch,
    event,
):
    path = create_journal(tmp_path, event)

    monkeypatch.setattr(
        "src.recovery.get_security_event",
        lambda event_id: None,
    )

    plan = build_recovery_plan(
        journal_file=path,
        key=TEST_KEY,
    )

    assert len(plan) == 1
    assert plan[0]["status"] == "MISSING_IN_DB"


# TEST 3 - CONFLICTING VALID DATABASE EVENT

def test_conflicting_verified_event_is_detected(
    tmp_path,
    monkeypatch,
    event,
):
    path = create_journal(tmp_path, event)

    stored = event.copy()
    stored["decision"] = "BLOCK"
    stored = signed_db_event(stored)

    monkeypatch.setattr(
        "src.recovery.get_security_event",
        lambda event_id: stored,
    )

    plan = build_recovery_plan(
        journal_file=path,
        key=TEST_KEY,
    )

    assert len(plan) == 1
    assert plan[0]["status"] == "CONFLICT"


# TEST 4 - INVALID DATABASE SIGNATURE

def test_invalid_db_signature_is_detected(
    tmp_path,
    monkeypatch,
    event,
):
    path = create_journal(tmp_path, event)

    stored = signed_db_event(event)

    # Modify the event AFTER signing it.
    stored["decision"] = "BLOCK"

    monkeypatch.setattr(
        "src.recovery.get_security_event",
        lambda event_id: stored,
    )

    plan = build_recovery_plan(
        journal_file=path,
        key=TEST_KEY,
    )

    assert len(plan) == 1

    assert plan[0]["status"] == (
        "DB_INTEGRITY_FAILURE"
    )


# TEST 5 - UNSIGNED DATABASE EVENT

def test_unsigned_existing_event_is_detected(
    tmp_path,
    monkeypatch,
    event,
):
    path = create_journal(tmp_path, event)

    stored = event.copy()
    stored["integrity_tag"] = None

    monkeypatch.setattr(
        "src.recovery.get_security_event",
        lambda event_id: stored,
    )

    plan = build_recovery_plan(
        journal_file=path,
        key=TEST_KEY,
    )

    assert len(plan) == 1
    assert plan[0]["status"] == "UNSIGNED_EXISTING"


# TEST 6 - DUPLICATE JOURNAL EVENT

def test_duplicate_journal_event_is_rejected(
    tmp_path,
    event,
):
    path = create_journal(tmp_path, event)

    append_recovery_event(
        event,
        journal_file=path,
        key=TEST_KEY,
    )

    with pytest.raises(RecoveryPlanningError):
        build_recovery_plan(
            journal_file=path,
            key=TEST_KEY,
        )
