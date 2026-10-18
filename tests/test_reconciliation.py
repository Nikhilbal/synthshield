
"""
SYNTHSHIELD
Stage 8.4.3 A - Audit Reconciliation Tests

These tests use temporary JSONL files and
mock database lookups.

They do not modify real PostgreSQL records.
"""

import json

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from src.reconciliation import (
    reconcile_audit_events,
)


# =========================================================
# TEST DATA FACTORY
# =========================================================

@pytest.fixture
def test_event():

    return {
        "event_id": str(uuid4()),
        "timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "agent_id": "reconciliation-test-agent",
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


def write_test_log(tmp_path, event):

    log_file = tmp_path / "test_audit.jsonl"

    log_file.write_text(
        json.dumps(event) + "\n",
        encoding="utf-8",
    )

    return log_file


# =========================================================
# TEST 1 - MATCHING EVENT
# =========================================================

def test_matching_event_is_detected(
    tmp_path,
    monkeypatch,
    test_event,
):

    log_file = write_test_log(
        tmp_path,
        test_event,
    )

    monkeypatch.setattr(
        "src.reconciliation.get_security_event",
        lambda event_id: test_event.copy(),
    )

    report = reconcile_audit_events(
        log_file
    )

    assert report["checked_events"] == 1
    assert report["matching_events"] == 1
    assert report["missing_event_ids"] == []
    assert report["mismatched_event_ids"] == []


# =========================================================
# TEST 2 - EVENT MISSING FROM DATABASE
# =========================================================

def test_missing_database_event_is_detected(
    tmp_path,
    monkeypatch,
    test_event,
):

    log_file = write_test_log(
        tmp_path,
        test_event,
    )

    monkeypatch.setattr(
        "src.reconciliation.get_security_event",
        lambda event_id: None,
    )

    report = reconcile_audit_events(
        log_file
    )

    assert report["matching_events"] == 0

    assert report["missing_event_ids"] == [
        test_event["event_id"]
    ]


# =========================================================
# TEST 3 - METADATA MISMATCH
# =========================================================

def test_modified_database_record_is_detected(
    tmp_path,
    monkeypatch,
    test_event,
):

    log_file = write_test_log(
        tmp_path,
        test_event,
    )

    modified_event = test_event.copy()

    modified_event["decision"] = "BLOCK"

    monkeypatch.setattr(
        "src.reconciliation.get_security_event",
        lambda event_id: modified_event,
    )

    report = reconcile_audit_events(
        log_file
    )

    assert report["matching_events"] == 0

    assert report["mismatched_event_ids"] == [
        test_event["event_id"]
    ]


# =========================================================
# TEST 4 - CORRUPTED JSONL LINE
# =========================================================

def test_invalid_jsonl_line_is_detected(
    tmp_path,
):

    log_file = tmp_path / "invalid.jsonl"

    log_file.write_text(
        '{"event_id": INVALID JSON\n',
        encoding="utf-8",
    )

    report = reconcile_audit_events(
        log_file
    )

    assert report["checked_events"] == 0

    assert report["invalid_lines"] == [1]


# =========================================================
# TEST 5 - DATABASE OUTAGE IS NOT HIDDEN
# =========================================================

def test_database_failure_is_not_treated_as_missing(
    tmp_path,
    monkeypatch,
    test_event,
):

    log_file = write_test_log(
        tmp_path,
        test_event,
    )

    def simulated_database_outage(event_id):

        raise ConnectionError(
            "Simulated PostgreSQL outage."
        )

    monkeypatch.setattr(
        "src.reconciliation.get_security_event",
        simulated_database_outage,
    )

    with pytest.raises(ConnectionError):

        reconcile_audit_events(
            log_file
        )
