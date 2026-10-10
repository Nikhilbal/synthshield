
import json

from src.audit import write_security_event


def get_sample_results():

    inference_analysis = {
        "sensitive_inference": True,
        "derived_information": (
            "Company may be acquiring AlphaCorp."
        ),
    }

    purpose_analysis = {
        "purpose_drift": True,
    }

    final_security_result = {
        "decision": "BLOCK",
        "risk_level": "CRITICAL",
    }

    return (
        inference_analysis,
        purpose_analysis,
        final_security_result,
    )


def test_audit_file_is_created(tmp_path):

    inference, purpose, final = get_sample_results()

    log_file = tmp_path / "security_events.jsonl"

    event = write_security_event(
        agent_id="finance-agent-001",
        source_names=["calendar", "travel", "finance"],
        inference_analysis=inference,
        purpose_analysis=purpose,
        final_security_result=final,
        log_file=log_file,
    )

    assert log_file.exists()
    assert event["decision"] == "BLOCK"
    assert event["risk_level"] == "CRITICAL"
    assert event["source_count"] == 3
    assert event["event_id"]
    assert event["timestamp_utc"]


def test_audit_log_does_not_store_inferred_secret(tmp_path):

    inference, purpose, final = get_sample_results()

    log_file = tmp_path / "security_events.jsonl"

    write_security_event(
        agent_id="finance-agent-001",
        source_names=["calendar", "travel", "finance"],
        inference_analysis=inference,
        purpose_analysis=purpose,
        final_security_result=final,
        log_file=log_file,
    )

    contents = log_file.read_text(encoding="utf-8")

    assert "Company may be acquiring AlphaCorp" not in contents

    saved_event = json.loads(contents)

    assert saved_event["sensitive_inference"] is True
    assert saved_event["purpose_drift"] is True


def test_multiple_events_are_recorded(tmp_path):

    inference, purpose, final = get_sample_results()

    log_file = tmp_path / "security_events.jsonl"

    first_event = write_security_event(
        agent_id="finance-agent-001",
        source_names=["calendar", "travel", "finance"],
        inference_analysis=inference,
        purpose_analysis=purpose,
        final_security_result=final,
        log_file=log_file,
    )

    second_event = write_security_event(
        agent_id="finance-agent-001",
        source_names=["calendar", "travel", "finance"],
        inference_analysis=inference,
        purpose_analysis=purpose,
        final_security_result=final,
        log_file=log_file,
    )

    lines = log_file.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(lines) == 2

    assert (
        first_event["event_id"]
        != second_event["event_id"]
    )
