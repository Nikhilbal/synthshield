from src.engine import (
    detect_sensitive_inference,
    load_json,
)

from src.purpose import (
    combine_security_decisions,
    evaluate_purpose,
    load_purpose_policy,
)


def test_legitimate_expense_task_is_allowed():

    policy = load_purpose_policy()

    result = evaluate_purpose(
        policy=policy,
        requested_task=(
            "Prepare the monthly expense report."
        ),
        accessed_sources=[
            "finance",
            "travel",
        ],
        proposed_output=(
            "Monthly travel and legal "
            "expenses summarized."
        ),
    )

    assert result["purpose_drift"] is False
    assert result["decision"] == "ALLOW"
    assert result["unauthorized_sources"] == []


def test_wrong_task_detects_purpose_drift():

    policy = load_purpose_policy()

    result = evaluate_purpose(
        policy=policy,
        requested_task=(
            "Analyze executive acquisition activity."
        ),
        accessed_sources=[
            "finance",
            "travel",
        ],
    )

    assert result["purpose_drift"] is True
    assert result["decision"] == "BLOCK"
    assert (
        result["task_matches_purpose"]
        is False
    )


def test_calendar_is_outside_expense_scope():

    policy = load_purpose_policy()

    result = evaluate_purpose(
        policy=policy,
        requested_task=(
            "Prepare the monthly expense report."
        ),
        accessed_sources=[
            "finance",
            "travel",
            "calendar",
        ],
    )

    assert result["purpose_drift"] is True

    assert "calendar" in (
        result["unauthorized_sources"]
    )

    assert result["decision"] == "BLOCK"


def test_acquisition_output_is_blocked():

    policy = load_purpose_policy()

    result = evaluate_purpose(
        policy=policy,
        requested_task=(
            "Prepare the monthly expense report."
        ),
        accessed_sources=[
            "finance",
            "travel",
        ],
        proposed_output=(
            "The company may be acquiring AlphaCorp."
        ),
    )

    assert result["purpose_drift"] is True

    assert result["decision"] == "BLOCK"

    assert len(
        result["forbidden_output_matches"]
    ) > 0


def test_combined_security_decision_blocks_both_risks():

    policy = load_purpose_policy()

    sources = {
        "calendar": load_json(
            "calendar.json"
        ),
        "travel": load_json(
            "travel.json"
        ),
        "finance": load_json(
            "finance.json"
        ),
    }

    inference_analysis = (
        detect_sensitive_inference(
            sources
        )
    )

    purpose_analysis = evaluate_purpose(
        policy=policy,
        requested_task=(
            "Analyze executive activity "
            "and possible acquisitions."
        ),
        accessed_sources=[
            "calendar",
            "travel",
            "finance",
        ],
        proposed_output=(
            "Company may be acquiring AlphaCorp."
        ),
    )

    final_result = (
        combine_security_decisions(
            inference_analysis,
            purpose_analysis,
        )
    )

    assert (
        inference_analysis["decision"]
        == "BLOCK"
    )

    assert (
        purpose_analysis["decision"]
        == "BLOCK"
    )

    assert (
        final_result["decision"]
        == "BLOCK"
    )

    assert (
        final_result["risk_level"]
        == "CRITICAL"
    )