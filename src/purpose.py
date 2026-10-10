import json
from pathlib import Path
from typing import Any


# ---------------------------------------------------------
# SYNTHSHIELD
# Purpose Lock and Purpose-Drift Detection Engine
# ---------------------------------------------------------


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"


def load_purpose_policy(
    filename: str = "purpose_policy.json",
) -> dict[str, Any]:
    """
    Load an AI agent's approved purpose policy.
    """

    file_path = DATA_DIR / filename

    with file_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def normalize_text(text: str) -> str:
    """
    Convert text to a simple normalized form
    for our prototype rule-based comparison.
    """

    return text.lower().strip()


def evaluate_purpose(
    policy: dict[str, Any],
    requested_task: str,
    accessed_sources: list[str],
    proposed_output: str = "",
) -> dict[str, Any]:
    """
    Determine whether an AI agent is still operating
    inside its approved purpose.
    """

    task_text = normalize_text(requested_task)
    output_text = normalize_text(proposed_output)

    purpose_keywords = [
        normalize_text(keyword)
        for keyword in policy["purpose_keywords"]
    ]

    allowed_sources = {
        normalize_text(source)
        for source in policy["allowed_sources"]
    }

    forbidden_keywords = [
        normalize_text(keyword)
        for keyword in policy[
            "forbidden_inference_keywords"
        ]
    ]

    task_matches_purpose = any(
        keyword in task_text
        for keyword in purpose_keywords
    )

    unauthorized_sources = [
        source
        for source in accessed_sources
        if normalize_text(source)
        not in allowed_sources
    ]

    forbidden_output_matches = [
        keyword
        for keyword in forbidden_keywords
        if keyword in output_text
    ]

    purpose_drift = (
        not task_matches_purpose
        or bool(unauthorized_sources)
        or bool(forbidden_output_matches)
    )

    reasons = []

    if not task_matches_purpose:
        reasons.append(
            "Requested task does not match "
            "the approved purpose."
        )

    if unauthorized_sources:
        reasons.append(
            "Agent accessed sources outside "
            "the approved purpose scope: "
            + ", ".join(unauthorized_sources)
        )

    if forbidden_output_matches:
        reasons.append(
            "Proposed output contains information "
            "outside the authorized purpose: "
            + ", ".join(forbidden_output_matches)
        )

    if purpose_drift:
        decision = "BLOCK"
        risk_level = "HIGH"
    else:
        decision = "ALLOW"
        risk_level = "LOW"

    return {
        "agent_id": policy["agent_id"],
        "agent_name": policy["agent_name"],
        "approved_purpose": policy[
            "approved_purpose"
        ],
        "requested_task": requested_task,
        "task_matches_purpose": (
            task_matches_purpose
        ),
        "unauthorized_sources": (
            unauthorized_sources
        ),
        "forbidden_output_matches": (
            forbidden_output_matches
        ),
        "purpose_drift": purpose_drift,
        "risk_level": risk_level,
        "decision": decision,
        "reasons": reasons,
    }


def combine_security_decisions(
    inference_analysis: dict[str, Any],
    purpose_analysis: dict[str, Any],
) -> dict[str, Any]:
    """
    Combine aggregation-inference security
    and purpose-security into one final decision.
    """

    block_reasons = []

    if (
        inference_analysis["decision"]
        == "BLOCK"
    ):
        block_reasons.append(
            "Sensitive aggregation inference detected."
        )

    if (
        purpose_analysis["decision"]
        == "BLOCK"
    ):
        block_reasons.append(
            "Purpose drift detected."
        )

    if block_reasons:

        return {
            "decision": "BLOCK",
            "risk_level": "CRITICAL",
            "reasons": block_reasons,
        }

    return {
        "decision": "ALLOW",
        "risk_level": "LOW",
        "reasons": [
            "No sensitive inference or "
            "purpose violation detected."
        ],
    }