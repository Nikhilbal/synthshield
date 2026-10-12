
from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel, Field, model_validator

from src.engine import (
    detect_sensitive_inference,
    load_json,
)

from src.purpose import (
    combine_security_decisions,
    evaluate_purpose,
    load_purpose_policy,
)

from src.audit import write_security_event


# ---------------------------------------------------------
# SYNTHSHIELD
# Stage 6 - FastAPI Security Evaluation Backend
# ---------------------------------------------------------

app = FastAPI(
    title="SYNTHSHIELD API",
    description=(
        "Prototype API for sensitive aggregation "
        "inference and purpose-policy evaluation."
    ),
    version="0.1.0",
)


# Only our three synthetic sources are supported.
SourceName = Literal["calendar", "travel", "finance"]


class EvaluationRequest(BaseModel):
    """
    Defines the JSON data clients are allowed to send.
    """

    requested_task: str = Field(
        min_length=1,
        max_length=500,
    )

    sources: list[SourceName] = Field(
        min_length=1,
        max_length=3,
    )

    @model_validator(mode="after")
    def check_unique_sources(self):
        if len(self.sources) != len(set(self.sources)):
            raise ValueError(
                "Each source must appear only once."
            )

        return self


class EvaluationResponse(BaseModel):
    """
    Defines the JSON data returned to clients.
    """

    event_id: str
    agent_id: str
    sources: list[str]
    sensitive_inference: bool
    purpose_drift: bool
    risk_level: str
    decision: str
    reasons: list[str]


@app.get("/health")
def health_check():
    """
    Simple endpoint for checking whether
    the API is responding.
    """

    return {
        "service": "SYNTHSHIELD",
        "status": "running",
        "version": "0.1.0",
    }


@app.post(
    "/v1/evaluate",
    response_model=EvaluationResponse,
)
def evaluate_agent_action(request: EvaluationRequest):
    """
    Evaluate an AI task using server-side synthetic data.

    This endpoint returns a policy decision only.
    It does not independently enforce that decision.
    """

    # Step 1: Load the selected synthetic sources.

    sources = {
        source_name: load_json(
            f"{source_name}.json"
        )
        for source_name in request.sources
    }

    # Step 2: Analyze aggregation inference.

    inference_result = detect_sensitive_inference(
        sources
    )

    # Step 3: Load the approved purpose policy.

    purpose_policy = load_purpose_policy()

    # Step 4: Analyze the requested task.

    purpose_result = evaluate_purpose(
        policy=purpose_policy,
        requested_task=request.requested_task,
        accessed_sources=request.sources,
        proposed_output=(
            inference_result["derived_information"] or ""
        ),
    )

    # Step 5: Produce the final decision.

    final_result = combine_security_decisions(
        inference_result,
        purpose_result,
    )

    # Step 6: Save audit metadata.

    audit_event = write_security_event(
        agent_id=purpose_policy["agent_id"],
        source_names=request.sources,
        inference_analysis=inference_result,
        purpose_analysis=purpose_result,
        final_security_result=final_result,
    )

    # Step 7: Return a decision without
    # exposing the raw synthetic source records
    # or the derived secret.

    return EvaluationResponse(
        event_id=audit_event["event_id"],
        agent_id=purpose_policy["agent_id"],
        sources=request.sources,
        sensitive_inference=inference_result[
            "sensitive_inference"
        ],
        purpose_drift=purpose_result[
            "purpose_drift"
        ],
        risk_level=final_result["risk_level"],
        decision=final_result["decision"],
        reasons=final_result["reasons"],
    )
