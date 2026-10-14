
import logging
from typing import Literal

from fastapi import FastAPI, HTTPException
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
from src.event_store import save_security_event


# =========================================================
# SYNTHSHIELD
# Stage 7.9 - FastAPI and PostgreSQL Integration
# =========================================================

logger = logging.getLogger(__name__)


app = FastAPI(
    title="SYNTHSHIELD API",
    description=(
        "Sensitive Aggregation Inference Protection "
        "with Purpose Lock and PostgreSQL Audit Logging"
    ),
    version="0.2.0",
)


# =========================================================
# REQUEST VALIDATION
# =========================================================

SourceName = Literal[
    "calendar",
    "travel",
    "finance",
]


class EvaluationRequest(BaseModel):

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


# =========================================================
# RESPONSE MODEL
# =========================================================

class EvaluationResponse(BaseModel):

    event_id: str
    agent_id: str
    sources: list[str]
    sensitive_inference: bool
    purpose_drift: bool
    risk_level: str
    decision: str
    reasons: list[str]


# =========================================================
# ENDPOINT 1 - HEALTH CHECK
# =========================================================

@app.get("/health")
def health_check():

    return {
        "service": "SYNTHSHIELD",
        "status": "running",
        "version": "0.2.0",
    }


# =========================================================
# ENDPOINT 2 - SECURITY EVALUATION
# =========================================================

@app.post(
    "/v1/evaluate",
    response_model=EvaluationResponse,
)
def evaluate_agent_action(
    request: EvaluationRequest,
):

    # -----------------------------------------------------
    # STEP 1: LOAD REQUESTED DATA SOURCES
    # -----------------------------------------------------

    sources = {
        source_name: load_json(
            f"{source_name}.json"
        )
        for source_name in request.sources
    }

    # -----------------------------------------------------
    # STEP 2: DETECT SENSITIVE INFERENCE
    # -----------------------------------------------------

    inference_result = detect_sensitive_inference(
        sources
    )

    # -----------------------------------------------------
    # STEP 3: LOAD THE APPROVED PURPOSE POLICY
    # -----------------------------------------------------

    purpose_policy = load_purpose_policy()

    # -----------------------------------------------------
    # STEP 4: EVALUATE PURPOSE DRIFT
    # -----------------------------------------------------

    purpose_result = evaluate_purpose(
        policy=purpose_policy,
        requested_task=request.requested_task,
        accessed_sources=request.sources,
        proposed_output=(
            inference_result["derived_information"]
            or ""
        ),
    )

    # -----------------------------------------------------
    # STEP 5: COMBINE SECURITY DECISIONS
    # -----------------------------------------------------

    final_result = combine_security_decisions(
        inference_result,
        purpose_result,
    )

    # -----------------------------------------------------
    # STEP 6: WRITE JSONL AUDIT EVENT
    # -----------------------------------------------------

    audit_event = write_security_event(
        agent_id=purpose_policy["agent_id"],
        source_names=request.sources,
        inference_analysis=inference_result,
        purpose_analysis=purpose_result,
        final_security_result=final_result,
    )

    # -----------------------------------------------------
    # STEP 7: SAVE THE EVENT TO POSTGRESQL
    # -----------------------------------------------------

    try:

        inserted = save_security_event(
            audit_event
        )

        if not inserted:
            raise RuntimeError(
                "Security audit event already exists."
            )

    except Exception:

        logger.exception(
            "PostgreSQL audit persistence failed."
        )

        # Do not return ALLOW if required
        # database audit storage fails.

        raise HTTPException(
            status_code=503,
            detail=(
                "Security audit database is unavailable."
            ),
        ) from None

    # -----------------------------------------------------
    # STEP 8: RETURN SECURITY DECISION
    # -----------------------------------------------------

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
