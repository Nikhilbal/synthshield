
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

from src.event_routes import router as event_router


# =========================================================
# SYNTHSHIELD
# Stage 8.2 - FastAPI, PostgreSQL and Authentication
# =========================================================

logger = logging.getLogger(__name__)


# =========================================================
# STEP 1 - INITIALIZE FASTAPI APPLICATION
# =========================================================

app = FastAPI(
    title="SYNTHSHIELD API",
    description=(
        "Sensitive Aggregation Inference Protection "
        "with Purpose Lock, PostgreSQL Audit Logging "
        "and Authenticated Security Event Retrieval"
    ),
    version="0.3.0",
)


# =========================================================
# STEP 2 - REGISTER AUTHENTICATED EVENT ROUTES
# =========================================================

# Registers the protected security-event retrieval routes
# defined in src/event_routes.py.
#
# Example:
# GET /v1/events/{event_id}
#
# Event retrieval requires a valid read API key.

app.include_router(event_router)


# =========================================================
# STEP 3 - DEFINE SUPPORTED DATA SOURCES
# =========================================================

SourceName = Literal[
    "calendar",
    "travel",
    "finance",
]


# =========================================================
# STEP 4 - API REQUEST MODEL
# =========================================================

class EvaluationRequest(BaseModel):
    """
    Define and validate incoming AI evaluation requests.
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
        """
        Reject duplicate data sources.
        """

        if len(self.sources) != len(set(self.sources)):
            raise ValueError(
                "Each source must appear only once."
            )

        return self


# =========================================================
# STEP 5 - API RESPONSE MODEL
# =========================================================

class EvaluationResponse(BaseModel):
    """
    Define the security evaluation response.
    """

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

@app.get(
    "/health",
    tags=["System Health"],
)
def health_check():
    """
    Check whether the SYNTHSHIELD API is running.
    """

    return {
        "service": "SYNTHSHIELD",
        "status": "running",
        "version": "0.3.0",
    }


# =========================================================
# ENDPOINT 2 - AI SECURITY EVALUATION
# =========================================================

@app.post(
    "/v1/evaluate",
    response_model=EvaluationResponse,
    tags=["Security Evaluation"],
)
def evaluate_agent_action(
    request: EvaluationRequest,
):
    """
    Evaluate an AI agent's requested task.

    The system checks:
    1. Sensitive aggregation inference
    2. Purpose policy violations
    3. Combined security decision
    4. JSONL audit logging
    5. PostgreSQL audit persistence

    The endpoint returns a policy decision.
    It does not independently enforce that decision.
    """

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
    # STEP 2: DETECT SENSITIVE AGGREGATION INFERENCE
    # -----------------------------------------------------

    inference_result = detect_sensitive_inference(
        sources
    )

    # -----------------------------------------------------
    # STEP 3: LOAD APPROVED PURPOSE POLICY
    # -----------------------------------------------------

    purpose_policy = load_purpose_policy()

    # -----------------------------------------------------
    # STEP 4: DETECT PURPOSE DRIFT
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
    # STEP 6: WRITE JSONL SECURITY AUDIT EVENT
    # -----------------------------------------------------

    audit_event = write_security_event(
        agent_id=purpose_policy["agent_id"],
        source_names=request.sources,
        inference_analysis=inference_result,
        purpose_analysis=purpose_result,
        final_security_result=final_result,
    )

    # -----------------------------------------------------
    # STEP 7: STORE THE SAME EVENT IN POSTGRESQL
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

        # Fail closed at the API-response level:
        # do not return ALLOW when required
        # audit persistence fails.

        raise HTTPException(
            status_code=503,
            detail=(
                "Security audit database is unavailable."
            ),
        ) from None

    # -----------------------------------------------------
    # STEP 8: RETURN FINAL SECURITY DECISION
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


# =========================================================
# END OF SYNTHSHIELD API
# =========================================================
