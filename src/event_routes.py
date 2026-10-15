
"""
SYNTHSHIELD
Stage 8.4.2 B3

Authenticated security event retrieval
with HMAC-SHA256 integrity verification.
"""

import logging

from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)

from pydantic import BaseModel

from src.auth import require_read_api_key
from src.event_store import get_security_event

from src.integrity import (
    AuditIntegrityConfigurationError,
    verify_security_event,
)


logger = logging.getLogger(__name__)


# =========================================================
# PROTECTED EVENT ROUTER
# =========================================================

router = APIRouter(
    prefix="/v1/events",
    tags=["Security Audit Events"],
    dependencies=[
        Depends(require_read_api_key),
    ],
)


# =========================================================
# VERIFIED EVENT RESPONSE MODEL
# =========================================================

class SecurityEventResponse(BaseModel):

    event_id: UUID
    timestamp_utc: datetime
    agent_id: str
    source_names: list[str]
    source_count: int
    sensitive_inference: bool
    purpose_drift: bool
    risk_level: str
    decision: str
    recorded_at: datetime

    integrity_status: Literal["VERIFIED"]


# =========================================================
# RETRIEVE AND VERIFY ONE SECURITY EVENT
# =========================================================

@router.get(
    "/{event_id}",
    response_model=SecurityEventResponse,
)
def read_security_event(event_id: UUID):

    """
    Retrieve a security event after authentication.

    Only cryptographically verified events
    are returned as successful responses.
    """

    # -----------------------------------------------------
    # STEP 1: RETRIEVE EVENT FROM POSTGRESQL
    # -----------------------------------------------------

    event = get_security_event(
        str(event_id)
    )

    # -----------------------------------------------------
    # STEP 2: HANDLE UNKNOWN EVENT
    # -----------------------------------------------------

    if event is None:

        raise HTTPException(
            status_code=404,
            detail="Security event not found.",
        )

    # -----------------------------------------------------
    # STEP 3: CHECK FOR LEGACY UNSIGNED EVENT
    # -----------------------------------------------------

    integrity_tag = event.get(
        "integrity_tag"
    )

    if integrity_tag is None:

        logger.warning(
            "Unsigned legacy security event requested: %s",
            event_id,
        )

        raise HTTPException(
            status_code=409,
            detail="UNSIGNED_LEGACY",
        )

    # -----------------------------------------------------
    # STEP 4: VERIFY HMAC-SHA256
    # -----------------------------------------------------

    try:

        is_verified = verify_security_event(
            event,
            integrity_tag,
        )

    except AuditIntegrityConfigurationError:

        logger.exception(
            "Audit integrity configuration unavailable."
        )

        raise HTTPException(
            status_code=503,
            detail=(
                "Audit integrity verification unavailable."
            ),
        ) from None

    except (KeyError, ValueError, TypeError):

        logger.exception(
            "Malformed security event metadata: %s",
            event_id,
        )

        raise HTTPException(
            status_code=409,
            detail="INTEGRITY_FAILURE",
        ) from None

    # -----------------------------------------------------
    # STEP 5: REJECT FAILED INTEGRITY CHECK
    # -----------------------------------------------------

    if not is_verified:

        logger.error(
            "Security event integrity verification failed: %s",
            event_id,
        )

        raise HTTPException(
            status_code=409,
            detail="INTEGRITY_FAILURE",
        )

    # -----------------------------------------------------
    # STEP 6: RETURN VERIFIED SECURITY EVENT
    # -----------------------------------------------------

    return SecurityEventResponse(
        event_id=event["event_id"],
        timestamp_utc=event["timestamp_utc"],
        agent_id=event["agent_id"],
        source_names=event["source_names"],
        source_count=event["source_count"],
        sensitive_inference=event[
            "sensitive_inference"
        ],
        purpose_drift=event["purpose_drift"],
        risk_level=event["risk_level"],
        decision=event["decision"],
        recorded_at=event["recorded_at"],
        integrity_status="VERIFIED",
    )
