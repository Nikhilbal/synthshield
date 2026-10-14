
from datetime import datetime
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)

from pydantic import BaseModel

from src.auth import require_read_api_key
from src.event_store import get_security_event


router = APIRouter(
    prefix="/v1/events",
    tags=["Security Audit Events"],
    dependencies=[
        Depends(require_read_api_key),
    ],
)


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


@router.get(
    "/{event_id}",
    response_model=SecurityEventResponse,
)
def read_security_event(event_id: UUID):
    """
    Retrieve one security event after authentication.
    """

    event = get_security_event(
        str(event_id)
    )

    if event is None:
        raise HTTPException(
            status_code=404,
            detail="Security event not found.",
        )

    return event
