
"""
SYNTHSHIELD - Phase 10.3D

Trusted tool execution API.

The requesting agent supplies:
- An issued Bearer credential
- A requested data source

The agent cannot supply its own workflow,
coalition scope, or policy decision.

IMPORTANT:
This module is not a security boundary until
deployed separately from untrusted agent code.
"""

from typing import Literal

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from src.agent_gateway import (
    AccessDenied,
    PolicyUnavailable,
)

from src.authorized_agent_gateway import (
    AuthorizedAgentGateway,
)


app = FastAPI(
    title="SYNTHSHIELD Trusted Tool Service",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


# Synthetic protected data.
# Real company information is not used.

def finance_tool():
    return {
        "category": "finance",
        "monthly_expenses": 12500,
        "currency": "INR",
    }


def travel_tool():
    return {
        "category": "travel",
        "monthly_travel_cost": 3500,
        "currency": "INR",
    }


def calendar_tool():
    return {
        "category": "calendar",
        "meeting_count": 4,
    }


PROTECTED_TOOLS = {
    "finance": finance_tool,
    "travel": travel_tool,
    "calendar": calendar_tool,
}


class ToolRequest(BaseModel):
    source: Literal[
        "finance",
        "travel",
        "calendar",
    ]


def extract_bearer_token(authorization):
    """
    Reject missing or malformed credentials.

    Never log or include credential values
    in error messages.
    """

    if not isinstance(authorization, str):
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
        )

    parts = authorization.split()

    if (
        len(parts) != 2
        or parts[0].lower() != "bearer"
        or not parts[1]
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization format.",
        )

    return parts[1]


@app.post("/v1/agent-tools/execute")
def execute_protected_tool(
    request: ToolRequest,
    authorization: str | None = Header(default=None),
):
    """
    Execute one registered source tool after
    credential and coalition verification.
    """

    credential = extract_bearer_token(
        authorization
    )

    gateway = AuthorizedAgentGateway(
        credential=credential,
        tools={
            request.source: PROTECTED_TOOLS[
                request.source
            ]
        },
    )

    try:
        result = gateway.access(
            request.source
        )

    except AccessDenied:
        raise HTTPException(
            status_code=403,
            detail="Tool access denied.",
        ) from None

    except PolicyUnavailable:
        raise HTTPException(
            status_code=503,
            detail="Security service unavailable.",
        ) from None

    except Exception:
        # Do not expose database details or
        # tool errors to an untrusted caller.
        raise HTTPException(
            status_code=503,
            detail="Protected tool unavailable.",
        ) from None

    return {
        "source": request.source,
        "result": result,
    }
