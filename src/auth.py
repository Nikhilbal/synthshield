
import hmac
import os

from pathlib import Path

from dotenv import load_dotenv

from fastapi import Depends, HTTPException
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent

bearer_scheme = HTTPBearer(
    auto_error=False,
)


def require_read_api_key(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
):
    """
    Require a valid API key before reading
    SYNTHSHIELD security event records.
    """

    load_dotenv(PROJECT_ROOT / ".env")

    expected_key = os.getenv(
        "SYNTHSHIELD_READ_API_KEY"
    )

    # Reject access if the server is not configured.
    if not expected_key or len(expected_key) < 32:
        raise HTTPException(
            status_code=503,
            detail="Security API authentication is not configured.",
        )

    # Reject missing or incorrect authentication.
    if (
        credentials is None
        or not hmac.compare_digest(
            credentials.credentials,
            expected_key,
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )
