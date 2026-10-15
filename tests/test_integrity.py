
"""
SYNTHSHIELD
Stage 8.4.2 - HMAC Audit Integrity Tests
"""

from copy import deepcopy
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from src.integrity import (
    AuditIntegrityConfigurationError,
    sign_security_event,
    verify_security_event,
)


# Fixed test key.
# This is NOT a real application secret.
TEST_KEY = bytes.fromhex("ab" * 32)


@pytest.fixture
def security_event():

    return {
        "event_id": str(uuid4()),
        "timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "agent_id": "finance-agent-001",
        "source_names": [
            "calendar",
            "travel",
            "finance",
        ],
        "source_count": 3,
        "sensitive_inference": True,
        "purpose_drift": True,
        "risk_level": "CRITICAL",
        "decision": "BLOCK",
    }


# ---------------------------------------------------------
# TEST 1 - VALID EVENT PASSES VERIFICATION
# ---------------------------------------------------------

def test_valid_security_event_passes(
    security_event,
):

    signature = sign_security_event(
        security_event,
        key=TEST_KEY,
    )

    assert len(signature) == 64

    assert verify_security_event(
        security_event,
        signature,
        key=TEST_KEY,
    ) is True


# ---------------------------------------------------------
# TEST 2 - CHANGING DECISION DETECTS TAMPERING
# ---------------------------------------------------------

def test_modified_decision_is_detected(
    security_event,
):

    signature = sign_security_event(
        security_event,
        key=TEST_KEY,
    )

    tampered_event = deepcopy(security_event)

    tampered_event["decision"] = "ALLOW"

    assert verify_security_event(
        tampered_event,
        signature,
        key=TEST_KEY,
    ) is False


# ---------------------------------------------------------
# TEST 3 - CHANGING RISK LEVEL DETECTS TAMPERING
# ---------------------------------------------------------

def test_modified_risk_level_is_detected(
    security_event,
):

    signature = sign_security_event(
        security_event,
        key=TEST_KEY,
    )

    tampered_event = deepcopy(security_event)

    tampered_event["risk_level"] = "LOW"

    assert verify_security_event(
        tampered_event,
        signature,
        key=TEST_KEY,
    ) is False


# ---------------------------------------------------------
# TEST 4 - CHANGING SOURCES DETECTS TAMPERING
# ---------------------------------------------------------

def test_modified_sources_are_detected(
    security_event,
):

    signature = sign_security_event(
        security_event,
        key=TEST_KEY,
    )

    tampered_event = deepcopy(security_event)

    tampered_event["source_names"] = [
        "finance",
        "travel",
    ]

    tampered_event["source_count"] = 2

    assert verify_security_event(
        tampered_event,
        signature,
        key=TEST_KEY,
    ) is False


# ---------------------------------------------------------
# TEST 5 - POSTGRESQL DATETIME IS SUPPORTED
# ---------------------------------------------------------

def test_postgresql_timestamp_is_supported(
    security_event,
):

    signature = sign_security_event(
        security_event,
        key=TEST_KEY,
    )

    retrieved_event = deepcopy(security_event)

    retrieved_event["timestamp_utc"] = (
        datetime.fromisoformat(
            security_event["timestamp_utc"]
        )
    )

    assert verify_security_event(
        retrieved_event,
        signature,
        key=TEST_KEY,
    ) is True


# ---------------------------------------------------------
# TEST 6 - WRONG SIGNING KEY IS REJECTED
# ---------------------------------------------------------

def test_wrong_signing_key_fails(
    security_event,
):

    signature = sign_security_event(
        security_event,
        key=TEST_KEY,
    )

    different_key = bytes.fromhex("cd" * 32)

    assert verify_security_event(
        security_event,
        signature,
        key=different_key,
    ) is False


# ---------------------------------------------------------
# TEST 7 - INVALID KEY LENGTH IS REJECTED
# ---------------------------------------------------------

def test_invalid_signing_key_is_rejected(
    security_event,
):

    with pytest.raises(
        AuditIntegrityConfigurationError
    ):

        sign_security_event(
            security_event,
            key=b"short-key",
        )
