
"""
SYNTHSHIELD
Stage 8.4.2 - Cryptographic Audit Integrity

Create and verify HMAC-SHA256 authentication
tags for security-event metadata.
"""

import hashlib
import hmac
import json
import os

from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class AuditIntegrityConfigurationError(Exception):
    """Audit signing key is missing or invalid."""


def load_integrity_key() -> bytes:
    """
    Load the HMAC signing key from the environment.

    The key must be exactly 32 bytes (256 bits),
    encoded as 64 hexadecimal characters.
    """

    load_dotenv(PROJECT_ROOT / ".env")

    key_hex = os.getenv("SYNTHSHIELD_AUDIT_HMAC_KEY")

    if not key_hex:
        raise AuditIntegrityConfigurationError(
            "Audit integrity key is not configured."
        )

    try:
        key = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise AuditIntegrityConfigurationError(
            "Audit integrity key must be hexadecimal."
        ) from exc

    if len(key) != 32:
        raise AuditIntegrityConfigurationError(
            "Audit integrity key must be 32 bytes."
        )

    return key


def normalize_timestamp(value) -> str:
    """
    Convert a timestamp to a consistent UTC format.

    Supports both ISO timestamp strings and
    datetime objects returned by PostgreSQL.
    """

    if isinstance(value, str):
        value = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

    if not isinstance(value, datetime):
        raise ValueError(
            "Invalid audit event timestamp."
        )

    if value.tzinfo is None:
        raise ValueError(
            "Audit timestamp must include a timezone."
        )

    return value.astimezone(
        timezone.utc
    ).isoformat(timespec="microseconds")


def canonical_event_payload(event: dict) -> bytes:
    """
    Create a deterministic representation of
    the protected security-event fields.

    Identical records produce identical bytes
    even when timestamps are represented as
    PostgreSQL datetime objects.
    """

    protected_data = {
        "event_id": str(
            UUID(str(event["event_id"]))
        ),
        "timestamp_utc": normalize_timestamp(
            event["timestamp_utc"]
        ),
        "agent_id": event["agent_id"],
        "source_names": event["source_names"],
        "source_count": event["source_count"],
        "sensitive_inference": event[
            "sensitive_inference"
        ],
        "purpose_drift": event["purpose_drift"],
        "risk_level": event["risk_level"],
        "decision": event["decision"],
    }

    canonical_json = json.dumps(
        protected_data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )

    return canonical_json.encode("utf-8")


def sign_security_event(
    event: dict,
    key: bytes | None = None,
) -> str:
    """
    Generate an HMAC-SHA256 integrity tag.

    Return a 64-character hexadecimal digest.
    """

    if key is None:
        key = load_integrity_key()

    if not isinstance(key, bytes) or len(key) != 32:
        raise AuditIntegrityConfigurationError(
            "Audit signing key must be 32 bytes."
        )

    payload = canonical_event_payload(event)

    signature = hmac.new(
        key,
        payload,
        hashlib.sha256,
    )

    return signature.hexdigest()


def verify_security_event(
    event: dict,
    integrity_tag: str | None,
    key: bytes | None = None,
) -> bool:
    """
    Verify that protected event fields have
    not changed since they were signed.
    """

    if not isinstance(integrity_tag, str):
        return False

    if len(integrity_tag) != 64:
        return False

    expected_tag = sign_security_event(
        event,
        key=key,
    )

    return hmac.compare_digest(
        expected_tag,
        integrity_tag,
    )
