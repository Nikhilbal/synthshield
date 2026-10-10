
import json
import os
import uuid

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_LOG_FILE = (
    PROJECT_ROOT / "audit_logs" / "security_events.jsonl"
)


def write_security_event(
    *,
    agent_id: str,
    source_names: list[str],
    inference_analysis: dict[str, Any],
    purpose_analysis: dict[str, Any],
    final_security_result: dict[str, Any],
    log_file: Path | None = None,
) -> dict[str, Any]:
    """
    Record metadata about a SYNTHSHIELD security decision.

    Do not write raw source data or inferred secret content
    into the audit log.
    """

    if log_file is None:
        log_file = DEFAULT_LOG_FILE

    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "agent_id": agent_id,
        "source_names": list(source_names),
        "source_count": len(source_names),
        "sensitive_inference": inference_analysis[
            "sensitive_inference"
        ],
        "purpose_drift": purpose_analysis[
            "purpose_drift"
        ],
        "risk_level": final_security_result[
            "risk_level"
        ],
        "decision": final_security_result[
            "decision"
        ],
    }

    log_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    line = (
        json.dumps(event, ensure_ascii=False)
        + "\n"
    )

    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_APPEND
    )

    fd = os.open(
        log_file,
        flags,
        0o600,
    )

    try:
        with os.fdopen(fd, "a", encoding="utf-8") as file:
            file.write(line)
            file.flush()
    except Exception:
        raise

    return event
