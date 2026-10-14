
from datetime import datetime
from typing import Any
from uuid import UUID

from psycopg.rows import dict_row

from src.database import get_database_connection


# ---------------------------------------------------------
# SYNTHSHIELD
# PostgreSQL Security Event Storage
# ---------------------------------------------------------


def save_security_event(
    event: dict[str, Any],
) -> bool:
    """
    Save one existing SYNTHSHIELD audit event
    to PostgreSQL.

    Returns True if a new row was inserted.
    Returns False if the event already exists.
    """

    sql = """
        INSERT INTO security_events (
            event_id,
            timestamp_utc,
            agent_id,
            source_names,
            source_count,
            sensitive_inference,
            purpose_drift,
            risk_level,
            decision
        )
        VALUES (
            %s, %s, %s, %s, %s,
            %s, %s, %s, %s
        )
        ON CONFLICT (event_id) DO NOTHING
    """

    values = (
        UUID(event["event_id"]),
        datetime.fromisoformat(event["timestamp_utc"]),
        event["agent_id"],
        event["source_names"],
        event["source_count"],
        event["sensitive_inference"],
        event["purpose_drift"],
        event["risk_level"],
        event["decision"],
    )

    with get_database_connection() as connection:

        with connection.cursor() as cursor:

            cursor.execute(sql, values)

            inserted = cursor.rowcount == 1

    return inserted


def get_security_event(
    event_id: str,
) -> dict[str, Any] | None:
    """
    Retrieve a security event by its UUID.

    Returns None if no matching event exists.
    """

    sql = """
        SELECT
            event_id,
            timestamp_utc,
            agent_id,
            source_names,
            source_count,
            sensitive_inference,
            purpose_drift,
            risk_level,
            decision,
            recorded_at
        FROM security_events
        WHERE event_id = %s
    """

    with get_database_connection() as connection:

        with connection.cursor(
            row_factory=dict_row
        ) as cursor:

            cursor.execute(
                sql,
                (UUID(event_id),),
            )

            event = cursor.fetchone()

    return event
