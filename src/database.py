
"""
SYNTHSHIELD
PostgreSQL Database Connection

Supports:
- Local Mac development
- Docker container networking

Database credentials remain in environment
variables and must not be hardcoded.
"""

import os
from pathlib import Path

import psycopg
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def get_database_connection():
    """
    Create a PostgreSQL connection.

    Local defaults:
        Host: 127.0.0.1
        Port: 5433

    Docker service settings:
        Host: postgres
        Port: 5432

    Environment variables:
        SYNTHSHIELD_DB_HOST
        SYNTHSHIELD_DB_PORT
        POSTGRES_DB
        POSTGRES_USER
        POSTGRES_PASSWORD
    """

    load_dotenv(PROJECT_ROOT / ".env")

    host = os.getenv(
        "SYNTHSHIELD_DB_HOST",
        "127.0.0.1",
    )

    port = int(
        os.getenv(
            "SYNTHSHIELD_DB_PORT",
            "5433",
        )
    )

    return psycopg.connect(
        host=host,
        port=port,
        dbname=os.environ["POSTGRES_DB"],
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        connect_timeout=5,
    )


def check_database_connection():
    """
    Verify PostgreSQL connectivity.

    Returns:
        (database_name, database_user)
    """

    with get_database_connection() as connection:

        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    current_database(),
                    current_user
                """
            )

            return cursor.fetchone()

def get_coordinator_connection():
    """
    Connect using the restricted coordinator role.

    Intended only for trusted, host-side
    credential provisioning and scope management.

    Never fall back to administrator credentials.
    """

    load_dotenv(PROJECT_ROOT / ".env")

    password = os.getenv(
        "SYNTHSHIELD_COORDINATOR_DB_PASSWORD"
    )

    if not password:
        raise RuntimeError(
            "Coordinator database credentials "
            "are not configured."
        )

    return psycopg.connect(
        host=os.getenv(
            "SYNTHSHIELD_DB_HOST",
            "127.0.0.1",
        ),
        port=int(
            os.getenv(
                "SYNTHSHIELD_DB_PORT",
                "5433",
            )
        ),
        dbname=os.environ["POSTGRES_DB"],
        user="synth_coordinator",
        password=password,
        connect_timeout=5,
    )
