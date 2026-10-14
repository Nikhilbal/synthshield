
import os
from pathlib import Path

import psycopg
from dotenv import load_dotenv


# Find the SYNTHSHIELD project root.
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def get_database_connection():
    """
    Create a PostgreSQL connection using
    credentials from the local .env file.
    """

    load_dotenv(PROJECT_ROOT / ".env")

    connection = psycopg.connect(
        host="127.0.0.1",
        port=5433,
        dbname=os.environ["POSTGRES_DB"],
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        connect_timeout=5,
    )

    return connection


def check_database_connection():
    """
    Verify that Python can connect to PostgreSQL.
    """

    with get_database_connection() as connection:

        with connection.cursor() as cursor:

            cursor.execute(
                "SELECT current_database(), current_user;"
            )

            result = cursor.fetchone()

            return result
