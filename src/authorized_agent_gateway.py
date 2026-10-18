
"""
SYNTHSHIELD - Phase 10.3A

Credential-verified coalition gateway.

Prototype assumptions:
- Only a trusted coordinator provisions agents.
- All protected tools use this gateway.
- Agents cannot directly access PostgreSQL.
- A coalition scope groups related workflows.

Do not expose provisioning functions to
untrusted agents or public API routes.
"""

import hashlib
import secrets
from uuid import UUID, uuid4

from src.database import get_database_connection

from src.agent_gateway import (
    AccessDenied,
    PolicyUnavailable,
    evaluate_with_synthshield,
    validate_agent_request,
    validate_security_decision,
)


def credential_digest(token):
    if not isinstance(token, str) or not token:
        raise AccessDenied("Missing agent credential.")

    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------
# TRUSTED COORDINATOR OPERATIONS
# ---------------------------------------------------------

def create_coalition_scope(task):
    """
    Coordinator-only operation.

    Create a common information-sharing scope
    that may contain several agent workflows.
    """

    if not isinstance(task, str) or not task.strip():
        raise ValueError("Invalid approved task.")

    scope_id = uuid4()

    with get_database_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO coalition_scopes (
                    scope_id,
                    requested_task
                )
                VALUES (%s, %s)
                """,
                (scope_id, task),
            )

    return str(scope_id)


def provision_workflow_agent(
    scope_id,
    agent_id,
    allowed_sources,
):
    """
    Coordinator-only operation.

    Bind one agent to one workflow and scope.

    Returns an opaque credential and workflow ID.
    Never log or print the credential.
    """

    scope_uuid = UUID(str(scope_id))

    if not isinstance(agent_id, str) or not agent_id.strip():
        raise ValueError("Invalid agent ID.")

    if (
        not isinstance(allowed_sources, list)
        or not allowed_sources
        or any(
            source not in {"calendar", "travel", "finance"}
            for source in allowed_sources
        )
        or len(allowed_sources) != len(set(allowed_sources))
    ):
        raise ValueError("Invalid source permissions.")

    token = secrets.token_urlsafe(32)
    workflow_id = uuid4()

    with get_database_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO authorized_agent_workflows (
                    workflow_id,
                    scope_id,
                    agent_id,
                    credential_hash,
                    allowed_sources
                )
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    workflow_id,
                    scope_uuid,
                    agent_id,
                    credential_digest(token),
                    allowed_sources,
                ),
            )

    return {
        "workflow_id": str(workflow_id),
        "credential": token,
    }


# ---------------------------------------------------------
# AUTHENTICATED DATA ACCESS
# ---------------------------------------------------------

class AuthorizedAgentGateway:
    """
    Derive the workflow and coalition scope
    from an issued credential.

    The agent cannot select a workflow ID
    through this gateway interface.
    """

    def __init__(
        self,
        *,
        credential,
        tools,
        evaluator=None,
    ):
        self._credential_hash = credential_digest(
            credential
        )

        if not isinstance(tools, dict):
            raise ValueError("Tools must be a dictionary.")

        self.tools = tools

        self.evaluator = (
            evaluator
            if evaluator is not None
            else evaluate_with_synthshield
        )

        if not callable(self.evaluator):
            raise ValueError("Evaluator must be callable.")

    def access(self, source):
        """
        Authenticate agent, check permissions,
        evaluate shared coalition, reserve access,
        and execute an approved tool.
        """

        validate_agent_request(
            "credential-verified access",
            [source],
            self.tools,
        )

        try:
            with get_database_connection() as connection:
                with connection.cursor() as cursor:

                    # Resolve membership from credential.
                    # The caller does not supply a scope ID.
                    cursor.execute(
                        """
                        SELECT
                            scope_id,
                            allowed_sources
                        FROM authorized_agent_workflows
                        WHERE credential_hash = %s
                          AND active = TRUE
                        """,
                        (self._credential_hash,),
                    )

                    membership = cursor.fetchone()

                    if membership is None:
                        raise AccessDenied(
                            "Unknown or revoked agent credential."
                        )

                    scope_id, allowed_sources = membership

                    if source not in allowed_sources:
                        raise AccessDenied(
                            "Agent lacks source permission."
                        )

                    # Serialize all agents sharing
                    # the same coalition scope.
                    cursor.execute(
                        """
                        SELECT
                            requested_task,
                            accessed_sources
                        FROM coalition_scopes
                        WHERE scope_id = %s
                        FOR UPDATE
                        """,
                        (scope_id,),
                    )

                    row = cursor.fetchone()

                    if row is None:
                        raise PolicyUnavailable(
                            "Coalition scope unavailable."
                        )

                    task, existing_sources = row

                    proposed_sources = list(
                        existing_sources
                    )

                    if source not in proposed_sources:
                        proposed_sources.append(source)

                    try:
                        decision = self.evaluator(
                            task,
                            proposed_sources,
                        )
                    except (
                        AccessDenied,
                        PolicyUnavailable,
                    ):
                        raise
                    except Exception as exc:
                        raise PolicyUnavailable(
                            "Coalition policy evaluation failed."
                        ) from exc

                    validate_security_decision(
                        decision,
                        proposed_sources,
                    )

                    # Reserve before releasing the
                    # lock and executing the tool.
                    if source not in existing_sources:
                        cursor.execute(
                            """
                            UPDATE coalition_scopes
                            SET accessed_sources = %s
                            WHERE scope_id = %s
                            """,
                            (
                                proposed_sources,
                                scope_id,
                            ),
                        )

        except (AccessDenied, PolicyUnavailable):
            raise

        except Exception as exc:
            raise PolicyUnavailable(
                "Authorization storage unavailable."
            ) from exc

        # Outside the database exception handler.
        # Failed tools preserve their reservation.
        return self.tools[source]()


def get_coalition_sources(scope_id):
    """
    Local inspection helper, not a public endpoint.
    """

    scope_uuid = UUID(str(scope_id))

    with get_database_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT accessed_sources
                FROM coalition_scopes
                WHERE scope_id = %s
                """,
                (scope_uuid,),
            )
            row = cursor.fetchone()

    return None if row is None else tuple(row[0])
