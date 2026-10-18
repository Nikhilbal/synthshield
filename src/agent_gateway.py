
"""
SYNTHSHIELD - Phase 9B
Agent Tool Access Security Gateway

This module checks SYNTHSHIELD's FastAPI security
evaluation before executing registered data tools.

Features:
1. Validate agent tasks and source requests.
2. Call the live SYNTHSHIELD security API.
3. Accept API source fields: sources or source_names.
4. Reject conflicting security responses.
5. Block unauthorized or sensitive data combinations.
6. Fail closed when the security service is unavailable.
7. Execute registered tools only after authorization.

SECURITY LIMITATION:
This is a local prototype gateway. It protects tool
calls routed through this function, but does not
prevent an agent from bypassing the gateway.
"""

import json

from urllib.request import Request, urlopen
from urllib.error import URLError


# =========================================================
# CONFIGURATION
# =========================================================

API_URL = "http://127.0.0.1:8000/v1/evaluate"

API_TIMEOUT = 5

ALLOWED_SOURCES = {
    "calendar",
    "travel",
    "finance",
}


# =========================================================
# SECURITY EXCEPTIONS
# =========================================================

class AccessDenied(Exception):
    """
    Raised when the security policy rejects access.
    """


class PolicyUnavailable(Exception):
    """
    Raised when the security service cannot provide
    a usable evaluation.
    """


# =========================================================
# STEP 1 - VALIDATE AGENT REQUEST
# =========================================================

def validate_agent_request(task, sources, tools):
    """
    Validate the requested task, data sources,
    and registered tool functions.

    Validation occurs before contacting the API.
    """

    # Task must be a non-empty string.

    if (
        not isinstance(task, str)
        or not task.strip()
    ):
        raise ValueError(
            "Task must be a non-empty string."
        )

    # Sources must be a non-empty list.

    if (
        not isinstance(sources, list)
        or not sources
    ):
        raise ValueError(
            "Sources must be a non-empty list."
        )

    # All sources must be strings.

    if not all(
        isinstance(source, str)
        for source in sources
    ):
        raise ValueError(
            "Every source must be a string."
        )

    # Duplicate sources are not permitted.

    if len(sources) != len(set(sources)):
        raise ValueError(
            "Duplicate sources are not allowed."
        )

    # Tools must be supplied as a dictionary.

    if not isinstance(tools, dict):
        raise ValueError(
            "Tools must be a dictionary."
        )

    # Every source must be known and registered.

    for source in sources:

        if source not in ALLOWED_SOURCES:
            raise ValueError(
                f"Unknown data source: {source}"
            )

        if source not in tools:
            raise ValueError(
                f"No registered tool for: {source}"
            )

        if not callable(tools[source]):
            raise ValueError(
                f"Registered tool is not callable: {source}"
            )


# =========================================================
# STEP 2 - CALL SYNTHSHIELD SECURITY API
# =========================================================

def evaluate_with_synthshield(task, sources):
    """
    Submit a proposed agent task to SYNTHSHIELD.

    Endpoint:
        POST /v1/evaluate

    Returns:
        Security evaluation dictionary.

    The API must respond successfully before
    any protected tool can execute.
    """

    payload = {
        "requested_task": task,
        "sources": sources,
    }

    encoded_payload = json.dumps(
        payload
    ).encode("utf-8")

    request = Request(
        API_URL,
        data=encoded_payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )

    try:

        with urlopen(
            request,
            timeout=API_TIMEOUT,
        ) as response:

            if response.status != 200:
                raise PolicyUnavailable(
                    "Unexpected security API response."
                )

            result = json.load(response)

    except PolicyUnavailable:
        raise

    except (
        URLError,
        TimeoutError,
        OSError,
        ValueError,
    ) as exc:

        raise PolicyUnavailable(
            "SYNTHSHIELD security evaluation "
            "is unavailable."
        ) from exc

    if not isinstance(result, dict):
        raise PolicyUnavailable(
            "Invalid security API response format."
        )

    return result


# =========================================================
# STEP 3 - VALIDATE SECURITY DECISION
# =========================================================

def validate_security_decision(result, sources):
    """
    Validate the API's security response.

    Important:
    Some API versions use "sources", while others
    use "source_names".

    Both are supported, but conflicting source
    lists are rejected.

    An HTTP 200 response alone does not authorize
    tool execution.
    """

    if not isinstance(result, dict):

        raise AccessDenied(
            "Security response must be a dictionary."
        )

    # -----------------------------------------------------
    # CHECK RETURNED SOURCE NAMES
    # -----------------------------------------------------

    api_sources = result.get("sources")

    audit_sources = result.get("source_names")

    # Reject a response that gives two different
    # source lists.

    if (
        api_sources is not None
        and audit_sources is not None
        and api_sources != audit_sources
    ):

        raise AccessDenied(
            "Conflicting source lists "
            "in security response."
        )

    # Prefer the API's sources field if available.

    if api_sources is not None:
        returned_sources = api_sources
    else:
        returned_sources = audit_sources

    # The evaluated sources must match the exact
    # original request.

    if returned_sources != sources:

        raise AccessDenied(
            "Security evaluation source mismatch."
        )

    # -----------------------------------------------------
    # CHECK DECISION
    # -----------------------------------------------------

    if result.get("decision") != "ALLOW":

        raise AccessDenied(
            "SYNTHSHIELD blocked tool access."
        )

    # -----------------------------------------------------
    # CHECK RISK CLASSIFICATION
    # -----------------------------------------------------

    if result.get("risk_level") != "LOW":

        raise AccessDenied(
            "Security risk level is not LOW."
        )

    # -----------------------------------------------------
    # CHECK SENSITIVE INFERENCE
    # -----------------------------------------------------

    if result.get("sensitive_inference") is not False:

        raise AccessDenied(
            "Sensitive inference detected "
            "or status unavailable."
        )

    # -----------------------------------------------------
    # CHECK PURPOSE DRIFT
    # -----------------------------------------------------

    if result.get("purpose_drift") is not False:

        raise AccessDenied(
            "Purpose drift detected "
            "or status unavailable."
        )

    # -----------------------------------------------------
    # CHECK AUDIT EVENT ID
    # -----------------------------------------------------

    event_id = result.get("event_id")

    if (
        not isinstance(event_id, str)
        or not event_id.strip()
    ):

        raise AccessDenied(
            "Security evaluation has no valid event ID."
        )

    # Every required security condition passed.

    return True


# =========================================================
# STEP 4 - GUARDED AGENT TOOL EXECUTION
# =========================================================

def run_guarded_task(
    task,
    sources,
    tools,
    evaluator=None,
):
    """
    Evaluate a task before executing protected tools.

    Args:
        task:
            Requested agent task.

        sources:
            List of data sources requested.

        tools:
            Dictionary mapping source names
            to callable tool functions.

        evaluator:
            Optional evaluator used for automated
            tests. Defaults to the live API.

    Returns:
        Dictionary of approved tool results.

    Security:
        No registered tool executes until
        the complete security decision is ALLOW.
    """

    # -----------------------------------------------------
    # STEP 1 - VALIDATE REQUEST
    # -----------------------------------------------------

    validate_agent_request(
        task,
        sources,
        tools,
    )

    # -----------------------------------------------------
    # STEP 2 - SELECT SECURITY EVALUATOR
    # -----------------------------------------------------

    if evaluator is None:

        evaluator = evaluate_with_synthshield

    # -----------------------------------------------------
    # STEP 3 - REQUEST SECURITY EVALUATION
    # -----------------------------------------------------

    try:

        result = evaluator(
            task,
            sources,
        )

    except (
        AccessDenied,
        PolicyUnavailable,
    ):
        raise

    except Exception as exc:

        raise PolicyUnavailable(
            "Security evaluation failed."
        ) from exc

    # -----------------------------------------------------
    # STEP 4 - ENFORCE SECURITY DECISION
    # -----------------------------------------------------

    validate_security_decision(
        result,
        sources,
    )

    # -----------------------------------------------------
    # STEP 5 - EXECUTE APPROVED TOOLS
    # -----------------------------------------------------

    retrieved = {}

    for source in sources:

        tool_function = tools[source]

        retrieved[source] = tool_function()

    # -----------------------------------------------------
    # STEP 6 - RETURN APPROVED RESULTS
    # -----------------------------------------------------

    return retrieved
