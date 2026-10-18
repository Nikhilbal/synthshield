
"""
SYNTHSHIELD - Isolated Agent Security Lab

Tests that an untrusted container:
1. Has no PostgreSQL credentials.
2. Has no trusted gateway source code.
3. Cannot open a direct PostgreSQL connection.
4. Cannot execute tools without authorization.
"""

import os
import socket
import json

from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError


URL = os.environ["SYNTHSHIELD_TOOL_URL"]


def attempt_tool(credential=None):
    headers = {
        "Content-Type": "application/json",
    }

    if credential is not None:
        headers["Authorization"] = (
            f"Bearer {credential}"
        )

    request = Request(
        URL,
        data=json.dumps({
            "source": "finance",
        }).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    try:
        with urlopen(request, timeout=5) as response:
            return response.status

    except HTTPError as exc:
        return exc.code


print("=" * 55)
print("SYNTHSHIELD - CONTAINER ISOLATION LAB")
print("=" * 55)

# No database password or HMAC key should be
# present inside the agent's environment.
assert "POSTGRES_PASSWORD" not in os.environ
assert "SYNTHSHIELD_AUDIT_HMAC_KEY" not in os.environ

print("[PASS] Agent has no database or HMAC secrets")

# No privileged SYNTHSHIELD source code should
# have been copied into this container.
assert not Path(
    "/app/src/authorized_agent_gateway.py"
).exists()

print("[PASS] Trusted gateway code is absent")

# Try connecting directly to PostgreSQL.
try:
    with socket.create_connection(
        ("postgres", 5432),
        timeout=3,
    ):
        raise AssertionError(
            "Agent reached PostgreSQL directly!"
        )

except OSError:
    print("[PASS] Direct PostgreSQL connection denied")

# Attempt an unauthenticated tool request.
assert attempt_tool() == 401
print("[PASS] Missing credential rejected")

# Attempt a made-up credential.
assert attempt_tool(
    "unissued-isolation-lab-credential"
) == 403

print("[PASS] Unknown credential rejected")

print("=" * 55)
print("CONTAINER ISOLATION LAB SUCCESSFUL")
print("=" * 55)
