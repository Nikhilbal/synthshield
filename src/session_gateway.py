
"""
SYNTHSHIELD - Phase 9C
Session-Based Coalition Protection

Tracks data sources accessed within one agent session.

Before accessing a new source, evaluates the union of:
- Previously accessed sources
- The newly requested source

This is a local, in-memory research prototype.
"""

from threading import RLock

from src.agent_gateway import (
    evaluate_with_synthshield,
    validate_agent_request,
    validate_security_decision,
)


class GuardedAgentSession:
    """
    Enforce SYNTHSHIELD policy across sequential
    tool calls within a single session instance.
    """

    def __init__(
        self,
        *,
        task,
        tools,
        evaluator=None,
    ):
        if not isinstance(task, str) or not task.strip():
            raise ValueError(
                "Session task must be non-empty."
            )

        if not isinstance(tools, dict):
            raise ValueError(
                "Tools must be a dictionary."
            )

        self.task = task
        self.tools = tools
        self.evaluator = (
            evaluator
            if evaluator is not None
            else evaluate_with_synthshield
        )

        if not callable(self.evaluator):
            raise ValueError(
                "Evaluator must be callable."
            )

        self._accessed_sources = []
        self._lock = RLock()

    @property
    def accessed_sources(self):
        """
        Return a read-only snapshot of accessed
        source names.
        """
        with self._lock:
            return tuple(self._accessed_sources)

    def access(self, source):
        """
        Evaluate accumulated source access before
        executing the requested tool.

        A denied request never executes its tool
        or changes the recorded source history.
        """

        # Validate the source and registered tool.
        validate_agent_request(
            self.task,
            [source],
            self.tools,
        )

        with self._lock:

            # Preserve first-access order.
            proposed_sources = list(
                self._accessed_sources
            )

            if source not in proposed_sources:
                proposed_sources.append(source)

            # Evaluate the complete coalition,
            # not only the newest source.
            from src.agent_gateway import (
                AccessDenied,
                PolicyUnavailable,
            )

            try:
                result = self.evaluator(
                    self.task,
                    proposed_sources,
                )

            except (AccessDenied, PolicyUnavailable):
                raise

            except Exception as exc:
                raise PolicyUnavailable(
                    "Session policy evaluation failed."
                ) from exc

            # Must be ALLOW with matching sources,
            # LOW risk, no sensitive inference,
            # and no purpose drift.
            validate_security_decision(
                result,
                proposed_sources,
            )

            # No tool executes before approval.
            value = self.tools[source]()

            # Only record successfully accessed sources.
            if source not in self._accessed_sources:
                self._accessed_sources.append(source)

            return value
