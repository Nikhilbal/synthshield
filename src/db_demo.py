
from src.engine import (
    detect_sensitive_inference,
    load_json,
)

from src.purpose import (
    combine_security_decisions,
    evaluate_purpose,
    load_purpose_policy,
)

from src.audit import write_security_event

from src.event_store import (
    save_security_event,
    get_security_event,
)


def main():

    print("=" * 65)
    print("SYNTHSHIELD")
    print("PostgreSQL Security Event Demonstration")
    print("=" * 65)

    # 1. Load synthetic data sources.

    sources = {
        "calendar": load_json("calendar.json"),
        "travel": load_json("travel.json"),
        "finance": load_json("finance.json"),
    }

    # 2. Evaluate sensitive inference.

    inference_result = detect_sensitive_inference(
        sources
    )

    # 3. Load the purpose policy.

    policy = load_purpose_policy()

    # 4. Evaluate purpose drift.

    purpose_result = evaluate_purpose(
        policy=policy,
        requested_task=(
            "Analyze whether the company "
            "may be acquiring AlphaCorp."
        ),
        accessed_sources=list(sources.keys()),
        proposed_output=(
            inference_result["derived_information"]
            or ""
        ),
    )

    # 5. Combine both security decisions.

    final_result = combine_security_decisions(
        inference_result,
        purpose_result,
    )

    # 6. Write the existing JSONL audit log.

    audit_event = write_security_event(
        agent_id=policy["agent_id"],
        source_names=list(sources.keys()),
        inference_analysis=inference_result,
        purpose_analysis=purpose_result,
        final_security_result=final_result,
    )

    # 7. Save the same event in PostgreSQL.

    inserted = save_security_event(
        audit_event
    )

    print("\nDATABASE INSERT")
    print("---------------")
    print(f"Inserted : {inserted}")
    print(f"Event ID : {audit_event['event_id']}")

    # 8. Retrieve that same event from PostgreSQL.

    stored_event = get_security_event(
        audit_event["event_id"]
    )

    if stored_event is None:
        raise RuntimeError(
            "Security event was not found in PostgreSQL."
        )

    print("\nDATABASE RETRIEVAL")
    print("------------------")

    print(f"Event ID      : {stored_event['event_id']}")
    print(f"Agent ID      : {stored_event['agent_id']}")
    print(f"Sources       : {stored_event['source_names']}")
    print(f"Inference     : {stored_event['sensitive_inference']}")
    print(f"Purpose Drift : {stored_event['purpose_drift']}")
    print(f"Risk Level    : {stored_event['risk_level']}")
    print(f"Decision      : {stored_event['decision']}")

    print("\nPOSTGRESQL VERIFICATION SUCCESSFUL")
    print("=" * 65)


if __name__ == "__main__":
    main()
