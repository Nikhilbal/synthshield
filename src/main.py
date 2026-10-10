
from src.purpose import (
    combine_security_decisions,
    evaluate_purpose,
    load_purpose_policy,
)

from src.engine import (
    detect_sensitive_inference,
    load_json,
)

from src.coalition import (
    analyze_all_coalitions,
    calculate_inference_synergy,
    find_minimal_sensitive_coalitions,
    run_counterfactual_removals,
)

from src.audit import write_security_event


def main():

    print("=" * 70)
    print("SYNTHSHIELD")
    print("Counterfactual Sensitive-Inference Security Engine")
    print("=" * 70)

    # ---------------------------------------------------------
    # STEP 1: LOAD COMPANY DATA
    # ---------------------------------------------------------

    sources = {
        "calendar": load_json("calendar.json"),
        "travel": load_json("travel.json"),
        "finance": load_json("finance.json"),
    }

    print("\nFULL DATA ACCESS")
    print("----------------")

    for source_name in sources:
        print(f"✓ {source_name.title()}")

    # ---------------------------------------------------------
    # STEP 2: DETECT SENSITIVE INFERENCE
    # ---------------------------------------------------------

    full_analysis = detect_sensitive_inference(sources)

    # ---------------------------------------------------------
    # STEP 3: LOAD PURPOSE POLICY
    # ---------------------------------------------------------

    purpose_policy = load_purpose_policy()

    requested_task = (
        "Analyze executive activity "
        "and determine whether the company "
        "may be acquiring AlphaCorp."
    )

    proposed_output = (
        full_analysis["derived_information"] or ""
    )

    # ---------------------------------------------------------
    # STEP 4: EVALUATE PURPOSE LOCK
    # ---------------------------------------------------------

    purpose_analysis = evaluate_purpose(
        policy=purpose_policy,
        requested_task=requested_task,
        accessed_sources=list(sources.keys()),
        proposed_output=proposed_output,
    )

    # ---------------------------------------------------------
    # STEP 5: COMBINE SECURITY DECISIONS
    # ---------------------------------------------------------

    final_security_result = combine_security_decisions(
        full_analysis,
        purpose_analysis,
    )

    # ---------------------------------------------------------
    # STEP 6: WRITE SECURITY AUDIT EVENT
    # ---------------------------------------------------------

    audit_event = write_security_event(
        agent_id=purpose_policy["agent_id"],
        source_names=list(sources.keys()),
        inference_analysis=full_analysis,
        purpose_analysis=purpose_analysis,
        final_security_result=final_security_result,
    )

    # ---------------------------------------------------------
    # STEP 7: FULL COALITION ANALYSIS
    # ---------------------------------------------------------

    print("\nFULL COALITION ANALYSIS")
    print("-----------------------")

    print(
        f"Risk Score          : "
        f"{full_analysis['risk_score']}/100"
    )

    print(
        f"Risk Level          : "
        f"{full_analysis['risk_level']}"
    )

    print(
        f"Sensitive Inference : "
        f"{full_analysis['sensitive_inference']}"
    )

    if full_analysis["derived_information"]:
        print(
            f"Derived Information : "
            f"\"{full_analysis['derived_information']}\""
        )

    print(
        f"Decision            : "
        f"{full_analysis['decision']}"
    )

    # ---------------------------------------------------------
    # STEP 8: TEST ALL DATA COALITIONS
    # ---------------------------------------------------------

    coalition_results = analyze_all_coalitions(sources)

    print("\nALL COALITION TESTS")
    print("-------------------")

    for result in coalition_results:

        coalition_name = " + ".join(result["sources"])

        sensitive = (
            "YES"
            if result["sensitive_inference"]
            else "NO"
        )

        print(
            f"{coalition_name:<30} "
            f"Risk={result['risk_score']:<3} "
            f"Sensitive={sensitive:<3} "
            f"Decision={result['decision']}"
        )

    # ---------------------------------------------------------
    # STEP 9: FIND MINIMAL SENSITIVE COALITIONS
    # ---------------------------------------------------------

    minimal_coalitions = find_minimal_sensitive_coalitions(
        coalition_results
    )

    print("\nMINIMAL SENSITIVE COALITION")
    print("---------------------------")

    if minimal_coalitions:

        for coalition in minimal_coalitions:
            coalition_name = " + ".join(
                coalition["sources"]
            )

            print(
                f"Required sources: {coalition_name}"
            )
    else:
        print("No sensitive coalition detected.")

    # ---------------------------------------------------------
    # STEP 10: COUNTERFACTUAL REMOVAL TESTS
    # ---------------------------------------------------------

    counterfactual_results = run_counterfactual_removals(
        sources
    )

    print("\nCOUNTERFACTUAL REMOVAL TESTS")
    print("----------------------------")

    for result in counterfactual_results:

        sensitive_after = (
            "YES"
            if result["sensitive_after_removal"]
            else "NO"
        )

        print(
            f"Remove {result['removed_source']:<10} "
            f"| Risk "
            f"{result['risk_before']} → "
            f"{result['risk_after']} "
            f"| Reduction "
            f"{result['risk_reduction']} "
            f"| Sensitive after removal: "
            f"{sensitive_after}"
        )

    # ---------------------------------------------------------
    # STEP 11: INFERENCE SYNERGY
    # ---------------------------------------------------------

    synergy = calculate_inference_synergy(
        coalition_results,
        total_sources=len(sources),
    )

    print("\nINFERENCE SYNERGY")
    print("-----------------")

    print(
        f"Full coalition risk       : "
        f"{synergy['full_risk']}"
    )

    print(
        f"Strongest partial risk    : "
        f"{synergy['strongest_partial_risk']}"
    )

    print(
        f"Prototype synergy score   : "
        f"{synergy['synergy_score']}/100"
    )

    # ---------------------------------------------------------
    # STEP 12: PURPOSE LOCK ANALYSIS
    # ---------------------------------------------------------

    print("\nPURPOSE LOCK ANALYSIS")
    print("---------------------")

    print(
        f"Agent                : "
        f"{purpose_analysis['agent_name']}"
    )

    print(
        f"Approved Purpose     : "
        f"{purpose_analysis['approved_purpose']}"
    )

    print(
        f"Requested Task       : "
        f"{purpose_analysis['requested_task']}"
    )

    print(
        f"Purpose Match        : "
        f"{purpose_analysis['task_matches_purpose']}"
    )

    print(
        f"Unauthorized Sources : "
        f"{purpose_analysis['unauthorized_sources']}"
    )

    print(
        f"Forbidden Output     : "
        f"{purpose_analysis['forbidden_output_matches']}"
    )

    print(
        f"Purpose Drift        : "
        f"{purpose_analysis['purpose_drift']}"
    )

    print(
        f"Purpose Risk Level   : "
        f"{purpose_analysis['risk_level']}"
    )

    print(
        f"Purpose Decision     : "
        f"{purpose_analysis['decision']}"
    )

    if purpose_analysis["reasons"]:

        print("\nPurpose Violation Reasons:")

        for reason in purpose_analysis["reasons"]:
            print(f"  - {reason}")

    # ---------------------------------------------------------
    # STEP 13: FINAL SECURITY DECISION
    # ---------------------------------------------------------

    print("\nFINAL SECURITY DECISION")
    print("-----------------------")

    print(
        f"Decision   : "
        f"{final_security_result['decision']}"
    )

    print(
        f"Risk Level : "
        f"{final_security_result['risk_level']}"
    )

    print("\nSecurity Reasons:")

    for reason in final_security_result["reasons"]:
        print(f"  - {reason}")

    # ---------------------------------------------------------
    # STEP 14: DISPLAY AUDIT EVENT
    # ---------------------------------------------------------

    print("\nSECURITY AUDIT EVENT")
    print("--------------------")

    print(
        f"Event ID     : {audit_event['event_id']}"
    )

    print(
        f"Timestamp    : {audit_event['timestamp_utc']}"
    )

    print(
        f"Agent ID     : {audit_event['agent_id']}"
    )

    print(
        f"Sources      : {audit_event['source_names']}"
    )

    print(
        f"Purpose Drift: {audit_event['purpose_drift']}"
    )

    print(
        f"Risk Level   : {audit_event['risk_level']}"
    )

    print(
        f"Decision     : {audit_event['decision']}"
    )

    print(
        "Audit Log    : audit_logs/security_events.jsonl"
    )

    # ---------------------------------------------------------
    # STEP 15: FINAL SUMMARY
    # ---------------------------------------------------------

    print("\nSYNTHSHIELD SECURITY SUMMARY")
    print("----------------------------")

    print(
        f"Data Sources Analyzed : {len(sources)}"
    )

    print(
        f"Coalitions Tested     : {len(coalition_results)}"
    )

    sensitive_count = sum(
        1
        for result in coalition_results
        if result["sensitive_inference"]
    )

    print(
        f"Sensitive Coalitions  : {sensitive_count}"
    )

    print(
        f"Inference Risk        : "
        f"{full_analysis['risk_level']}"
    )

    print(
        f"Purpose Drift         : "
        f"{purpose_analysis['purpose_drift']}"
    )

    print(
        f"Final Decision        : "
        f"{final_security_result['decision']}"
    )

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
