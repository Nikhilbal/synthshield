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


def main():

    print("=" * 70)
    print("SYNTHSHIELD")
    print("Counterfactual Sensitive-Inference Security Engine")
    print("=" * 70)

    sources = {
        "calendar": load_json("calendar.json"),
        "travel": load_json("travel.json"),
        "finance": load_json("finance.json"),
    }

    print("\nFULL DATA ACCESS")
    print("----------------")

    for source_name in sources:
        print(f"✓ {source_name.title()}")

    full_analysis = detect_sensitive_inference(sources)

    print("\nFULL COALITION ANALYSIS")
    print("-----------------------")

    print(
        f'Risk Score          : '
        f'{full_analysis["risk_score"]}/100'
    )

    print(
        f'Risk Level          : '
        f'{full_analysis["risk_level"]}'
    )

    print(
        f'Sensitive Inference : '
        f'{full_analysis["sensitive_inference"]}'
    )

    if full_analysis["derived_information"]:

        print(
            f'Derived Information : '
            f'"{full_analysis["derived_information"]}"'
        )

    print(
        f'Decision            : '
        f'{full_analysis["decision"]}'
    )

    coalition_results = analyze_all_coalitions(
        sources
    )

    print("\nALL COALITION TESTS")
    print("-------------------")

    for result in coalition_results:

        coalition_name = " + ".join(
            result["sources"]
        )

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

    minimal_coalitions = (
        find_minimal_sensitive_coalitions(
            coalition_results
        )
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

        print(
            "No sensitive coalition detected."
        )

    counterfactual_results = (
        run_counterfactual_removals(
            sources
        )
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

    print("\nFINAL SECURITY DECISION")
    print("-----------------------")

    print(
        f"Decision : "
        f"{full_analysis['decision']}"
    )

    print(
        f"Reason   : "
        f"{full_analysis['reason']}"
    )

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()