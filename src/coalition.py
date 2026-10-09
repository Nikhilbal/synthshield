from itertools import combinations
from typing import Any

from src.engine import detect_sensitive_inference


# ---------------------------------------------------------
# SYNTHSHIELD
# Counterfactual Coalition Analysis Engine
# ---------------------------------------------------------


def analyze_all_coalitions(
    sources: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    Test every possible non-empty combination of data sources.
    """

    source_names = tuple(sources.keys())

    coalition_results = []

    for coalition_size in range(1, len(source_names) + 1):

        for coalition_names in combinations(
            source_names,
            coalition_size,
        ):

            coalition_data = {
                name: sources[name]
                for name in coalition_names
            }

            analysis = detect_sensitive_inference(
                coalition_data
            )

            coalition_results.append(
                {
                    "sources": coalition_names,
                    "risk_score": analysis["risk_score"],
                    "risk_level": analysis["risk_level"],
                    "sensitive_inference": (
                        analysis["sensitive_inference"]
                    ),
                    "decision": analysis["decision"],
                }
            )

    return coalition_results


def find_minimal_sensitive_coalitions(
    coalition_results: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    Find the smallest source combinations that still create
    a sensitive inference.
    """

    minimal_coalitions = []

    for candidate in coalition_results:

        if not candidate["sensitive_inference"]:
            continue

        candidate_sources = set(candidate["sources"])

        has_sensitive_proper_subset = any(
            other["sensitive_inference"]
            and set(other["sources"]) < candidate_sources
            for other in coalition_results
        )

        if not has_sensitive_proper_subset:
            minimal_coalitions.append(candidate)

    return minimal_coalitions


def run_counterfactual_removals(
    sources: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    Remove one source at a time and see how the security result changes.
    """

    full_analysis = detect_sensitive_inference(sources)

    counterfactual_results = []

    for source_to_remove in sources:

        reduced_sources = {
            name: data
            for name, data in sources.items()
            if name != source_to_remove
        }

        reduced_analysis = detect_sensitive_inference(
            reduced_sources
        )

        contribution = (
            full_analysis["risk_score"]
            - reduced_analysis["risk_score"]
        )

        counterfactual_results.append(
            {
                "removed_source": source_to_remove,
                "risk_before": full_analysis["risk_score"],
                "risk_after": reduced_analysis["risk_score"],
                "risk_reduction": contribution,
                "sensitive_after_removal": (
                    reduced_analysis["sensitive_inference"]
                ),
                "decision_after_removal": (
                    reduced_analysis["decision"]
                ),
            }
        )

    return counterfactual_results


def calculate_inference_synergy(
    coalition_results: list[dict[str, Any]],
    total_sources: int,
) -> dict[str, int]:
    """
    Estimate how much extra risk appears only when the
    complete coalition is assembled.

    Prototype formula:

    Full coalition risk
        -
    strongest proper-subset risk
        =
    inference synergy
    """

    full_coalitions = [
        result
        for result in coalition_results
        if len(result["sources"]) == total_sources
    ]

    if not full_coalitions:
        return {
            "full_risk": 0,
            "strongest_partial_risk": 0,
            "synergy_score": 0,
        }

    full_risk = max(
        result["risk_score"]
        for result in full_coalitions
    )

    proper_subset_risks = [
        result["risk_score"]
        for result in coalition_results
        if len(result["sources"]) < total_sources
    ]

    strongest_partial_risk = max(
        proper_subset_risks,
        default=0,
    )

    synergy_score = max(
        0,
        full_risk - strongest_partial_risk,
    )

    return {
        "full_risk": full_risk,
        "strongest_partial_risk": strongest_partial_risk,
        "synergy_score": synergy_score,
    }