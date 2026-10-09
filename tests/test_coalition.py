from src.coalition import (
    analyze_all_coalitions,
    calculate_inference_synergy,
    find_minimal_sensitive_coalitions,
    run_counterfactual_removals,
)

from src.engine import load_json


def get_all_sources():

    return {
        "calendar": load_json("calendar.json"),
        "travel": load_json("travel.json"),
        "finance": load_json("finance.json"),
    }


def test_three_sources_create_seven_coalitions():

    sources = get_all_sources()

    results = analyze_all_coalitions(sources)

    assert len(results) == 7


def test_only_one_coalition_is_sensitive():

    sources = get_all_sources()

    results = analyze_all_coalitions(sources)

    sensitive_results = [
        result
        for result in results
        if result["sensitive_inference"]
    ]

    assert len(sensitive_results) == 1

    assert set(
        sensitive_results[0]["sources"]
    ) == {
        "calendar",
        "travel",
        "finance",
    }


def test_minimal_sensitive_coalition():

    sources = get_all_sources()

    results = analyze_all_coalitions(sources)

    minimal = find_minimal_sensitive_coalitions(
        results
    )

    assert len(minimal) == 1

    assert set(
        minimal[0]["sources"]
    ) == {
        "calendar",
        "travel",
        "finance",
    }


def test_removing_any_source_breaks_sensitive_inference():

    sources = get_all_sources()

    results = run_counterfactual_removals(
        sources
    )

    assert len(results) == 3

    for result in results:

        assert (
            result["sensitive_after_removal"]
            is False
        )

        assert (
            result["decision_after_removal"]
            == "ALLOW"
        )

        assert result["risk_before"] == 95
        assert result["risk_after"] == 45
        assert result["risk_reduction"] == 50


def test_synergy_score():

    sources = get_all_sources()

    coalition_results = analyze_all_coalitions(
        sources
    )

    synergy = calculate_inference_synergy(
        coalition_results,
        total_sources=3,
    )

    assert synergy["full_risk"] == 95

    assert (
        synergy["strongest_partial_risk"]
        == 45
    )

    assert synergy["synergy_score"] == 50