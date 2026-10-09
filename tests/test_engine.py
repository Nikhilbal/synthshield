from src.engine import (
    detect_sensitive_inference,
    load_json,
)


def get_all_sources():
    """
    Load all three synthetic company data sources.
    """

    return {
        "calendar": load_json("calendar.json"),
        "travel": load_json("travel.json"),
        "finance": load_json("finance.json"),
    }


def test_calendar_alone_is_allowed():
    sources = get_all_sources()

    result = detect_sensitive_inference(
        {
            "calendar": sources["calendar"]
        }
    )

    assert result["sensitive_inference"] is False
    assert result["decision"] == "ALLOW"
    assert result["risk_score"] == 20


def test_travel_alone_is_allowed():
    sources = get_all_sources()

    result = detect_sensitive_inference(
        {
            "travel": sources["travel"]
        }
    )

    assert result["sensitive_inference"] is False
    assert result["decision"] == "ALLOW"
    assert result["risk_score"] == 20


def test_finance_alone_is_allowed():
    sources = get_all_sources()

    result = detect_sensitive_inference(
        {
            "finance": sources["finance"]
        }
    )

    assert result["sensitive_inference"] is False
    assert result["decision"] == "ALLOW"
    assert result["risk_score"] == 20


def test_two_sources_do_not_create_sensitive_inference():
    sources = get_all_sources()

    result = detect_sensitive_inference(
        {
            "calendar": sources["calendar"],
            "finance": sources["finance"],
        }
    )

    assert result["sensitive_inference"] is False
    assert result["decision"] == "ALLOW"
    assert result["risk_score"] == 45


def test_full_coalition_is_blocked():
    sources = get_all_sources()

    result = detect_sensitive_inference(sources)

    assert result["sensitive_inference"] is True

    assert (
        result["derived_information"]
        == "Company may be acquiring AlphaCorp."
    )

    assert result["risk_score"] == 95
    assert result["risk_level"] == "CRITICAL"
    assert result["decision"] == "BLOCK"