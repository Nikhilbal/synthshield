import json
from pathlib import Path
from typing import Any


# ---------------------------------------------------------
# SYNTHSHIELD
# Core Sensitive Aggregation Inference Engine
# ---------------------------------------------------------


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"


def load_json(filename: str) -> dict[str, Any]:
    """
    Load one synthetic company data source from JSON.
    """

    file_path = DATA_DIR / filename

    with file_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def convert_to_searchable_text(record: dict[str, Any]) -> str:
    """
    Convert structured JSON data into lowercase searchable text.

    This is only our Stage 2 detector.
    Later an AI/NLP classifier will replace this primitive approach.
    """

    return json.dumps(record).lower().replace("-", " ")


def detect_sensitive_inference(
    sources: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """
    Analyze any combination of data sources.

    The function checks which security signals exist and determines
    whether their combination produces sensitive derived knowledge.
    """

    calendar_text = convert_to_searchable_text(
        sources.get("calendar", {})
    )

    travel_text = convert_to_searchable_text(
        sources.get("travel", {})
    )

    finance_text = convert_to_searchable_text(
        sources.get("finance", {})
    )

    signals = {
        "strategic_meeting": (
            "cfo" in calendar_text
            and "alphacorp" in calendar_text
            and "meeting" in calendar_text
        ),

        "executive_travel": (
            "cfo" in travel_text
            and "london" in travel_text
        ),

        "due_diligence": (
            "due diligence" in finance_text
        ),
    }

    triggered_signals = sum(signals.values())

    risk_scores = {
        0: 0,
        1: 20,
        2: 45,
        3: 95,
    }

    risk_score = risk_scores[triggered_signals]

    if risk_score >= 90:
        risk_level = "CRITICAL"
    elif risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 30:
        risk_level = "MEDIUM"
    elif risk_score > 0:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"

    sensitive_inference = triggered_signals == 3

    if sensitive_inference:

        derived_information = (
            "Company may be acquiring AlphaCorp."
        )

        decision = "BLOCK"

        reason = (
            "Sensitive strategic information was created "
            "by combining multiple individually allowed sources."
        )

        confidence = 95

    else:

        derived_information = None
        decision = "ALLOW"

        reason = (
            "The available combination does not create "
            "the protected strategic inference."
        )

        confidence = 0

    return {
        "sensitive_inference": sensitive_inference,
        "derived_information": derived_information,
        "confidence": confidence,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "decision": decision,
        "reason": reason,
        "signals": signals,
        "triggered_signals": triggered_signals,
    }