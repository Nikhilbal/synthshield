import json
from pathlib import Path


# ---------------------------------------------------------
# SYNTHSHIELD - Stage 1
# Basic Sensitive Aggregation Inference Detector
# ---------------------------------------------------------


# Find the main project directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Point to our synthetic company data folder.
DATA_DIR = PROJECT_ROOT / "data"


def load_json(filename):
    """
    Load one JSON data source from the data directory.
    """

    file_path = DATA_DIR / filename

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def convert_to_searchable_text(record):
    """
    Convert a JSON dictionary into lowercase text
    so our first detector can search for signals.
    """

    return json.dumps(record).lower().replace("-", " ")


def detect_sensitive_inference(calendar_data, travel_data, finance_data):
    """
    Check whether several individually allowed data sources,
    when combined, create a sensitive business inference.
    """

    calendar_text = convert_to_searchable_text(calendar_data)
    travel_text = convert_to_searchable_text(travel_data)
    finance_text = convert_to_searchable_text(finance_data)

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

    if triggered_signals == 3:

        return {
            "sensitive_inference": True,
            "derived_information": "Company may be acquiring AlphaCorp.",
            "confidence": 95,
            "inference_synergy_score": 89,
            "risk_level": "CRITICAL",
            "decision": "BLOCK",
            "reason": (
                "Sensitive strategic information was created "
                "by combining multiple individually allowed sources."
            ),
            "signals": signals,
        }

    return {
        "sensitive_inference": False,
        "derived_information": None,
        "confidence": 0,
        "inference_synergy_score": 0,
        "risk_level": "LOW",
        "decision": "ALLOW",
        "reason": "No sensitive aggregation inference detected.",
        "signals": signals,
    }


def main():

    print("=" * 60)
    print("SYNTHSHIELD")
    print("Sensitive Aggregation Inference Protection")
    print("=" * 60)

    calendar_data = load_json("calendar.json")
    travel_data = load_json("travel.json")
    finance_data = load_json("finance.json")

    print("\nDATA SOURCES ACCESSED")
    print("---------------------")
    print("✓ Executive Calendar")
    print("✓ Corporate Travel")
    print("✓ Finance System")

    print("\nINDIVIDUAL SOURCE STATUS")
    print("------------------------")
    print("Calendar : ALLOWED")
    print("Travel   : ALLOWED")
    print("Finance  : ALLOWED")

    result = detect_sensitive_inference(
        calendar_data,
        travel_data,
        finance_data,
    )

    print("\nDERIVED KNOWLEDGE ANALYSIS")
    print("--------------------------")

    if result["sensitive_inference"]:

        print(f'Derived information : "{result["derived_information"]}"')
        print(f'Confidence          : {result["confidence"]}%')
        print(
            f'Inference Synergy   : '
            f'{result["inference_synergy_score"]}/100'
        )
        print(f'Risk Level          : {result["risk_level"]}')

        print("\nSECURITY DECISION")
        print("-----------------")
        print(f'Decision : {result["decision"]}')
        print(f'Reason   : {result["reason"]}')

    else:

        print("No sensitive derived knowledge detected.")
        print("Decision : ALLOW")

    print("\nSIGNALS")
    print("-------")

    for signal, detected in result["signals"].items():
        print(f"{signal}: {detected}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()