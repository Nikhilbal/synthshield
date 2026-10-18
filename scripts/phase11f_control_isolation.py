"""SYNTHSHIELD Phase 11F: isolate coalition inference from Purpose Lock.

Run from ~/Projects/synthshield:
    python -m scripts.phase11f_control_isolation

This test reads synthetic data and the existing purpose policy. The permissive
policy is an IN-MEMORY COPY; no production policy, files, DB, or API are changed.
"""

from copy import deepcopy

from src.engine import detect_sensitive_inference, load_json
from src.purpose import (
    combine_security_decisions,
    evaluate_purpose,
    load_purpose_policy,
)

TASK = "Prepare the monthly company expense report"


def check_case(label, *, names, data, policy, expected_inference, expected_purpose):
    selected = {name: data[name] for name in names}
    inference = detect_sensitive_inference(selected)
    purpose = evaluate_purpose(
        policy=policy,
        requested_task=TASK,
        accessed_sources=list(names),
        proposed_output=inference["derived_information"] or "",
    )
    final = combine_security_decisions(inference, purpose)

    assert inference["decision"] == expected_inference, (
        f"{label}: inference expected {expected_inference}, "
        f"got {inference['decision']}"
    )
    assert purpose["decision"] == expected_purpose, (
        f"{label}: purpose expected {expected_purpose}, "
        f"got {purpose['decision']}"
    )
    expected_final = (
        "BLOCK" if "BLOCK" in (expected_inference, expected_purpose) else "ALLOW"
    )
    assert final["decision"] == expected_final, (
        f"{label}: final expected {expected_final}, got {final['decision']}"
    )

    print(f"\n{label}")
    print("  Sources:             ", ", ".join(names))
    print("  Triggered signals:   ", inference["triggered_signals"])
    print("  Inference risk:      ", f"{inference['risk_score']}/100 ({inference['risk_level']})")
    print("  Inference decision:  ", inference["decision"])
    print("  Purpose decision:    ", purpose["decision"])
    print("  Final decision:      ", final["decision"])
    print("  Reasons:             ", "; ".join(final["reasons"]))
    print("  [PASS] Isolated decisions match expected outcome")
    return inference, purpose, final


def main():
    print("=" * 64)
    print("SYNTHSHIELD - PHASE 11F INDEPENDENT SECURITY CONTROLS")
    print("=" * 64)

    data = {
        "calendar": load_json("calendar.json"),
        "travel": load_json("travel.json"),
        "finance": load_json("finance.json"),
    }
    original_policy = load_purpose_policy()
    permissive_test_policy = deepcopy(original_policy)
    permissive_test_policy["allowed_sources"] = ["calendar", "travel", "finance"]
    permissive_test_policy["forbidden_inference_keywords"] = []

    # This confirms the test policy was copied instead of modifying the original.
    assert "calendar" not in original_policy["allowed_sources"]
    assert original_policy["forbidden_inference_keywords"]

    cases = (
        (
            "CASE 1: Inference ALLOW / Purpose ALLOW",
            ("finance", "travel"),
            original_policy,
            "ALLOW",
            "ALLOW",
        ),
        (
            "CASE 2: Inference ALLOW / Purpose BLOCK",
            ("calendar",),
            original_policy,
            "ALLOW",
            "BLOCK",
        ),
        (
            "CASE 3: Inference BLOCK / Purpose ALLOW (in-memory test policy)",
            ("calendar", "travel", "finance"),
            permissive_test_policy,
            "BLOCK",
            "ALLOW",
        ),
        (
            "CASE 4: Inference BLOCK / Purpose BLOCK",
            ("calendar", "travel", "finance"),
            original_policy,
            "BLOCK",
            "BLOCK",
        ),
    )

    for label, names, policy, inference_expected, purpose_expected in cases:
        inference, _purpose, _final = check_case(
            label,
            names=names,
            data=data,
            policy=policy,
            expected_inference=inference_expected,
            expected_purpose=purpose_expected,
        )
        if len(names) == 3:
            assert inference["risk_score"] == 95
            assert inference["sensitive_inference"] is True
        else:
            assert inference["sensitive_inference"] is False

    # Verify the in-memory copy did not mutate the project's default policy.
    assert load_purpose_policy() == original_policy
    print("\n" + "=" * 64)
    print("[PASS] All four security-control combinations verified")
    print("[PASS] Coalition detector blocks even when Purpose Lock allows")
    print("[PASS] Purpose Lock blocks even when coalition detector allows")
    print("[PASS] Original purpose policy unchanged")
    print("PHASE 11F SECURITY CONTROL ISOLATION COMPLETE")
    print("=" * 64)


if __name__ == "__main__":
    main()
