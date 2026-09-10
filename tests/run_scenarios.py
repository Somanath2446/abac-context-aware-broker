"""
tests/run_scenarios.py

Day 8-9: fires every scenario in scenarios.json at the *running* broker and
records actual vs expected outcome. This is the results table directly —
no separate results generator needed, per the plan.

Usage:
    1. Start the broker in another terminal:
         python -m uvicorn broker.main:app --reload --port 8000
    2. Run this script:
         python tests/run_scenarios.py

Prints a pass/fail line per scenario plus a summary count, and writes
tests/scenario_results.json with the full detail for the report.
"""

import json
import sys
from pathlib import Path

import requests

BROKER_URL = "http://localhost:8000"
SCENARIOS_PATH = Path(__file__).resolve().parent / "scenarios.json"
RESULTS_PATH = Path(__file__).resolve().parent / "scenario_results.json"


def outcome_matches(expected: str, allowed: bool) -> bool:
    """
    expected is either the literal string "allow" / "deny", or (for the
    deliberately-tricky false-positive cases) a longer note that starts
    with "deny (...)" or similar. We only match on the first word.
    """
    expected_word = expected.split()[0].strip("()").lower()
    actual_word = "allow" if allowed else "deny"
    return expected_word == actual_word


def run_single_request(request_attrs: dict) -> dict:
    resp = requests.post(f"{BROKER_URL}/request-access", json=request_attrs, timeout=5)
    return resp.json()


def run_scenario(scenario: dict) -> dict:
    if "steps" in scenario:
        # Multi-step scenario (currently: the revocation case, A4)
        token_id = None
        last_result = None
        for step in scenario["steps"]:
            if step["action"].startswith("POST /request-access"):
                req = dict(step["request"]) if "request" in step else {}
                if token_id:
                    req["token_id"] = token_id
                result = run_single_request(req)
                token_id = result.get("token_id", token_id)
                last_result = result
            elif step["action"].startswith("POST /revoke"):
                requests.post(f"{BROKER_URL}/revoke/{token_id}", timeout=5)
        allowed = last_result.get("allowed", False)
        actual_reason = last_result.get("reason", "")
    else:
        result = run_single_request(scenario["request"])
        allowed = result.get("allowed", False)
        actual_reason = result.get("reason", "")

    passed = outcome_matches(scenario["expected_outcome"], allowed)
    return {
        "id": scenario["id"],
        "name": scenario["name"],
        "category": scenario["category"],
        "expected_outcome": scenario["expected_outcome"],
        "actual_outcome": "allow" if allowed else "deny",
        "actual_reason": actual_reason,
        "passed": passed,
    }


def main():
    with open(SCENARIOS_PATH) as f:
        scenarios = json.load(f)

    try:
        requests.get(f"{BROKER_URL}/health", timeout=3)
    except requests.exceptions.ConnectionError:
        print(f"ERROR: could not reach broker at {BROKER_URL}.")
        print("Start it first: python -m uvicorn broker.main:app --reload --port 8000")
        sys.exit(1)

    results = []
    for scenario in scenarios:
        result = run_scenario(scenario)
        results.append(result)
        status = "PASS" if result["passed"] else "FAIL"
        print(f"[{status}] {result['id']} {result['name']:40s} "
              f"expected={result['expected_outcome']!r:20} actual={result['actual_outcome']}")

    passed_count = sum(r["passed"] for r in results)
    print(f"\n{passed_count}/{len(results)} scenarios matched expected outcome.")

    with open(RESULTS_PATH, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Full results written to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
