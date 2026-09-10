"""
policy_engine/evaluate.py

Person B — Policy Engine core.

Day 1: rule schema (see rules.json) — a rule is:
    {
      "rule_id": "...",
      "resource": "scan_images/*",          # glob pattern matched against attributes["object_id"]
      "allow_if": {
        "role": "radiologist",
        "source_network": "hospital-vpn",
        "time_range": ["09:00", "18:00"]    # HH:MM, inclusive; supports overnight wraparound
      }
    }

Day 2: evaluate(attributes, rules) -> (bool, str). Plain conditional matching,
no cleverness. Fully standalone — no FastAPI, no boto3/AWS import here, so it
can be built and tested before the broker exists.

Day 4-5: time-range matching handles overnight ranges (e.g. 22:00-06:00).
"Virtual clock" is not a separate module: evaluate() never calls
datetime.now() itself. It only ever reads attributes["timestamp"], which the
broker either forwards from the client or stamps with server time. Tests and
demos inject whatever timestamp they want by putting it straight into
`attributes` — that's the whole virtual clock.

attributes dict shape (matches broker/main.py's AccessRequest exactly):
    {
        "object_id": str,
        "requester_id": str,
        "role": str,
        "source_network": str,
        "device_id": str,
        "timestamp": str,   # ISO 8601, e.g. "2025-06-01T14:30:00+00:00"
    }
"""

import fnmatch
from datetime import datetime, time
from typing import Tuple


def _parse_time_of_day(iso_timestamp: str) -> time:
    """Extract the HH:MM:SS wall-clock time from an ISO 8601 timestamp string."""
    dt = datetime.fromisoformat(iso_timestamp)
    return dt.time()


def _in_time_range(current: time, start_str: str, end_str: str) -> bool:
    """
    Inclusive time-of-day range check, handling overnight wraparound.

    Normal range (start <= end), e.g. 09:00-18:00:
        allowed if start <= current <= end

    Overnight range (start > end), e.g. 22:00-06:00:
        allowed if current >= start OR current <= end
        (the range wraps past midnight)
    """
    start = time.fromisoformat(start_str)
    end = time.fromisoformat(end_str)

    if start <= end:
        return start <= current <= end
    else:
        return current >= start or current <= end


def evaluate(attributes: dict, rules: list) -> Tuple[bool, str]:
    """
    Evaluate an access request's attributes against a list of ABAC rules.

    Returns:
        (True, reason)  if some rule's resource pattern matches and every
                         condition in its allow_if block is satisfied.
        (False, reason) otherwise. `reason` always explains the decision —
                         this is what the audit log and false-positive
                         analysis run on, not just the boolean.

    Matching semantics:
        - Rules are checked in order.
        - A rule only applies if attributes["object_id"] matches its
          "resource" glob pattern.
        - Multiple rules can apply to the same resource (e.g. a day-shift
          rule and an on-call rule for the same resource) — this is how you
          express OR conditions. The first fully-satisfied rule wins.
        - If no rule allows, the denial reason reported is from whichever
          resource-matching rule came *closest* to allowing (fewest failed
          conditions), not simply the last rule checked. This matters for
          audit quality: a request with the right role but wrong network
          should say "wrong network", not get overwritten by an unrelated
          rule's "wrong role" message just because that rule happened to be
          checked later.
    """
    resource = attributes.get("object_id", "")
    best_denial_reason = None
    best_failure_count = None

    for rule in rules:
        if not fnmatch.fnmatch(resource, rule["resource"]):
            continue  # this rule doesn't govern this resource at all

        rule_id = rule.get("rule_id", "<unnamed rule>")
        allow_if = rule["allow_if"]
        failures = []

        if "role" in allow_if:
            expected_role = allow_if["role"]
            actual_role = attributes.get("role")
            if actual_role != expected_role:
                failures.append(
                    f"role '{actual_role}' does not match required role '{expected_role}'"
                )

        if "source_network" in allow_if:
            expected_net = allow_if["source_network"]
            actual_net = attributes.get("source_network")
            if actual_net != expected_net:
                failures.append(
                    f"source_network '{actual_net}' does not match required network '{expected_net}'"
                )

        if "time_range" in allow_if:
            start_str, end_str = allow_if["time_range"]
            timestamp = attributes.get("timestamp")
            if not timestamp:
                failures.append("no timestamp provided to check against time_range")
            else:
                current = _parse_time_of_day(timestamp)
                if not _in_time_range(current, start_str, end_str):
                    failures.append(
                        f"time {current.strftime('%H:%M')} is outside allowed range "
                        f"{start_str}-{end_str}"
                    )

        if not failures:
            return True, f"allowed by rule '{rule_id}': all conditions satisfied"

        # Keep the reason from whichever matching rule is "closest" to
        # allowing (fewest failed conditions) — that's the most useful
        # single explanation for an audit log, not just whichever rule
        # happened to be checked last.
        if best_failure_count is None or len(failures) < best_failure_count:
            best_failure_count = len(failures)
            best_denial_reason = f"denied by rule '{rule_id}': " + "; ".join(failures)

    if best_denial_reason is not None:
        return False, best_denial_reason

    return False, f"denied: no rule matches resource '{resource}'"