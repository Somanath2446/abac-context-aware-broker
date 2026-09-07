"""
tests/test_policy_engine.py

Day 3: one test per rule (correct context -> allow), plus wrong
role/network/time -> deny for each. Day 4-5 adds overnight-range and
virtual-clock-injection coverage.

Run: pytest tests/test_policy_engine.py -v
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parent.parent))

from policy_engine.evaluate import evaluate

RULES_PATH = Path(__file__).resolve().parent.parent / "policy_engine" / "rules.json"


@pytest.fixture
def rules():
    with open(RULES_PATH) as f:
        return json.load(f)


def make_attrs(**overrides):
    base = {
        "object_id": "scan_images/patient1.png",
        "requester_id": "user123",
        "role": "radiologist",
        "source_network": "hospital-vpn",
        "device_id": "laptop-42",
        "timestamp": "2025-06-01T14:30:00+00:00",  # 14:30, well inside 09:00-18:00
    }
    base.update(overrides)
    return base


# ---- radiologist-daytime-scans ------------------------------------------

def test_radiologist_daytime_correct_context_allows(rules):
    allowed, reason = evaluate(make_attrs(), rules)
    assert allowed is True
    assert "radiologist-daytime-scans" in reason


def test_radiologist_daytime_wrong_role_denies(rules):
    allowed, reason = evaluate(make_attrs(role="nurse"), rules)
    assert allowed is False


def test_radiologist_daytime_wrong_network_denies(rules):
    allowed, reason = evaluate(make_attrs(source_network="public-wifi"), rules)
    assert allowed is False


def test_radiologist_daytime_wrong_time_denies(rules):
    # 22:00 is outside 09:00-18:00 and outside the on-call role, so this
    # should still deny because the role here is the day-shift radiologist.
    allowed, reason = evaluate(
        make_attrs(timestamp="2025-06-01T22:00:00+00:00"), rules
    )
    assert allowed is False


# ---- radiologist-oncall-scans (overnight range 18:00-09:00) -------------

def test_radiologist_oncall_correct_context_allows(rules):
    allowed, reason = evaluate(
        make_attrs(role="radiologist-oncall", timestamp="2025-06-01T23:00:00+00:00"),
        rules,
    )
    assert allowed is True
    assert "radiologist-oncall-scans" in reason


def test_radiologist_oncall_after_midnight_allows(rules):
    # Overnight wraparound: 02:00 should still count as inside 18:00-09:00.
    allowed, reason = evaluate(
        make_attrs(role="radiologist-oncall", timestamp="2025-06-02T02:00:00+00:00"),
        rules,
    )
    assert allowed is True


def test_radiologist_oncall_midday_denies(rules):
    # 14:00 is outside the overnight window (18:00-09:00).
    allowed, reason = evaluate(
        make_attrs(role="radiologist-oncall", timestamp="2025-06-01T14:00:00+00:00"),
        rules,
    )
    assert allowed is False


# ---- nurse-patient-records ------------------------------------------------

def test_nurse_patient_records_correct_context_allows(rules):
    allowed, reason = evaluate(
        make_attrs(
            object_id="patient_records/chart1.pdf",
            role="nurse",
            timestamp="2025-06-01T08:00:00+00:00",
        ),
        rules,
    )
    assert allowed is True
    assert "nurse-patient-records" in reason


def test_nurse_patient_records_wrong_role_denies(rules):
    allowed, reason = evaluate(
        make_attrs(object_id="patient_records/chart1.pdf", role="radiologist"),
        rules,
    )
    assert allowed is False


# ---- auditor-audit-logs ---------------------------------------------------

def test_auditor_audit_logs_correct_context_allows(rules):
    allowed, reason = evaluate(
        make_attrs(
            object_id="audit_logs/2025-06.log",
            role="auditor",
            source_network="admin-office",
        ),
        rules,
    )
    assert allowed is True
    assert "auditor-audit-logs" in reason


def test_auditor_audit_logs_wrong_network_denies(rules):
    allowed, reason = evaluate(
        make_attrs(
            object_id="audit_logs/2025-06.log",
            role="auditor",
            source_network="hospital-vpn",
        ),
        rules,
    )
    assert allowed is False


# ---- itadmin-overnight-maintenance (overnight range 22:00-06:00) --------

def test_itadmin_overnight_correct_context_allows(rules):
    allowed, reason = evaluate(
        make_attrs(
            object_id="system_configs/network.conf",
            role="it-admin",
            source_network="admin-vpn",
            timestamp="2025-06-01T23:30:00+00:00",
        ),
        rules,
    )
    assert allowed is True
    assert "itadmin-overnight-maintenance" in reason


def test_itadmin_daytime_denies(rules):
    allowed, reason = evaluate(
        make_attrs(
            object_id="system_configs/network.conf",
            role="it-admin",
            source_network="admin-vpn",
            timestamp="2025-06-01T14:00:00+00:00",
        ),
        rules,
    )
    assert allowed is False


# ---- no matching resource --------------------------------------------------

def test_unknown_resource_denies_with_clear_reason(rules):
    allowed, reason = evaluate(make_attrs(object_id="random_file.txt"), rules)
    assert allowed is False
    assert "no rule matches resource" in reason


# ---- virtual clock injection ----------------------------------------------

def test_virtual_clock_injection_simulates_arbitrary_time(rules):
    """
    No real datetime.now() is ever called inside evaluate() — the caller
    fully controls "now" by setting attributes['timestamp']. This is what
    lets tests (and later, live demos) simulate "it's 2 AM" instantly.
    """
    allowed_night, _ = evaluate(
        make_attrs(role="radiologist-oncall", timestamp="2099-01-01T02:00:00+00:00"),
        rules,
    )
    allowed_day, _ = evaluate(
        make_attrs(role="radiologist-oncall", timestamp="2099-01-01T14:00:00+00:00"),
        rules,
    )
    assert allowed_night is True
    assert allowed_day is False
