"""End-to-end tests against the generated datasets.

These are the tests that matter most for a detection tool: they check the
pipeline against ground truth on the attack dataset, and check that the same
rules stay quiet on the baseline dataset. If a threshold is tuned too loosely,
the second half of this file fails.
"""
from __future__ import annotations

import glob
import os

import pytest

import parser
from correlation import correlate
from detection import DetectionConfig, run_all
from reports import incident_report, investigation_report
from scoring import risk as risk_scoring
from tools import generate_scenario

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def run(folder: str):
    paths = sorted(glob.glob(os.path.join(DATA, folder, "*.log")))
    if not paths:
        pytest.skip(f"data/{folder} not generated; run tools/generate_scenario.py")
    result = parser.parse_files(paths)
    config = DetectionConfig()
    alerts = risk_scoring.score_alerts(run_all(result.events, config), config)
    incidents = correlate(alerts, result.events, config)
    return result, alerts, incidents, config


@pytest.fixture(scope="module")
def attack():
    return run("attacks")


@pytest.fixture(scope="module")
def baseline():
    return run("normal")


# --- parsing ---------------------------------------------------------------
def test_all_three_formats_are_detected_and_parsed(attack):
    result, _, _, _ = attack
    formats = {f.log_format for f in result.files}
    assert formats == {"linux_auth", "windows_security", "web_access"}
    assert len(result.events) > 9000
    assert result.events["timestamp"].notna().all()
    assert result.events["timestamp"].is_monotonic_increasing


def test_every_line_of_the_line_oriented_logs_is_parsed(attack):
    result, _, _, _ = attack
    for stats in result.files:
        if stats.log_format == "windows_security":
            continue          # one record spans many lines
        assert stats.parsed_events == stats.total_lines, stats.name


# --- ground truth: every planted stage is detected ------------------------
def test_each_planted_stage_raises_its_rule(attack):
    _, alerts, _, _ = attack
    fired = {a.rule_id for a in alerts}
    for rule_id in ("LH-001", "LH-002", "LH-003", "LH-004", "LH-005",
                    "LH-006", "LH-008", "LH-009", "LH-010", "LH-011"):
        assert rule_id in fired, f"{rule_id} did not fire on the attack dataset"


def test_the_brute_force_against_admin_is_found_with_the_right_count(attack):
    _, alerts, _, _ = attack
    match = [a for a in alerts
             if a.rule_id == "LH-001" and a.username == "admin"
             and a.source_ip == generate_scenario.ATTACKER_IP]
    assert len(match) == 1
    assert match[0].count == 17          # 17 failures were planted


def test_the_compromise_of_admin_is_critical(attack):
    _, alerts, _, _ = attack
    match = [a for a in alerts if a.rule_id == "LH-003" and a.username == "admin"]
    assert len(match) == 1
    assert match[0].severity == "critical"
    assert match[0].risk >= 85
    assert match[0].metadata["seconds_to_success"] <= 5


def test_the_attack_forms_one_incident_covering_every_stage(attack):
    _, _, incidents, _ = attack
    top = incidents[0]
    assert top.risk_band == "CRITICAL"
    assert top.source_ips == [generate_scenario.ATTACKER_IP]
    assert set(top.log_sources) == {"linux_auth", "windows_security", "web_access"}
    assert len(top.stages) == 7
    assert top.duration_minutes < 60      # one sitting, not a whole day
    assert "admin" in top.usernames and "administrator" in top.usernames


def test_the_chain_is_ordered_as_it_happened(attack):
    _, _, incidents, _ = attack
    stamps = [when for _, when in
              ((s, min((a.first_seen for a in incidents[0].alerts
                        if a.alert_id in ids and a.first_seen), default=None))
               for s, ids in incidents[0].stages)]
    stamps = [s for s in stamps if s is not None]
    assert stamps == sorted(stamps)


def test_the_second_actor_is_a_separate_incident(attack):
    _, _, incidents, _ = attack
    spray = [i for i in incidents
             if generate_scenario.SPRAY_IP in i.source_ips]
    assert len(spray) == 1
    assert generate_scenario.ATTACKER_IP not in spray[0].source_ips


def test_the_attackers_address_is_the_highest_risk_entity(attack):
    _, alerts, _, _ = attack
    worst = max(alerts, key=lambda a: a.risk)
    assert worst.source_ip == generate_scenario.ATTACKER_IP


def test_techniques_expected_from_the_scenario_are_mapped(attack):
    _, alerts, _, _ = attack
    techniques = {t for a in alerts for t in a.mitre}
    for tid in ("T1110", "T1078", "T1190", "T1059.001", "T1105",
                "T1136.001", "T1070.001", "T1548.003"):
        assert tid in techniques, tid


# --- the other half: silence on the baseline ------------------------------
def test_no_medium_or_worse_alert_on_the_baseline(baseline):
    _, alerts, _, _ = baseline
    noisy = [a for a in alerts if a.severity in ("medium", "high", "critical")]
    assert noisy == [], [f"{a.rule_id} {a.name} {a.severity}" for a in noisy]


def test_the_attack_only_rules_stay_silent_on_the_baseline(baseline):
    _, alerts, _, _ = baseline
    fired = {a.rule_id for a in alerts}
    for rule_id in ("LH-001", "LH-002", "LH-003", "LH-004", "LH-008", "LH-009"):
        assert rule_id not in fired, f"{rule_id} false-positived on clean data"


def test_no_incident_on_the_baseline_reaches_high(baseline):
    _, _, incidents, _ = baseline
    assert all(i.risk < 65 for i in incidents), \
        [(i.incident_id, i.risk) for i in incidents]


# --- reporting -------------------------------------------------------------
def test_incident_report_contains_the_evidence_an_analyst_needs(attack):
    result, _, incidents, config = attack
    report = incident_report(incidents[0], result.events, config)
    for heading in ("# Incident Report", "## Summary", "## Assessment",
                    "## How the risk score was reached", "## Attack chain",
                    "## Detections", "## Timeline", "## Evidence (raw log lines)",
                    "## MITRE ATT&CK", "## Recommended investigation",
                    "## Limitations"):
        assert heading in report, heading
    assert generate_scenario.ATTACKER_IP in report
    assert "T1110" in report


def test_full_investigation_report_covers_every_incident(attack):
    result, alerts, incidents, config = attack
    report = investigation_report(incidents, alerts, result.events,
                                  result.summary(), config)
    for incident in incidents:
        assert incident.incident_id in report


# --- determinism -----------------------------------------------------------
def test_the_generator_is_reproducible(tmp_path):
    first = generate_scenario.generate(str(tmp_path / "a"), seed=99)
    second = generate_scenario.generate(str(tmp_path / "b"), seed=99)
    assert first == second
    for name in ("auth.log", "access.log", "security.log"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()
