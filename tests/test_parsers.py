"""Parser tests: the normalized schema is the contract everything else relies on."""
from __future__ import annotations

from datetime import datetime

import parser
from parser import linux, schema, web, windows


def test_linux_failed_password():
    event = linux.parse_line(
        "Sep 18 10:21:01 web-01 sshd[1234]: Failed password for admin from "
        "192.168.1.20 port 51234 ssh2", year=2026)
    assert event is not None
    assert event.event_type == schema.AUTH_FAILURE
    assert event.username == "admin"
    assert event.source_ip == "192.168.1.20"
    assert event.host == "web-01"
    assert event.timestamp == datetime(2026, 9, 18, 10, 21, 1)


def test_linux_invalid_user_is_distinct_from_a_wrong_password():
    event = linux.parse_line(
        "Sep 18 10:21:03 web-01 sshd[1]: Failed password for invalid user oracle "
        "from 192.168.1.20 port 1 ssh2", year=2026)
    assert event.event_type == schema.AUTH_INVALID_USER
    assert event.username == "oracle"


def test_linux_accepted_password():
    event = linux.parse_line(
        "Sep 18 10:21:24 web-01 sshd[1]: Accepted password for admin from "
        "192.168.1.20 port 1 ssh2", year=2026)
    assert event.event_type == schema.AUTH_SUCCESS
    assert event.extra["auth_method"] == "password"


def test_linux_sudo_captures_command_and_target():
    event = linux.parse_line(
        "Sep 18 10:23:01 web-01 sudo:    admin : TTY=pts/1 ; PWD=/root ; USER=root ; "
        "COMMAND=/usr/bin/cat /etc/shadow", year=2026)
    assert event.event_type == schema.PRIVILEGE_USE
    assert event.username == "admin"
    assert event.command_line == "/usr/bin/cat /etc/shadow"
    assert event.extra["target_user"] == "root"


def test_linux_rfc3339_timestamps():
    event = linux.parse_line(
        "2026-09-18T10:24:00+08:00 web-01 sshd[1]: Accepted publickey for alice "
        "from 10.0.0.5 port 1 ssh2", year=2026)
    assert event.timestamp == datetime(2026, 9, 18, 10, 24, 0)
    assert event.username == "alice"


def test_linux_year_rolls_over_at_new_year():
    text = "\n".join([
        "Dec 31 23:59:59 web-01 sshd[1]: Failed password for a from 10.0.0.1 port 1 ssh2",
        "Jan 01 00:00:30 web-01 sshd[2]: Failed password for a from 10.0.0.1 port 1 ssh2",
    ])
    first, second = list(linux.parse(text, year=2025))
    assert first.timestamp.year == 2025
    assert second.timestamp.year == 2026


def test_linux_skips_unparseable_lines():
    assert linux.parse_line("this is not a syslog line", year=2026) is None
    assert linux.parse_line("", year=2026) is None


def test_web_combined_format():
    event = web.parse_line(
        '192.168.1.20 - - [18/Sep/2026:10:21:01 +0800] "GET /admin HTTP/1.1" '
        '200 1043 "-" "curl/8.4.0"')
    assert event.event_type == schema.WEB_REQUEST
    assert event.http_method == "GET"
    assert event.uri == "/admin"
    assert event.http_status == 200
    assert event.bytes_sent == 1043
    assert event.user_agent == "curl/8.4.0"
    assert event.timestamp == datetime(2026, 9, 18, 10, 21, 1)


def test_web_trimmed_format_without_timezone_or_size():
    event = web.parse_line(
        '192.168.1.20 - - [18/Sep/2026:10:21:01] "GET /admin HTTP/1.1" 200')
    assert event.http_status == 200
    assert event.bytes_sent is None


def test_web_keeps_payloads_containing_spaces():
    event = web.parse_line(
        '10.0.0.9 - - [18/Sep/2026:10:21:01 +0800] '
        '"GET /search?q=1 UNION SELECT pw FROM users HTTP/1.1" 200 12')
    assert event.http_method == "GET"
    assert "UNION SELECT" in event.uri
    assert "HTTP/1.1" not in event.uri


def test_web_error_status_is_a_failure():
    event = web.parse_line(
        '10.0.0.9 - - [18/Sep/2026:10:21:01 +0800] "GET /nope HTTP/1.1" 404 0')
    assert event.status == "failure"


WINDOWS_BLOCK = """Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          9/18/2026 10:21:01 AM
Event ID:      4625
Task Category: Logon
Computer:      DC01.corp.local
Description:
An account failed to log on.

Subject:
\tSecurity ID:\t\tNULL SID
\tAccount Name:\t\t-
Account For Which Logon Failed:
\tAccount Name:\t\tadministrator
Failure Information:
\tFailure Reason:\t\tUnknown user name or bad password.
Logon Type:\t\t3
Network Information:
\tWorkstation Name:\tKALI
\tSource Network Address:\t192.168.1.20
"""


def test_windows_text_block_prefers_the_target_account_over_the_subject():
    events = list(windows.parse(WINDOWS_BLOCK))
    assert len(events) == 1
    event = events[0]
    # "Account Name" appears twice; the Subject value is the placeholder "-".
    assert event.username == "administrator"
    assert event.event_type == schema.AUTH_FAILURE
    assert event.event_code == "4625"
    assert event.source_ip == "192.168.1.20"
    assert event.logon_type == "Network"
    assert event.timestamp == datetime(2026, 9, 18, 10, 21, 1)


def test_windows_blank_lines_inside_a_description_do_not_split_a_record():
    doubled = WINDOWS_BLOCK + "\n" + WINDOWS_BLOCK
    assert len(list(windows.parse(doubled))) == 2


def test_windows_csv_export():
    text = "\n".join([
        "TimeCreated,EventID,Computer,TargetUserName,IpAddress,LogonType",
        "2026-09-18T10:25:00,4624,DC01,administrator,192.168.1.20,10",
    ])
    event = list(windows.parse(text))[0]
    assert event.event_type == schema.AUTH_SUCCESS
    assert event.username == "administrator"
    assert event.logon_type == "RemoteInteractive (RDP)"


def test_windows_json_lines():
    text = ('{"TimeCreated": "2026-09-18T10:27:03", "Id": 4688, '
            '"Computer": "DC01", "TargetUserName": "administrator", '
            '"NewProcessName": "C:\\\\Windows\\\\System32\\\\cmd.exe", '
            '"CommandLine": "cmd.exe /c whoami"}')
    event = list(windows.parse(text))[0]
    assert event.event_type == schema.PROCESS_CREATION
    assert event.command_line == "cmd.exe /c whoami"


def test_windows_unknown_event_id_still_normalizes():
    text = "Log Name: Security\nEvent ID: 9999\nComputer: DC01\nDate: 9/18/2026 1:00:00 AM"
    event = list(windows.parse(text))[0]
    assert event.event_type == schema.OTHER
    assert event.event_code == "9999"


def test_format_detection_votes_correctly():
    assert parser.detect_format(
        "Sep 18 10:21:01 web-01 sshd[1]: Failed password for a from 10.0.0.1 port 1 ssh2"
    ) == schema.LINUX_AUTH
    assert parser.detect_format(
        '10.0.0.1 - - [18/Sep/2026:10:21:01 +0800] "GET / HTTP/1.1" 200 1'
    ) == schema.WEB_ACCESS
    assert parser.detect_format(WINDOWS_BLOCK) == schema.WINDOWS_SECURITY


def test_merged_frames_share_one_ordered_event_id_space():
    linux_text = ("Sep 18 10:21:01 web-01 sshd[1]: Failed password for a from "
                  "10.0.0.1 port 1 ssh2")
    web_text = '10.0.0.1 - - [18/Sep/2026:10:20:00 +0800] "GET / HTTP/1.1" 200 1'
    merged = parser.merge_results([
        parser.parse_text(linux_text, name="auth.log"),
        parser.parse_text(web_text, name="access.log"),
    ])
    frame = merged.events
    assert list(frame["event_id"]) == [0, 1]
    # Sorted across sources, so the web request at 10:20 comes first.
    assert frame.iloc[0]["source"] == schema.WEB_ACCESS
    assert frame["timestamp"].is_monotonic_increasing


def test_empty_input_produces_an_empty_frame_with_the_full_schema():
    frame = parser.parse_text("", name="empty.log").events
    assert frame.empty
    for column in schema.COLUMNS:
        assert column in frame.columns
