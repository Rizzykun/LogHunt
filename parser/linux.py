"""Parser for Linux authentication logs (/var/log/auth.log, /var/log/secure).

Handles classic syslog timestamps (Sep 18 10:21:01) and RFC3339 syslog
(2026-09-18T10:21:01+08:00). Syslog carries no year, so the year is inferred:
callers pass a default year and the parser bumps it when the month rolls
backwards, which is how a log file crossing new year reads.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Iterator, Optional

from .schema import (
    AUTH_FAILURE,
    AUTH_INVALID_USER,
    AUTH_SUCCESS,
    LINUX_AUTH,
    OTHER,
    PRIVILEGE_USE,
    SESSION_CLOSE,
    SESSION_OPEN,
    Event,
)

# Sep 18 10:21:01 web-01 sshd[1234]: message
SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[\w.\-]+)\s+(?P<proc>[\w./\-]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

# 2026-09-18T10:21:01.123456+08:00 web-01 sshd[1234]: message
RFC3339_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>[\w.\-]+)\s+(?P<proc>[\w./\-]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

MONTHS = {
    m: i + 1
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    )
}

IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"

# Message patterns, tried in order.
# Each entry is (regex, event_type, status, action label).
MESSAGE_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"^Failed (?P<method>password|publickey|none) for invalid user "
                r"(?P<user>\S+) from (?P<ip>" + IPV4 + r")"),
     AUTH_INVALID_USER, "failure", "Failed SSH auth for non-existent user"),
    (re.compile(r"^Failed (?P<method>password|publickey|none) for "
                r"(?P<user>\S+) from (?P<ip>" + IPV4 + r")"),
     AUTH_FAILURE, "failure", "Failed SSH password authentication"),
    (re.compile(r"^Accepted (?P<method>password|publickey|keyboard-interactive(?:/pam)?) "
                r"for (?P<user>\S+) from (?P<ip>" + IPV4 + r")"),
     AUTH_SUCCESS, "success", "Successful SSH authentication"),
    (re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>" + IPV4 + r")"),
     AUTH_INVALID_USER, "failure", "SSH login attempt for non-existent user"),
    (re.compile(r"^Connection closed by (?:authenticating|invalid) user "
                r"(?P<user>\S+) (?P<ip>" + IPV4 + r")"),
     AUTH_FAILURE, "failure", "SSH connection aborted during authentication"),
    (re.compile(r"^pam_unix\([^)]*\):\s*session opened for user (?P<user>[\w.\-]+)"),
     SESSION_OPEN, "success", "PAM session opened"),
    (re.compile(r"^pam_unix\([^)]*\):\s*session closed for user (?P<user>[\w.\-]+)"),
     SESSION_CLOSE, "info", "PAM session closed"),
    (re.compile(r"^pam_unix\([^)]*\):\s*authentication failure;.*?\buser=(?P<user>[\w.\-]+)"),
     AUTH_FAILURE, "failure", "PAM authentication failure"),
]

# sudo:  alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow
SUDO_RE = re.compile(
    r"^\s*(?P<user>[\w.\-]+)\s*:\s*(?P<detail>.*?USER=(?P<target>[\w.\-]+).*?"
    r"COMMAND=(?P<command>.*))$"
)
SUDO_FAIL_RE = re.compile(
    r"^\s*(?P<user>[\w.\-]+)\s*:\s*(?:\d+ incorrect password attempts"
    r"|command not allowed|user NOT in sudoers)"
)
NEW_USER_RE = re.compile(r"^new (?:user|group): name=(?P<user>[\w.\-]+)")
SU_OK_RE = re.compile(r"^Successful su for (?P<target>[\w.\-]+) by (?P<user>[\w.\-]+)")


def _parse_syslog_timestamp(mon: str, day: str, time_str: str, year: int) -> Optional[datetime]:
    try:
        hh, mm, ss = (int(p) for p in time_str.split(":"))
        return datetime(year, MONTHS[mon], int(day), hh, mm, ss)
    except (ValueError, KeyError):
        return None


def _parse_rfc3339(ts: str) -> Optional[datetime]:
    cleaned = ts.replace("Z", "+00:00")
    cleaned = re.sub(r"([+\-]\d{2})(\d{2})$", r"\1:\2", cleaned)
    try:
        dt = datetime.fromisoformat(cleaned.replace(" ", "T"))
    except ValueError:
        return None
    return dt.replace(tzinfo=None) if dt.tzinfo else dt


def _classify(proc: str, msg: str) -> tuple[str, str, str, dict]:
    """Return (event_type, status, action, captured fields) for a message."""
    for pattern, event_type, status, action in MESSAGE_PATTERNS:
        m = pattern.match(msg)
        if m:
            return event_type, status, action, m.groupdict()

    base_proc = proc.split("/")[-1]
    if base_proc in ("sudo", "su"):
        m = SUDO_RE.match(msg)
        if m:
            return PRIVILEGE_USE, "success", "sudo command executed", m.groupdict()
        m = SUDO_FAIL_RE.match(msg)
        if m:
            return PRIVILEGE_USE, "failure", "sudo authorisation denied", m.groupdict()
        m = SU_OK_RE.match(msg)
        if m:
            return PRIVILEGE_USE, "success", "switched user via su", m.groupdict()
    if base_proc in ("useradd", "groupadd", "usermod"):
        m = NEW_USER_RE.match(msg)
        if m:
            return (PRIVILEGE_USE, "success",
                    "account modified by " + base_proc, m.groupdict())
    return OTHER, "info", msg[:120], {}


def parse_line(line: str, year: int, line_no: Optional[int] = None) -> Optional[Event]:
    """Parse a single auth.log line into an Event, or None if unrecognised."""
    line = line.rstrip("\r\n")
    if not line.strip():
        return None

    m = SYSLOG_RE.match(line)
    if m:
        ts = _parse_syslog_timestamp(m.group("mon"), m.group("day"), m.group("time"), year)
    else:
        m = RFC3339_RE.match(line)
        if not m:
            return None
        ts = _parse_rfc3339(m.group("ts"))

    proc, msg, host = m.group("proc"), m.group("msg"), m.group("host")
    event_type, status, action, captured = _classify(proc, msg)

    event = Event(
        timestamp=ts,
        source=LINUX_AUTH,
        host=host,
        source_ip=captured.get("ip", ""),
        username=captured.get("user", ""),
        event_type=event_type,
        action=action,
        status=status,
        process=proc,
        command_line=captured.get("command", "").strip(),
        raw=line,
        line_no=line_no,
    )
    if captured.get("target"):
        event.extra["target_user"] = captured["target"]
    if m.groupdict().get("pid"):
        event.extra["pid"] = m.group("pid")
    if captured.get("method"):
        event.extra["auth_method"] = captured["method"]
    return event


def parse(text: str, year: Optional[int] = None) -> Iterator[Event]:
    """Parse a whole auth.log, inferring the year across month rollovers."""
    year = year or datetime.now().year
    prev_month: Optional[int] = None
    for i, line in enumerate(text.splitlines(), start=1):
        event = parse_line(line, year, line_no=i)
        if event is None:
            continue
        if event.timestamp is not None:
            month = event.timestamp.month
            if prev_month is not None and month < prev_month - 6:
                # Dec -> Jan: the log crossed into the next year
                year += 1
                event.timestamp = event.timestamp.replace(year=year)
            prev_month = month
        yield event
