"""Parser for Windows Security event logs.

Windows logs reach an analyst in several shapes, so three are supported:

1. Event Viewer / ``wevtutil qe /f:text`` key-value blocks (the default of the
   bundled sample data, because it is the most recognisable form).
2. CSV exported with ``Get-WinEvent ... | Export-Csv``.
3. JSON (one object per line, or a single JSON array).

Only the event IDs that matter for this toolkit are given semantics; anything
else is kept as a normalized ``other`` event so it still shows on the timeline.
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime
from typing import Any, Iterator, Optional

from .schema import (
    AUTH_FAILURE,
    AUTH_SUCCESS,
    OTHER,
    PRIVILEGE_ASSIGNED,
    PRIVILEGE_USE,
    PROCESS_CREATION,
    SESSION_CLOSE,
    WINDOWS_SECURITY,
    Event,
)

# Event ID -> (event_type, status, action)
EVENT_ID_MAP: dict[str, tuple[str, str, str]] = {
    "4624": (AUTH_SUCCESS, "success", "Successful account logon"),
    "4625": (AUTH_FAILURE, "failure", "Failed account logon"),
    "4634": (SESSION_CLOSE, "info", "Account logoff"),
    "4647": (SESSION_CLOSE, "info", "User-initiated logoff"),
    "4648": (AUTH_SUCCESS, "success", "Logon using explicit credentials"),
    "4672": (PRIVILEGE_ASSIGNED, "success", "Special privileges assigned to new logon"),
    "4688": (PROCESS_CREATION, "info", "New process created"),
    "4720": (PRIVILEGE_USE, "success", "User account created"),
    "4724": (PRIVILEGE_USE, "success", "Password reset attempted"),
    "4732": (PRIVILEGE_USE, "success", "Member added to a privileged local group"),
    "4768": (AUTH_SUCCESS, "success", "Kerberos TGT requested"),
    "4771": (AUTH_FAILURE, "failure", "Kerberos pre-authentication failed"),
    "4776": (AUTH_SUCCESS, "success", "Credential validation"),
    "1102": (PRIVILEGE_USE, "success", "Security audit log cleared"),
}

# Logon type -> label, used in alert text ("type 3" means little on its own).
LOGON_TYPES = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}

PLACEHOLDERS = {"", "-", "null sid", "n/a", "0x0", "0", "none", "not available"}

KV_RE = re.compile(r"^\s*(?P<key>[A-Za-z][A-Za-z /()'\-]{2,40}):\s*(?P<value>.*?)\s*$")

TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %H:%M:%S",
    "%d/%m/%Y %I:%M:%S %p",
    "%m/%d/%Y %I:%M:%S.%f %p",
)

# Column aliases for CSV / JSON input, normalized key -> accepted names.
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": ("timecreated", "timegenerated", "date", "timestamp", "eventtime", "systemtime"),
    "event_code": ("eventid", "id", "event_id", "eventcode"),
    "host": ("computer", "computername", "machinename", "host", "hostname"),
    "username": ("targetusername", "accountname", "account", "user", "username",
                 "subjectusername"),
    "source_ip": ("ipaddress", "sourcenetworkaddress", "sourceaddress", "source_ip",
                  "clientaddress", "workstationip"),
    "process": ("newprocessname", "processname", "process", "image"),
    "command_line": ("commandline", "processcommandline", "command_line"),
    "logon_type": ("logontype", "logon_type"),
    "raw": ("message", "description", "raw"),
}


def _parse_ts(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    # ``/Date(1758...)/`` style from ConvertTo-Json
    m = re.match(r"^/Date\((\d+)\)/$", text)
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000)
    cleaned = text.replace("Z", "").strip()
    cleaned = re.sub(r"([+\-]\d{2}):?\d{2}$", "", cleaned).strip()
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return None


def _first_real(values: list[str]) -> str:
    """Pick the first meaningful value for a repeated key.

    Security events repeat ``Account Name`` (once for the Subject, once for the
    target). The subject side is usually a placeholder such as ``-`` or
    ``NULL SID`` for network logons, so the first non-placeholder wins.
    """
    for v in values:
        if v.strip().lower() not in PLACEHOLDERS:
            return v.strip()
    return ""


def _lookup(fields: dict[str, list[str]], *keys: str) -> str:
    for key in keys:
        if key in fields:
            value = _first_real(fields[key])
            if value:
                return value
    return ""


def _build_event(fields: dict[str, list[str]], raw: str,
                 line_no: Optional[int] = None) -> Optional[Event]:
    event_code = _lookup(fields, "event id", "eventid", "id")
    event_code = re.sub(r"\D", "", event_code)
    if not event_code:
        return None

    event_type, status, action = EVENT_ID_MAP.get(
        event_code, (OTHER, "info", "Windows event " + event_code)
    )
    process = _lookup(fields, "new process name", "process name", "image")
    if process.lower() in PLACEHOLDERS:
        process = ""
    logon_type = re.sub(r"\D", "", _lookup(fields, "logon type"))

    event = Event(
        timestamp=_parse_ts(_lookup(fields, "date", "timecreated", "time created", "timestamp")),
        source=WINDOWS_SECURITY,
        host=_lookup(fields, "computer", "computer name", "machinename"),
        source_ip=_lookup(fields, "source network address", "source address",
                          "client address", "ip address"),
        username=_lookup(fields, "account name", "target user name", "user name"),
        event_type=event_type,
        action=action,
        status=status,
        process=process,
        command_line=_lookup(fields, "process command line", "command line"),
        event_code=event_code,
        logon_type=LOGON_TYPES.get(logon_type, logon_type),
        raw=raw.strip(),
        line_no=line_no,
    )
    workstation = _lookup(fields, "workstation name")
    if workstation:
        event.extra["workstation"] = workstation
    reason = _lookup(fields, "failure reason", "status")
    if reason and status == "failure":
        event.extra["failure_reason"] = reason
    if logon_type:
        event.extra["logon_type_id"] = logon_type
    return event


def _parse_text_blocks(text: str) -> Iterator[Event]:
    """Parse Event-Viewer style key/value blocks.

    A record starts at each ``Log Name:`` (or ``Event[n]:``) header, so blank
    lines inside a description do not split a record in half.
    """
    lines = text.splitlines()
    starts = [
        i for i, line in enumerate(lines)
        if re.match(r"^\s*(Log Name\s*:|Event\[\d+\]\s*:)", line)
    ]
    if not starts:
        # No header at all: treat the whole text as one record.
        starts = [0]
    bounds = list(zip(starts, starts[1:] + [len(lines)]))

    for start, end in bounds:
        block = lines[start:end]
        fields: dict[str, list[str]] = {}
        for line in block:
            m = KV_RE.match(line)
            if not m:
                continue
            key = re.sub(r"\s+", " ", m.group("key")).strip().lower()
            fields.setdefault(key, []).append(m.group("value"))
        event = _build_event(fields, "\n".join(block), line_no=start + 1)
        if event is not None:
            yield event


def _record_to_fields(record: dict[str, Any]) -> dict[str, list[str]]:
    """Map a CSV/JSON record onto the key names the block parser uses."""
    lowered = {str(k).strip().lower().replace("_", "").replace(" ", ""): v
               for k, v in record.items() if k is not None}
    canonical_keys = {
        "timestamp": "date",
        "event_code": "event id",
        "host": "computer",
        "username": "account name",
        "source_ip": "source network address",
        "process": "new process name",
        "command_line": "process command line",
        "logon_type": "logon type",
        "raw": "description",
    }
    fields: dict[str, list[str]] = {}
    for canon, aliases in FIELD_ALIASES.items():
        for alias in aliases:
            key = alias.replace("_", "")
            if key in lowered and lowered[key] is not None:
                fields.setdefault(canonical_keys[canon], []).append(str(lowered[key]))
                break
    # A Message/Description body often carries the fields a flat export dropped.
    body = fields.get("description", [""])[0]
    if body:
        for line in body.splitlines():
            m = KV_RE.match(line)
            if m:
                key = re.sub(r"\s+", " ", m.group("key")).strip().lower()
                fields.setdefault(key, []).append(m.group("value"))
    return fields


def _parse_csv(text: str) -> Iterator[Event]:
    reader = csv.DictReader(io.StringIO(text))
    for i, record in enumerate(reader, start=2):
        fields = _record_to_fields(record)
        raw = ", ".join(f"{k}={v}" for k, v in record.items() if v)
        event = _build_event(fields, raw, line_no=i)
        if event is not None:
            yield event


def _parse_json(text: str) -> Iterator[Event]:
    stripped = text.lstrip()
    records: list[dict[str, Any]] = []
    if stripped.startswith("["):
        loaded = json.loads(stripped)
        records = [r for r in loaded if isinstance(r, dict)]
    else:
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append(record)
    for i, record in enumerate(records, start=1):
        fields = _record_to_fields(record)
        event = _build_event(fields, json.dumps(record)[:800], line_no=i)
        if event is not None:
            yield event


def parse(text: str) -> Iterator[Event]:
    """Parse Windows security log text in whichever of the three shapes it is."""
    stripped = text.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        yield from _parse_json(text)
        return

    first_line = stripped.splitlines()[0] if stripped.splitlines() else ""
    looks_like_csv = "," in first_line and re.search(
        r"(?i)\b(eventid|timecreated|id)\b", first_line
    )
    if looks_like_csv:
        yield from _parse_csv(text)
        return

    yield from _parse_text_blocks(text)
