"""Normalized event schema shared by every parser.

Every parser in this package turns a raw log line (or block) into an
:class:`Event`.  Detections only ever see normalized events, which is what
makes one rule work across Linux, Windows and web logs.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict, fields
from datetime import datetime
from typing import Any, Iterable, Optional

import pandas as pd

# --- event_type vocabulary -------------------------------------------------
# Kept deliberately small.  Detections match on these, never on raw strings.
AUTH_FAILURE = "auth_failure"
AUTH_SUCCESS = "auth_success"
AUTH_INVALID_USER = "auth_invalid_user"
PRIVILEGE_USE = "privilege_use"
PRIVILEGE_ASSIGNED = "privilege_assigned"
PROCESS_CREATION = "process_creation"
WEB_REQUEST = "web_request"
SESSION_OPEN = "session_open"
SESSION_CLOSE = "session_close"
OTHER = "other"

AUTH_EVENT_TYPES = (AUTH_FAILURE, AUTH_SUCCESS, AUTH_INVALID_USER)

# --- log sources -----------------------------------------------------------
LINUX_AUTH = "linux_auth"
WINDOWS_SECURITY = "windows_security"
WEB_ACCESS = "web_access"


@dataclass
class Event:
    """One normalized log event."""

    timestamp: Optional[datetime] = None
    source: str = OTHER          # which log family this came from
    host: str = ""               # machine the event was recorded on
    source_ip: str = ""
    destination_ip: str = ""
    username: str = ""
    event_type: str = OTHER
    action: str = ""             # short human description
    status: str = ""             # success | failure | info
    process: str = ""
    command_line: str = ""
    http_method: str = ""
    uri: str = ""
    http_status: Optional[int] = None
    user_agent: str = ""
    bytes_sent: Optional[int] = None
    event_code: str = ""         # Windows Event ID, when applicable
    logon_type: str = ""
    raw: str = ""
    line_no: Optional[int] = None
    extra: dict = field(default_factory=dict)

    def as_row(self) -> dict[str, Any]:
        row = asdict(self)
        row.pop("extra")
        return row


COLUMNS = [f.name for f in fields(Event) if f.name != "extra"]


def events_to_frame(events: Iterable[Event]) -> pd.DataFrame:
    """Build the canonical DataFrame every downstream stage consumes.

    Adds an ``event_id`` column so alerts can cite specific evidence.
    """
    rows = [e.as_row() for e in events]
    df = pd.DataFrame(rows, columns=COLUMNS)
    if df.empty:
        df["event_id"] = pd.Series(dtype="int64")
        return df

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.sort_values("timestamp", kind="stable", na_position="last")
    df = df.reset_index(drop=True)
    df.insert(0, "event_id", df.index.astype("int64"))
    df["http_status"] = pd.to_numeric(df["http_status"], errors="coerce")
    df["bytes_sent"] = pd.to_numeric(df["bytes_sent"], errors="coerce")
    for col in ("username", "source_ip", "host", "process", "uri"):
        df[col] = df[col].fillna("").astype(str)
    return df


def empty_frame() -> pd.DataFrame:
    return events_to_frame([])
