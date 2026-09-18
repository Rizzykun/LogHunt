"""Parser for Apache/Nginx access logs (common and combined log formats).

Accepts the full combined format as well as the trimmed variants people paste
into tickets, where the timezone, byte count, referrer and user agent may all
be missing.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Iterator, Optional

from .schema import WEB_ACCESS, WEB_REQUEST, Event

# 192.168.1.20 - - [18/Sep/2026:10:21:01 +0800] "GET /admin HTTP/1.1" 200 1234 "-" "curl/8.0"
ACCESS_RE = re.compile(
    r"^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+"
    r"\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<request>[^"]*)"\s+'
    r"(?P<status>\d{3})"
    r"(?:\s+(?P<bytes>\d+|-))?"
    r'(?:\s+"(?P<referrer>[^"]*)")?'
    r'(?:\s+"(?P<agent>[^"]*)")?'
)

REQUEST_RE = re.compile(
    r"^(?P<method>[A-Z]+)\s+(?P<uri>\S+)(?:\s+(?P<proto>HTTP/[\d.]+))?$"
)

TS_FORMATS = (
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
    "%d/%b/%Y %H:%M:%S",
)


def _parse_ts(value: str) -> Optional[datetime]:
    value = value.strip()
    for fmt in TS_FORMATS:
        try:
            dt = datetime.strptime(value, fmt)
        except ValueError:
            continue
        return dt.replace(tzinfo=None) if dt.tzinfo else dt
    return None


def parse_line(line: str, line_no: Optional[int] = None) -> Optional[Event]:
    """Parse one access-log line into an Event, or None if unrecognised."""
    line = line.rstrip("\r\n")
    if not line.strip():
        return None
    m = ACCESS_RE.match(line)
    if not m:
        return None

    request = (m.group("request") or "").strip()
    rm = REQUEST_RE.match(request)
    if rm:
        method, uri = rm.group("method"), rm.group("uri")
    else:
        # Attack payloads often contain raw spaces ("?q=1 UNION SELECT ..."),
        # which the strict form rejects. Split off the verb and the trailing
        # protocol by hand so the URI stays intact for the web-attack rules.
        method, _, rest = request.partition(" ")
        if not method.isupper():
            method = ""
            rest = request
        uri = re.sub(r"\s+HTTP/[\d.]+$", "", rest).strip() or request

    status = int(m.group("status"))
    size = m.group("bytes")
    remote_user = m.group("user")

    event = Event(
        timestamp=_parse_ts(m.group("ts")),
        source=WEB_ACCESS,
        source_ip=m.group("ip"),
        username="" if remote_user in ("-", None) else remote_user,
        event_type=WEB_REQUEST,
        action=(method + " " + uri).strip(),
        status="success" if status < 400 else "failure",
        http_method=method,
        uri=uri,
        http_status=status,
        user_agent="" if m.group("agent") in ("-", None) else m.group("agent"),
        bytes_sent=int(size) if size and size != "-" else None,
        raw=line,
        line_no=line_no,
    )
    referrer = m.group("referrer")
    if referrer and referrer != "-":
        event.extra["referrer"] = referrer
    if rm and rm.group("proto"):
        event.extra["protocol"] = rm.group("proto")
    return event


def parse(text: str) -> Iterator[Event]:
    for i, line in enumerate(text.splitlines(), start=1):
        event = parse_line(line, line_no=i)
        if event is not None:
            yield event
