"""Log parsing and normalization.

Public entry points:

    detect_format(text, filename)  -> "linux_auth" | "windows_security" | "web_access"
    parse_text(text, fmt, name)    -> ParseResult
    parse_files(paths)             -> ParseResult over several files

Format detection works by voting: a sample of the file is handed to every
parser and whichever one recognises the most lines wins. That beats guessing
from the file name, which analysts rename constantly.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Iterable, Optional

import pandas as pd

from . import linux, web, windows
from .schema import (
    AUTH_EVENT_TYPES,
    AUTH_FAILURE,
    AUTH_INVALID_USER,
    AUTH_SUCCESS,
    LINUX_AUTH,
    WEB_ACCESS,
    WINDOWS_SECURITY,
    Event,
    empty_frame,
    events_to_frame,
)

__all__ = [
    "ParseResult",
    "detect_format",
    "parse_text",
    "parse_file",
    "parse_files",
    "FORMATS",
    "empty_frame",
]

FORMATS = (LINUX_AUTH, WINDOWS_SECURITY, WEB_ACCESS)
FORMAT_LABELS = {
    LINUX_AUTH: "Linux auth log",
    WINDOWS_SECURITY: "Windows Security event log",
    WEB_ACCESS: "Web server access log",
}

SAMPLE_LINES = 400


@dataclass
class FileStats:
    name: str
    log_format: str
    total_lines: int
    parsed_events: int

    @property
    def skipped_lines(self) -> int:
        return max(0, self.total_lines - self.parsed_events)


@dataclass
class ParseResult:
    events: pd.DataFrame
    files: list[FileStats] = field(default_factory=list)

    @property
    def total_lines(self) -> int:
        return sum(f.total_lines for f in self.files)

    @property
    def parsed_events(self) -> int:
        return len(self.events)

    def summary(self) -> str:
        parts = [f"{f.name}: {f.parsed_events} events ({FORMAT_LABELS.get(f.log_format, f.log_format)})"
                 for f in self.files]
        return "; ".join(parts)


def _parse_with(fmt: str, text: str, year: Optional[int] = None) -> list[Event]:
    if fmt == LINUX_AUTH:
        return list(linux.parse(text, year=year))
    if fmt == WINDOWS_SECURITY:
        return list(windows.parse(text))
    if fmt == WEB_ACCESS:
        return list(web.parse(text))
    raise ValueError("unknown log format: " + fmt)


def detect_format(text: str, filename: str = "") -> str:
    """Pick the parser that recognises the most of a sample of ``text``."""
    lines = [ln for ln in text.splitlines() if ln.strip()][:SAMPLE_LINES]
    sample = "\n".join(lines)
    if not sample:
        return LINUX_AUTH

    scores: dict[str, int] = {}
    for fmt in FORMATS:
        try:
            scores[fmt] = len(_parse_with(fmt, sample))
        except Exception:
            scores[fmt] = 0

    # Windows blocks span many lines, so its per-line score is naturally low;
    # weight it by the lines a record occupies before comparing.
    if scores.get(WINDOWS_SECURITY):
        scores[WINDOWS_SECURITY] = min(
            len(lines), scores[WINDOWS_SECURITY] * max(1, len(lines) // max(1, scores[WINDOWS_SECURITY]))
        )

    best = max(scores, key=lambda f: scores[f])
    if scores[best] == 0:
        # Nothing matched; fall back to the file name as a last resort.
        name = os.path.basename(filename).lower()
        if "access" in name or name.endswith(".log") and "http" in name:
            return WEB_ACCESS
        if "security" in name or "windows" in name or name.endswith(".evtx"):
            return WINDOWS_SECURITY
        return LINUX_AUTH
    return best


def parse_text(text: str, fmt: Optional[str] = None, name: str = "input",
               year: Optional[int] = None) -> ParseResult:
    """Normalize one log body into a ParseResult."""
    fmt = fmt or detect_format(text, name)
    events = _parse_with(fmt, text, year=year)
    frame = events_to_frame(events)
    total = len([ln for ln in text.splitlines() if ln.strip()])
    return ParseResult(frame, [FileStats(name, fmt, total, len(events))])


def parse_file(path: str, fmt: Optional[str] = None,
               year: Optional[int] = None) -> ParseResult:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    return parse_text(text, fmt=fmt, name=os.path.basename(path), year=year)


def parse_files(paths: Iterable[str], year: Optional[int] = None) -> ParseResult:
    """Parse several logs and merge them into one timeline.

    Merging matters: the interesting attack chains cross log sources (a web
    exploit, then an SSH login, then a Windows process).
    """
    frames: list[pd.DataFrame] = []
    stats: list[FileStats] = []
    for path in paths:
        result = parse_file(path, year=year)
        frames.append(result.events)
        stats.extend(result.files)
    return _merge(frames, stats)


def merge_results(results: Iterable[ParseResult]) -> ParseResult:
    results = list(results)
    frames = [r.events for r in results]
    stats = [f for r in results for f in r.files]
    return _merge(frames, stats)


def _merge(frames: list[pd.DataFrame], stats: list[FileStats]) -> ParseResult:
    frames = [f for f in frames if not f.empty]
    if not frames:
        return ParseResult(empty_frame(), stats)
    merged = pd.concat(frames, ignore_index=True)
    merged = merged.drop(columns=["event_id"], errors="ignore")
    merged["timestamp"] = pd.to_datetime(merged["timestamp"], errors="coerce")
    merged = merged.sort_values("timestamp", kind="stable", na_position="last")
    merged = merged.reset_index(drop=True)
    merged.insert(0, "event_id", merged.index.astype("int64"))
    return ParseResult(merged, stats)
