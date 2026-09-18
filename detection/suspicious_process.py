"""Detection 6: suspicious process execution.

cmd.exe runs on every Windows host all day, so a flat "these binaries are bad"
list produces an alert queue nobody reads. Two things are separated here:

* the binary itself, which carries a *baseline* severity (powershell.exe is
  low on its own, mimikatz is not);
* the command line, which is what actually raises severity - encoded
  payloads, download cradles, hidden windows, credential dumping.

The same rule then covers Linux by reading the command executed via sudo.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import pandas as pd

from parser.schema import PRIVILEGE_USE, PROCESS_CREATION

from .base import Alert, DetectionConfig, bump_severity

PROCESS_RULE_ID = "LH-010"
COMMAND_RULE_ID = "LH-011"


@dataclass(frozen=True)
class WatchedBinary:
    name: str
    severity: str
    mitre: tuple[str, ...]
    why: str


# Interpreters and LOLBins worth logging. Severity here is the floor.
WATCHED_BINARIES: tuple[WatchedBinary, ...] = (
    WatchedBinary("powershell.exe", "medium", ("T1059.001",),
                  "PowerShell is the default tooling for post-exploitation on Windows"),
    WatchedBinary("pwsh.exe", "medium", ("T1059.001",), "PowerShell Core"),
    WatchedBinary("cmd.exe", "low", ("T1059.003",),
                  "command shell, common legitimately and in intrusions"),
    WatchedBinary("wscript.exe", "medium", ("T1059.005",), "Windows Script Host"),
    WatchedBinary("cscript.exe", "medium", ("T1059.005",), "Windows Script Host"),
    WatchedBinary("mshta.exe", "high", ("T1218.005",),
                  "executes remote script content, rarely used legitimately"),
    WatchedBinary("certutil.exe", "high", ("T1105",),
                  "can download and decode files, a common transfer LOLBin"),
    WatchedBinary("bitsadmin.exe", "high", ("T1105",), "background file transfer"),
    WatchedBinary("regsvr32.exe", "high", ("T1218.010",), "script proxy execution"),
    WatchedBinary("rundll32.exe", "medium", ("T1218.011",), "DLL proxy execution"),
    WatchedBinary("wmic.exe", "medium", ("T1059.003",), "remote execution and discovery"),
    WatchedBinary("psexec.exe", "high", ("T1569.002",), "remote service execution"),
    WatchedBinary("schtasks.exe", "medium", ("T1053.005",), "scheduled task creation"),
    WatchedBinary("net.exe", "low", ("T1087",), "account and share discovery"),
    WatchedBinary("net1.exe", "low", ("T1087",), "account and share discovery"),
    WatchedBinary("whoami.exe", "low", ("T1082",), "post-exploitation orientation"),
    WatchedBinary("nltest.exe", "medium", ("T1087",), "domain trust discovery"),
    WatchedBinary("vssadmin.exe", "high", ("T1003",), "shadow copy access"),
    WatchedBinary("ntdsutil.exe", "critical", ("T1003",), "domain credential database access"),
    WatchedBinary("mimikatz.exe", "critical", ("T1003",), "credential dumping tool"),
    WatchedBinary("procdump.exe", "high", ("T1003",), "process memory dumping"),
    WatchedBinary("reg.exe", "low", ("T1003",), "registry access, including hive export"),
)

BINARY_INDEX = {b.name: b for b in WATCHED_BINARIES}

# Command-line indicators. Each one bumps severity and adds techniques.
COMMAND_INDICATORS: list[tuple[re.Pattern, str, tuple[str, ...], int]] = [
    (re.compile(r"-enc(odedcommand)?\b|frombase64string", re.I),
     "base64-encoded command", ("T1027", "T1059.001"), 2),
    (re.compile(r"-nop(rofile)?\b.*-w(indowstyle)?\s+hidden|-w\s+hidden", re.I),
     "hidden window and profile bypass", ("T1059.001",), 1),
    (re.compile(r"downloadstring|downloadfile|invoke-webrequest|iwr\b|curl\b|wget\b"
                r"|net\.webclient", re.I),
     "remote download cradle", ("T1105",), 2),
    (re.compile(r"iex\b|invoke-expression", re.I),
     "in-memory execution of downloaded code", ("T1059.001",), 2),
    (re.compile(r"-executionpolicy\s+bypass|-ep\s+bypass", re.I),
     "execution policy bypass", ("T1059.001",), 1),
    (re.compile(r"-urlcache|-decode\b|-encode\b", re.I),
     "certutil transfer or decode flags", ("T1105",), 2),
    (re.compile(r"lsass|sekurlsa|ntds\.dit|\bhklm\\sam\b|reg\s+save", re.I),
     "credential material access", ("T1003",), 3),
    (re.compile(r"vssadmin\s+delete|wbadmin\s+delete|bcdedit.*recoveryenabled\s+no", re.I),
     "recovery destruction", ("T1070.001",), 3),
    (re.compile(r"wevtutil\s+cl|clear-eventlog", re.I),
     "event log clearing", ("T1070.001",), 3),
    (re.compile(r"whoami|net\s+(user|group|localgroup)|nltest|systeminfo|ipconfig\s*/all", re.I),
     "host and account discovery", ("T1082", "T1087"), 0),
    (re.compile(r"\bnc\b|\bncat\b|/dev/tcp/|socat", re.I),
     "reverse shell tooling", ("T1059.004",), 2),
    (re.compile(r"/etc/(shadow|passwd|sudoers)", re.I),
     "credential file access", ("T1003.008",), 2),
    (re.compile(r"base64\s+-d|\|\s*sh\b|\|\s*bash\b", re.I),
     "decode-and-execute pipeline", ("T1059.004", "T1027"), 2),
    (re.compile(r"history\s+-c|rm\s+-rf?\s+/var/log|>\s*/var/log/", re.I),
     "log tampering", ("T1070.001",), 2),
]


def _binary_name(process: str) -> str:
    text = str(process or "").strip().strip('"')
    if not text:
        return ""
    return re.split(r"[\\/]", text)[-1].lower()


def _indicators(command_line: str) -> tuple[list[str], set[str], int]:
    notes: list[str] = []
    techniques: set[str] = set()
    bump = 0
    text = str(command_line or "")
    if not text:
        return notes, techniques, bump
    for pattern, note, tids, weight in COMMAND_INDICATORS:
        if pattern.search(text):
            notes.append(note)
            techniques.update(tids)
            bump = max(bump, weight)
    return notes, techniques, bump


def detect_windows_processes(events: pd.DataFrame,
                             config: DetectionConfig | None = None) -> list[Alert]:
    config = config or DetectionConfig()
    if events.empty:
        return []
    processes = events[events["event_type"] == PROCESS_CREATION].copy()
    if processes.empty:
        return []

    processes["_binary"] = processes["process"].map(_binary_name)
    watched = processes[processes["_binary"].isin(BINARY_INDEX)]
    if watched.empty:
        return []

    alerts: list[Alert] = []
    for (binary, username, host), group in watched.groupby(
            ["_binary", "username", "host"], sort=False):
        info = BINARY_INDEX[binary]
        commands = [c for c in group["command_line"].tolist() if c]
        notes: list[str] = []
        techniques: set[str] = set(info.mitre)
        bump = 0
        for command in commands:
            n, t, b = _indicators(command)
            notes.extend(n)
            techniques.update(t)
            bump = max(bump, b)
        notes = list(dict.fromkeys(notes))

        severity = bump_severity(info.severity, bump) if bump else info.severity
        if severity == "low" and not notes:
            # cmd.exe with an unremarkable command line: record it, do not
            # shout about it. Correlation can still pick it up later.
            severity = "low"
        if config.is_critical_asset(host) and severity in ("medium", "high"):
            severity = bump_severity(severity)

        alerts.append(Alert(
            rule_id=PROCESS_RULE_ID,
            name=f"Suspicious Process Execution: {binary}",
            severity=severity,
            category="Execution",
            description=(
                f"{len(group)} execution(s) of {binary}"
                + (f" by '{username}'" if username else "")
                + (f" on {host}" if host else "")
                + f". {info.why.capitalize()}."
                + (f" Command line indicators: {', '.join(notes)}." if notes else
                   " No suspicious command-line indicators - context only.")
                + (f" Example: {commands[0][:200]}" if commands else "")
            ),
            first_seen=group["timestamp"].min(),
            last_seen=group["timestamp"].max(),
            source_ip=next((ip for ip in group["source_ip"] if ip), ""),
            username=username,
            host=host,
            count=len(group),
            evidence=group["event_id"].tolist(),
            mitre=sorted(techniques),
            metadata={
                "binary": binary,
                "baseline_severity": info.severity,
                "indicators": notes,
                "commands": commands[:25],
                "executions": len(group),
                "critical_asset": config.is_critical_asset(host),
            },
        ))
    return alerts


def detect_linux_commands(events: pd.DataFrame,
                          config: DetectionConfig | None = None) -> list[Alert]:
    """The Linux half: commands run through sudo/su that match the indicators."""
    config = config or DetectionConfig()
    if events.empty:
        return []
    candidates = events[
        (events["event_type"] == PRIVILEGE_USE) & (events["command_line"] != "")
    ]
    if candidates.empty:
        return []

    alerts: list[Alert] = []
    for (username, host), group in candidates.groupby(["username", "host"], sort=False):
        flagged: list[tuple[pd.Series, list[str], set[str], int]] = []
        for _, row in group.iterrows():
            notes, techniques, bump = _indicators(row["command_line"])
            if notes:
                flagged.append((row, notes, techniques, bump))
        if not flagged:
            continue

        notes = list(dict.fromkeys(n for _, ns, _, _ in flagged for n in ns))
        techniques = sorted({t for _, _, ts, _ in flagged for t in ts} | {"T1059.004"})
        bump = max(b for _, _, _, b in flagged)
        severity = bump_severity("low", max(1, bump))
        if config.is_critical_asset(host):
            severity = bump_severity(severity)

        rows = pd.DataFrame([r for r, _, _, _ in flagged])
        alerts.append(Alert(
            rule_id=COMMAND_RULE_ID,
            name="Suspicious Privileged Command",
            severity=severity,
            category="Execution",
            description=(
                f"{len(flagged)} privileged command(s) run by '{username}'"
                + (f" on {host}" if host else "")
                + f" matched suspicious indicators: {', '.join(notes)}. "
                + "Commands: "
                + " | ".join(str(r["command_line"])[:100] for r, _, _, _ in flagged[:3])
            ),
            first_seen=rows["timestamp"].min(),
            last_seen=rows["timestamp"].max(),
            source_ip=next((ip for ip in rows["source_ip"] if ip), ""),
            username=username,
            host=host,
            count=len(flagged),
            evidence=rows["event_id"].astype(int).tolist(),
            mitre=techniques,
            metadata={
                "indicators": notes,
                "commands": [str(r["command_line"]) for r, _, _, _ in flagged][:25],
                "critical_asset": config.is_critical_asset(host),
            },
        ))
    return alerts


def detect(events: pd.DataFrame, config: DetectionConfig | None = None) -> list[Alert]:
    return detect_windows_processes(events, config) + detect_linux_commands(events, config)
