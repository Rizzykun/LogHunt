"""Detection 4: privilege escalation activity after a successful login.

A sudo command is not suspicious. A sudo command two minutes after a login
that itself followed 17 failures is the middle of an intrusion. This rule
supplies the link between the two by tying every privileged action back to
the session that enabled it.

It also reports the persistence-flavoured privileged events (new accounts,
group changes, cleared audit logs) on their own, because those matter whether
or not a login precedes them in the dataset.
"""
from __future__ import annotations

import re
from typing import Optional

import pandas as pd

from parser.schema import (
    AUTH_SUCCESS,
    PRIVILEGE_ASSIGNED,
    PRIVILEGE_USE,
    SESSION_OPEN,
)

from .base import Alert, DetectionConfig

ESCALATION_RULE_ID = "LH-005"
PERSISTENCE_RULE_ID = "LH-006"
FAILED_ESCALATION_RULE_ID = "LH-007"

PRIVILEGE_TYPES = (PRIVILEGE_USE, PRIVILEGE_ASSIGNED)
LOGIN_TYPES = (AUTH_SUCCESS, SESSION_OPEN)

# Windows event IDs that describe persistence rather than routine elevation.
PERSISTENCE_EVENT_CODES = {
    "4720": ("Local account created", ["T1136.001"], "high"),
    "4724": ("Account password reset by another user", ["T1098"], "medium"),
    "4732": ("Account added to a privileged local group", ["T1098"], "high"),
    "1102": ("Security audit log cleared", ["T1070.001"], "critical"),
}

# Commands worth calling out inside a sudo/root session.
SENSITIVE_COMMAND_PATTERNS: list[tuple[re.Pattern, str, list[str]]] = [
    (re.compile(r"/etc/(shadow|passwd|sudoers)"), "access to credential files",
     ["T1003.008"]),
    (re.compile(r"\b(useradd|adduser|usermod|groupadd)\b"), "account creation or change",
     ["T1136.001"]),
    (re.compile(r"\b(curl|wget)\b"), "file download inside a privileged session",
     ["T1105"]),
    (re.compile(r"\b(nc|ncat|netcat|socat)\b"), "network listener or reverse shell tooling",
     ["T1059.004"]),
    (re.compile(r"\bchmod\s+(777|\+s)\b"), "permissive or setuid permission change",
     ["T1548.003"]),
    (re.compile(r"\b(history\s+-c|rm\s+-rf?\s+/var/log|truncate.*log)"), "log tampering",
     ["T1070.001"]),
    (re.compile(r"\bcrontab\b|/etc/cron"), "scheduled task change", ["T1053.005"]),
]


def _techniques_for(row: pd.Series) -> list[str]:
    code = str(row.get("event_code") or "")
    if code in PERSISTENCE_EVENT_CODES:
        return list(PERSISTENCE_EVENT_CODES[code][1])
    if code == "4672":
        return ["T1078"]
    process = str(row.get("process") or "").lower()
    if "sudo" in process or "su" in process.split("/"):
        return ["T1548.003"]
    if any(p in process for p in ("useradd", "adduser", "usermod", "groupadd")):
        return ["T1136.001"]
    return ["T1078"]


def _sensitive_notes(commands: list[str]) -> tuple[list[str], list[str]]:
    notes: list[str] = []
    techniques: list[str] = []
    joined = " ; ".join(commands).lower()
    for pattern, note, tids in SENSITIVE_COMMAND_PATTERNS:
        if pattern.search(joined):
            notes.append(note)
            techniques.extend(tids)
    return notes, techniques


def _last_login_before(logins: pd.DataFrame, username: str, ts: pd.Timestamp,
                       window: pd.Timedelta) -> Optional[pd.Series]:
    candidates = logins[
        (logins["username"] == username)
        & (logins["timestamp"] <= ts)
        & (logins["timestamp"] >= ts - window)
    ]
    if candidates.empty:
        return None
    login = candidates.iloc[-1].copy()
    if not login["source_ip"]:
        # An SSH login writes two lines: "Accepted password ... from <ip>" and
        # a PAM session line that carries no address. The PAM line is the later
        # of the two, so backfill the address from the session it belongs to -
        # otherwise the alert loses the attacker's IP.
        with_ip = candidates[candidates["source_ip"] != ""]
        if not with_ip.empty:
            login["source_ip"] = with_ip.iloc[-1]["source_ip"]
    return login


def detect_escalation(events: pd.DataFrame,
                      config: DetectionConfig | None = None) -> list[Alert]:
    config = config or DetectionConfig()
    if events.empty:
        return []

    priv = events[
        events["event_type"].isin(PRIVILEGE_TYPES)
        & (events["status"] != "failure")
        & events["timestamp"].notna()
    ].sort_values("timestamp", kind="stable")
    logins = events[
        events["event_type"].isin(LOGIN_TYPES) & events["timestamp"].notna()
    ].sort_values("timestamp", kind="stable")
    if priv.empty or logins.empty:
        return []

    window = pd.Timedelta(minutes=config.priv_window_minutes)
    alerts: list[Alert] = []

    for username, group in priv.groupby("username", sort=False):
        if not username:
            continue
        # Attribute each privileged action to the session that preceded it and
        # collapse all actions from one session into a single alert.
        sessions: dict[pd.Timestamp, list[int]] = {}
        for idx, row in group.iterrows():
            login = _last_login_before(logins, username, row["timestamp"], window)
            if login is None:
                continue
            sessions.setdefault(login["timestamp"], []).append(idx)

        for login_ts, indices in sessions.items():
            actions = group.loc[indices]
            login = _last_login_before(logins, username, actions["timestamp"].min(), window)
            if login is None:
                continue
            commands = [c for c in actions["command_line"].tolist() if c]
            notes, extra_techniques = _sensitive_notes(commands)
            techniques = {"T1078"}
            for _, row in actions.iterrows():
                techniques.update(_techniques_for(row))
            techniques.update(extra_techniques)

            source_ip = login["source_ip"] or (actions["source_ip"].iloc[0] or "")
            host = login["host"] or (actions["host"].iloc[0] or "")
            external = bool(source_ip) and not config.is_internal_ip(source_ip)
            delay = (actions["timestamp"].min() - login_ts).total_seconds()

            # An administrator using sudo is the most common thing in an auth
            # log, so the floor is deliberately low: this rule exists to supply
            # context to a chain, not to page anyone on its own. What lifts it
            # is a sensitive command or a login from outside the network.
            severity = "low"
            if config.is_privileged_user(username):
                severity = "medium"
            if notes or external:
                severity = "high"
            if notes and external:
                severity = "critical"
            if config.is_critical_asset(host) and severity == "high":
                severity = "critical"

            described = commands[:3] or actions["action"].unique().tolist()[:3]
            alerts.append(Alert(
                rule_id=ESCALATION_RULE_ID,
                name="Privilege Escalation Activity",
                severity=severity,
                category="Privilege Escalation",
                description=(
                    f"'{username}' logged in at {login_ts:%H:%M:%S}"
                    + (f" from {source_ip}" if source_ip else "")
                    + f" and performed {len(actions)} privileged action(s) starting "
                      f"{delay:.0f}s later"
                    + (f" on {host}" if host else "")
                    + ". "
                    + (f"Noted: {'; '.join(notes)}. " if notes else "")
                    + "Actions: " + " | ".join(str(c)[:120] for c in described)
                ),
                first_seen=login_ts,
                last_seen=actions["timestamp"].max(),
                source_ip=source_ip,
                username=username,
                host=host,
                count=len(actions),
                evidence=[int(login["event_id"])] + actions["event_id"].tolist(),
                mitre=sorted(techniques),
                metadata={
                    "login_time": str(login_ts),
                    "seconds_from_login": round(delay, 1),
                    "privileged_actions": len(actions),
                    "commands": commands[:25],
                    "sensitive_activity": notes,
                    "external_source": external,
                    "privileged_account": config.is_privileged_user(username),
                    "critical_asset": config.is_critical_asset(host),
                },
            ))
    return alerts


def detect_persistence(events: pd.DataFrame,
                       config: DetectionConfig | None = None) -> list[Alert]:
    """Account creation, group changes and cleared logs, reported on their own."""
    config = config or DetectionConfig()
    if events.empty:
        return []

    alerts: list[Alert] = []
    codes = events["event_code"].astype(str)
    for code, (label, techniques, severity) in PERSISTENCE_EVENT_CODES.items():
        matching = events[codes == code]
        for _, row in matching.iterrows():
            alerts.append(_persistence_alert(row, label, techniques, severity, config))

    # Linux equivalent: useradd / groupadd / usermod in auth.log.
    linux_mask = (
        events["event_type"].isin(PRIVILEGE_TYPES)
        & events["process"].str.contains("useradd|adduser|usermod|groupadd", case=False,
                                         na=False, regex=True)
    )
    for _, row in events[linux_mask].iterrows():
        alert = _persistence_alert(
            row, "Local account created or modified", ["T1136.001"], "high", config)
        _attribute_account_creation(alert, row, events)
        alerts.append(alert)
    return alerts


def _attribute_account_creation(alert: Alert, row: pd.Series,
                                events: pd.DataFrame) -> None:
    """Name the account that *ran* useradd, not the account it created.

    ``useradd[2001]: new user: name=svc_backup`` records the new account and
    nothing about who made it, so the alert would otherwise be attributed to a
    username that did not exist a second earlier - and would never correlate
    into the chain that created it. The matching sudo line, moments before on
    the same host, does name the actor.
    """
    created = alert.username
    if not created or row["timestamp"] is None or pd.isna(row["timestamp"]):
        return
    window = pd.Timedelta(minutes=2)
    actors = events[
        (events["event_type"] == PRIVILEGE_USE)
        & (events["host"] == row["host"])
        & (events["timestamp"] <= row["timestamp"])
        & (events["timestamp"] >= row["timestamp"] - window)
        & events["command_line"].str.contains("useradd|adduser|usermod|groupadd",
                                              case=False, na=False, regex=True)
    ]
    if actors.empty:
        alert.metadata["created_account"] = created
        alert.metadata["actor"] = "not recorded in the log"
        return

    actor = actors.iloc[-1]
    alert.username = actor["username"]
    alert.source_ip = alert.source_ip or actor["source_ip"]
    alert.evidence = sorted(set(alert.evidence + [int(actor["event_id"])]))
    alert.metadata["created_account"] = created
    alert.metadata["actor"] = actor["username"]
    alert.metadata["actor_command"] = actor["command_line"]
    alert.description = (
        f"Account '{created}' was created on {row['host']} by '{actor['username']}' via "
        f"{actor['command_line']}. A new account appearing during an intrusion is the "
        f"usual way access is kept after the original hole is closed."
    )


def _persistence_alert(row: pd.Series, label: str, techniques: list[str],
                       severity: str, config: DetectionConfig) -> Alert:
    username = row["username"]
    host = row["host"]
    if config.is_critical_asset(host) and severity == "high":
        severity = "critical"
    return Alert(
        rule_id=PERSISTENCE_RULE_ID,
        name="Account or Audit Policy Manipulation",
        severity=severity,
        category="Persistence",
        description=(
            f"{label}"
            + (f" involving '{username}'" if username else "")
            + (f" on {host}" if host else "")
            + f". Raw action: {str(row['action'])[:120]}."
        ),
        first_seen=row["timestamp"],
        last_seen=row["timestamp"],
        source_ip=row["source_ip"],
        username=username,
        host=host,
        count=1,
        evidence=[int(row["event_id"])],
        mitre=techniques,
        metadata={
            "event_code": str(row.get("event_code") or ""),
            "process": str(row.get("process") or ""),
            "detail": label,
            "critical_asset": config.is_critical_asset(host),
        },
    )


def detect_failed_escalation(events: pd.DataFrame,
                             config: DetectionConfig | None = None) -> list[Alert]:
    """Denied sudo / not-in-sudoers attempts - escalation that did not land."""
    config = config or DetectionConfig()
    if events.empty:
        return []
    failed = events[
        (events["event_type"] == PRIVILEGE_USE) & (events["status"] == "failure")
    ]
    if failed.empty:
        return []

    alerts: list[Alert] = []
    for (username, host), group in failed.groupby(["username", "host"], sort=False):
        alerts.append(Alert(
            rule_id=FAILED_ESCALATION_RULE_ID,
            name="Failed Privilege Escalation Attempt",
            severity="medium" if len(group) < 3 else "high",
            category="Privilege Escalation",
            description=(
                f"{len(group)} denied privilege escalation attempt(s) by '{username}'"
                + (f" on {host}" if host else "")
                + ". Either a misconfiguration or an account probing what it can reach."
            ),
            first_seen=group["timestamp"].min(),
            last_seen=group["timestamp"].max(),
            source_ip=(group["source_ip"].iloc[0] or ""),
            username=username,
            host=host,
            count=len(group),
            evidence=group["event_id"].tolist(),
            mitre=["T1548.003"],
            metadata={"attempts": len(group)},
        ))
    return alerts


def detect(events: pd.DataFrame, config: DetectionConfig | None = None) -> list[Alert]:
    return (detect_escalation(events, config)
            + detect_persistence(events, config)
            + detect_failed_escalation(events, config))
