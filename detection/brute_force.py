"""Detection 1: authentication brute force, and its password-spraying variant.

Works on the normalized ``auth_failure`` / ``auth_invalid_user`` event types,
so one rule covers SSH (Linux) and event ID 4625/4771 (Windows) at once.
"""
from __future__ import annotations

import pandas as pd

from parser.schema import AUTH_FAILURE, AUTH_INVALID_USER

from .base import Alert, DetectionConfig, window_bursts

RULE_ID = "LH-001"
SPRAY_RULE_ID = "LH-002"

FAILURE_TYPES = (AUTH_FAILURE, AUTH_INVALID_USER)


def _failures(events: pd.DataFrame) -> pd.DataFrame:
    if events.empty:
        return events
    mask = events["event_type"].isin(FAILURE_TYPES) & events["timestamp"].notna()
    return events[mask]


def detect(events: pd.DataFrame, config: DetectionConfig | None = None) -> list[Alert]:
    config = config or DetectionConfig()
    failures = _failures(events)
    if failures.empty:
        return []

    alerts: list[Alert] = []
    for source_ip, group in failures.groupby("source_ip", sort=False):
        if not source_ip:
            # Some log formats omit the client address; an IP-keyed rule
            # cannot speak to those, and guessing would invent evidence.
            continue
        group = group.sort_values("timestamp", kind="stable")
        stamps = list(group["timestamp"])
        for start, end in window_bursts(stamps, config.bf_failure_threshold,
                                        config.bf_window_minutes):
            burst = group.iloc[start:end + 1]
            alerts.extend(_alerts_for_burst(burst, source_ip, config))
    return alerts


def _alerts_for_burst(burst: pd.DataFrame, source_ip: str,
                      config: DetectionConfig) -> list[Alert]:
    attempts = len(burst)
    users = [u for u in burst["username"].unique().tolist() if u]
    hosts = [h for h in burst["host"].unique().tolist() if h]
    first, last = burst["timestamp"].min(), burst["timestamp"].max()
    span = max(1, round((last - first).total_seconds() / 60))
    evidence = burst["event_id"].tolist()
    privileged = [u for u in users if config.is_privileged_user(u)]
    invalid_only = bool((burst["event_type"] == AUTH_INVALID_USER).all())

    spraying = len(users) >= config.spray_distinct_users
    if spraying:
        severity = "high" if privileged else "medium"
        return [Alert(
            rule_id=SPRAY_RULE_ID,
            name="Possible Password Spraying",
            severity=severity,
            category="Credential Access",
            description=(
                f"{attempts} failed authentication attempts from {source_ip} spread across "
                f"{len(users)} accounts within {span} minute(s) - a spraying pattern rather "
                f"than guessing one password."
            ),
            first_seen=first,
            last_seen=last,
            source_ip=source_ip,
            username=privileged[0] if privileged else "",
            host=hosts[0] if hosts else "",
            count=attempts,
            evidence=evidence,
            mitre=["T1110.003", "T1110"],
            metadata={
                "attempts": attempts,
                "window_minutes": span,
                "targeted_users": users[:25],
                "distinct_users": len(users),
                "targeted_hosts": hosts,
                "privileged_targets": privileged,
            },
        )]

    # Single-account guessing: one alert per targeted account keeps the
    # investigation answerable ("was THIS account compromised?").
    alerts: list[Alert] = []
    for username, per_user in burst.groupby("username", sort=False):
        user_attempts = len(per_user)
        if user_attempts < config.bf_failure_threshold:
            continue
        u_first, u_last = per_user["timestamp"].min(), per_user["timestamp"].max()
        u_span = max(1, round((u_last - u_first).total_seconds() / 60))
        rate = user_attempts / max(1.0, (u_last - u_first).total_seconds() / 60.0)
        severity = "medium"
        if user_attempts >= config.bf_failure_threshold * 3 or rate >= 10:
            severity = "high"
        if config.is_privileged_user(username) and severity == "medium":
            severity = "high"

        target = username or "(unknown account)"
        alerts.append(Alert(
            rule_id=RULE_ID,
            name="Brute Force Authentication Attempts",
            severity=severity,
            category="Credential Access",
            description=(
                f"{user_attempts} failed authentication attempts against '{target}' from "
                f"{source_ip} within {u_span} minute(s) "
                f"({rate:.1f} attempts/minute)."
                + (" The account does not exist on the target, which reads as account"
                   " enumeration." if invalid_only else "")
            ),
            first_seen=u_first,
            last_seen=u_last,
            source_ip=source_ip,
            username=username,
            host=(per_user["host"].iloc[0] if len(per_user) else ""),
            count=user_attempts,
            evidence=per_user["event_id"].tolist(),
            mitre=["T1110.001", "T1110"],
            metadata={
                "attempts": user_attempts,
                "window_minutes": u_span,
                "attempts_per_minute": round(rate, 2),
                "targeted_hosts": [h for h in per_user["host"].unique().tolist() if h],
                "account_exists": not invalid_only,
                "privileged_account": config.is_privileged_user(username),
            },
        ))
    return alerts
