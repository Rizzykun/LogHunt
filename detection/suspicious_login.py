"""Detections 2 and 3: successful login after brute force, and odd login sources.

Detection 2 is the one that turns noise into an incident. A brute force alert
on its own is background radiation on any internet-facing host; a brute force
followed by a *successful* login from the same source is a possible account
compromise and deserves an analyst.

Detection 3 baselines each account's own login history instead of using
geolocation, which a log file cannot support on its own.
"""
from __future__ import annotations

import ipaddress
from typing import Optional

import pandas as pd

from parser.schema import AUTH_FAILURE, AUTH_INVALID_USER, AUTH_SUCCESS, SESSION_OPEN

from .base import Alert, DetectionConfig

COMPROMISE_RULE_ID = "LH-003"
ANOMALOUS_SOURCE_RULE_ID = "LH-004"

FAILURE_TYPES = (AUTH_FAILURE, AUTH_INVALID_USER)
SUCCESS_TYPES = (AUTH_SUCCESS,)


def _network_of(ip: str) -> Optional[str]:
    """Collapse an address to its /24 (or /64) so a baseline can generalise."""
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    prefix = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))


def detect_compromise(events: pd.DataFrame,
                      config: DetectionConfig | None = None) -> list[Alert]:
    """Successful authentication shortly after a run of failures from one IP."""
    config = config or DetectionConfig()
    if events.empty:
        return []

    auth = events[
        events["event_type"].isin(FAILURE_TYPES + SUCCESS_TYPES)
        & events["timestamp"].notna()
        & (events["source_ip"] != "")
    ].sort_values("timestamp", kind="stable")
    if auth.empty:
        return []

    window = pd.Timedelta(minutes=config.compromise_window_minutes)
    alerts: list[Alert] = []

    for source_ip, group in auth.groupby("source_ip", sort=False):
        successes = group[group["event_type"].isin(SUCCESS_TYPES)]
        if successes.empty:
            continue
        failures = group[group["event_type"].isin(FAILURE_TYPES)]
        if failures.empty:
            continue

        for _, success in successes.iterrows():
            ts = success["timestamp"]
            preceding = failures[
                (failures["timestamp"] <= ts) & (failures["timestamp"] >= ts - window)
            ]
            if len(preceding) < config.bf_failure_threshold:
                continue

            username = success["username"]
            same_account = preceding[preceding["username"] == username]
            host = success["host"]
            first = preceding["timestamp"].min()
            evidence = preceding["event_id"].tolist() + [int(success["event_id"])]

            # Failures against the very account that then succeeded is the
            # strong case; failures against other accounts still matter but
            # are weaker evidence, so they are reported as such.
            if len(same_account) >= config.bf_failure_threshold:
                severity = "critical"
                confidence = "high"
                detail = (
                    f"{len(same_account)} failed attempts against '{username}' from "
                    f"{source_ip} were followed by a successful authentication as the "
                    f"same account"
                )
            else:
                severity = "high"
                confidence = "medium"
                detail = (
                    f"{len(preceding)} failed attempts from {source_ip} (against "
                    f"{preceding['username'].nunique()} account(s)) were followed by a "
                    f"successful authentication as '{username}'"
                )

            gap = (ts - preceding["timestamp"].max()).total_seconds()
            alerts.append(Alert(
                rule_id=COMPROMISE_RULE_ID,
                name="Possible Account Compromise",
                severity=severity,
                category="Credential Access",
                description=(
                    f"{detail} at {ts:%Y-%m-%d %H:%M:%S}"
                    + (f" on {host}" if host else "")
                    + f". Gap between the last failure and the success: {gap:.0f}s."
                ),
                first_seen=first,
                last_seen=ts,
                source_ip=source_ip,
                username=username,
                host=host,
                count=len(preceding) + 1,
                evidence=evidence,
                mitre=["T1110", "T1078"],
                metadata={
                    "failed_attempts": int(len(preceding)),
                    "failed_attempts_same_account": int(len(same_account)),
                    "seconds_to_success": round(gap, 1),
                    "confidence": confidence,
                    "privileged_account": config.is_privileged_user(username),
                    "logon_type": success.get("logon_type", "") or "",
                },
            ))
    return alerts


def detect_anomalous_source(events: pd.DataFrame,
                            config: DetectionConfig | None = None) -> list[Alert]:
    """Successful login from a network the account has essentially never used.

    The baseline is the account's own history inside the same dataset: the
    networks that account for most of its successful logins. A source outside
    that set, seen only once or twice, is what an analyst would want to look at.
    """
    config = config or DetectionConfig()
    if events.empty:
        return []

    logins = events[
        events["event_type"].isin((AUTH_SUCCESS, SESSION_OPEN))
        & (events["username"] != "")
        & (events["source_ip"] != "")
        & events["timestamp"].notna()
    ].copy()
    if logins.empty:
        return []

    logins["network"] = logins["source_ip"].map(_network_of)
    logins = logins[logins["network"].notna()]
    if logins.empty:
        return []

    alerts: list[Alert] = []
    for username, group in logins.groupby("username", sort=False):
        if len(group) < config.baseline_min_logins:
            # Too little history to call anything unusual for this account.
            continue
        counts = group["network"].value_counts()
        # Baseline = the networks covering 80% of this account's logins.
        cumulative = counts.cumsum() / counts.sum()
        baseline = set(counts.index[: max(1, int((cumulative < 0.8).sum()) + 1)])

        for network, rare in group.groupby("network", sort=False):
            if network in baseline:
                continue
            if len(rare) > config.baseline_rare_max_count:
                continue
            ips = sorted(set(rare["source_ip"]))
            external = [ip for ip in ips if not config.is_internal_ip(ip)]
            severity = "high" if external else "medium"
            if config.is_privileged_user(username) and severity == "medium":
                severity = "high"

            share = len(rare) / len(group) * 100
            alerts.append(Alert(
                rule_id=ANOMALOUS_SOURCE_RULE_ID,
                name="Anomalous Login Source",
                severity=severity,
                category="Valid Accounts",
                description=(
                    f"'{username}' authenticated from {', '.join(ips)} ({network}), a network "
                    f"outside this account's normal pattern. Baseline for the account: "
                    f"{', '.join(sorted(baseline))} "
                    f"({len(group)} logins observed, this source is {share:.1f}% of them)."
                    + ("" if not external else " The source is not in the configured internal"
                                              " ranges.")
                ),
                first_seen=rare["timestamp"].min(),
                last_seen=rare["timestamp"].max(),
                source_ip=ips[0],
                username=username,
                host=(rare["host"].iloc[0] if len(rare) else ""),
                count=len(rare),
                evidence=rare["event_id"].tolist(),
                mitre=["T1078"],
                metadata={
                    "baseline_networks": sorted(baseline),
                    "observed_network": network,
                    "source_ips": ips,
                    "account_logins_in_dataset": int(len(group)),
                    "external_source": bool(external),
                    "privileged_account": config.is_privileged_user(username),
                },
            ))
    return alerts


def detect(events: pd.DataFrame, config: DetectionConfig | None = None) -> list[Alert]:
    return detect_compromise(events, config) + detect_anomalous_source(events, config)
