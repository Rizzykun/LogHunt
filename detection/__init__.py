"""Detection engine: runs every rule over a normalized event frame.

Six detection families, eleven rules. Families map to the project's design;
the extra rules are variants that were cheap once the normalized schema
existed (spraying alongside guessing, scanning alongside exploitation).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

import pandas as pd

from . import brute_force, privilege, suspicious_login, suspicious_process, web_attack
from .base import (
    SEVERITIES,
    SEVERITY_RANK,
    Alert,
    DetectionConfig,
    alerts_to_frame,
    max_severity,
)

__all__ = [
    "Alert",
    "DetectionConfig",
    "RULE_CATALOG",
    "alerts_to_frame",
    "run_all",
    "SEVERITIES",
    "SEVERITY_RANK",
    "max_severity",
]


@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    family: str
    name: str
    logic: str
    log_sources: tuple[str, ...]
    mitre: tuple[str, ...]


# Documentation for the dashboard's rule list - kept beside the code so the
# two cannot drift apart.
RULE_CATALOG: tuple[RuleInfo, ...] = (
    RuleInfo("LH-001", "Brute force", "Brute Force Authentication Attempts",
             "5+ failed authentications against one account from one source IP within 5 minutes",
             ("Linux auth", "Windows Security"), ("T1110.001", "T1110")),
    RuleInfo("LH-002", "Brute force", "Possible Password Spraying",
             "5+ failures from one source IP spread across 5+ distinct accounts in the window",
             ("Linux auth", "Windows Security"), ("T1110.003", "T1110")),
    RuleInfo("LH-003", "Login after brute force", "Possible Account Compromise",
             "A successful authentication within 10 minutes of a burst of failures from the "
             "same source IP",
             ("Linux auth", "Windows Security"), ("T1110", "T1078")),
    RuleInfo("LH-004", "Anomalous login source", "Anomalous Login Source",
             "A successful login from a /24 outside the networks covering 80% of that "
             "account's own login history",
             ("Linux auth", "Windows Security"), ("T1078",)),
    RuleInfo("LH-005", "Privilege escalation", "Privilege Escalation Activity",
             "Privileged actions (sudo, 4672, account changes) within 15 minutes of a "
             "successful login by the same account",
             ("Linux auth", "Windows Security"), ("T1078", "T1548.003")),
    RuleInfo("LH-006", "Privilege escalation", "Account or Audit Policy Manipulation",
             "Account creation, privileged group changes, or a cleared security log",
             ("Linux auth", "Windows Security"), ("T1136.001", "T1098", "T1070.001")),
    RuleInfo("LH-007", "Privilege escalation", "Failed Privilege Escalation Attempt",
             "Denied sudo or not-in-sudoers events",
             ("Linux auth",), ("T1548.003",)),
    RuleInfo("LH-008", "Web attack", "Suspected Web Attack",
             "Eight signature classes matched against doubly URL-decoded requests; severity "
             "rises when the response was 2xx",
             ("Web access",), ("T1190", "T1083", "T1059", "T1505.003")),
    RuleInfo("LH-009", "Web attack", "Possible Content Discovery Scan",
             "20+ HTTP 404s from one source in 5 minutes, or a self-identifying scanner UA",
             ("Web access",), ("T1595.003", "T1046")),
    RuleInfo("LH-010", "Suspicious process", "Suspicious Process Execution",
             "Watched interpreters and LOLBins from event ID 4688; command-line indicators "
             "(encoding, download cradles, credential access) raise severity",
             ("Windows Security",), ("T1059.001", "T1059.003", "T1105", "T1003")),
    RuleInfo("LH-011", "Suspicious process", "Suspicious Privileged Command",
             "The same command-line indicators applied to commands run via sudo",
             ("Linux auth",), ("T1059.004", "T1003.008", "T1105")),
)

RULE_FAMILIES = tuple(dict.fromkeys(r.family for r in RULE_CATALOG))

DetectFn = Callable[[pd.DataFrame, Optional[DetectionConfig]], list[Alert]]

RULE_MODULES: tuple[DetectFn, ...] = (
    brute_force.detect,
    suspicious_login.detect,
    privilege.detect,
    web_attack.detect,
    suspicious_process.detect,
)


def run_all(events: pd.DataFrame, config: Optional[DetectionConfig] = None) -> list[Alert]:
    """Run every rule, then sort and label the findings.

    Scoring is deliberately left to ``scoring.risk`` / ``correlation.engine``:
    a rule decides *what* it found, not how much it should worry anyone.
    """
    config = config or DetectionConfig()
    if events is None or events.empty:
        return []

    alerts: list[Alert] = []
    for detect in RULE_MODULES:
        try:
            alerts.extend(detect(events, config))
        except Exception as exc:  # a broken rule must not lose the other ten
            alerts.append(Alert(
                rule_id="LH-000",
                name="Detection rule error",
                severity="info",
                category="Toolkit",
                description=f"{detect.__module__} raised {type(exc).__name__}: {exc}",
            ))

    alerts.sort(key=lambda a: (a.first_seen is None, a.first_seen,
                               -SEVERITY_RANK.get(a.severity, 0)))
    for i, alert in enumerate(alerts, start=1):
        alert.alert_id = f"LH-A-{i:04d}"
    return alerts
