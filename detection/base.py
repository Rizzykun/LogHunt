"""Shared pieces every detection rule uses: the Alert type and tuning config."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Optional, Sequence

import pandas as pd

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Accounts whose compromise matters more than an ordinary user's. Matched
# case-insensitively, exactly or by prefix for service accounts.
DEFAULT_PRIVILEGED_USERS = (
    "root", "admin", "administrator", "sysadmin", "dbadmin", "backup",
    "svc_", "sa", "oracle", "postgres", "jenkins", "domain admin",
)

# Hosts an analyst would treat as crown jewels. In a real deployment this
# comes from a CMDB; here it is a list you edit per environment.
DEFAULT_CRITICAL_ASSETS = ("dc01", "db-01", "db01", "vault", "pay", "fin")


@dataclass
class DetectionConfig:
    """Thresholds for every rule, in one place so the UI can tune them."""

    # Detection 1: brute force
    bf_failure_threshold: int = 5
    bf_window_minutes: int = 5
    # Detection 1b: password spraying
    spray_distinct_users: int = 5
    # Detection 2: success after brute force
    compromise_window_minutes: int = 10
    # Detection 3: anomalous login source
    baseline_min_logins: int = 5
    baseline_rare_max_count: int = 2
    internal_networks: tuple[str, ...] = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    # Detection 4: privilege escalation
    priv_window_minutes: int = 15
    # Detection 5: web attack
    scan_404_threshold: int = 20
    scan_window_minutes: int = 5
    # Correlation: the largest gap allowed between two alerts in one chain.
    # 30 minutes keeps an intrusion together (its stages are minutes apart)
    # without chaining a whole day of routine admin work into one "incident".
    correlation_window_minutes: int = 30
    # Environment context, feeds risk scoring
    privileged_users: tuple[str, ...] = DEFAULT_PRIVILEGED_USERS
    critical_assets: tuple[str, ...] = DEFAULT_CRITICAL_ASSETS

    def is_privileged_user(self, username: str) -> bool:
        if not username:
            return False
        name = str(username).strip().lower().rstrip("$")
        for candidate in self.privileged_users:
            candidate = candidate.lower()
            if name == candidate or (candidate.endswith("_") and name.startswith(candidate)):
                return True
        return False

    def is_critical_asset(self, host: str) -> bool:
        if not host:
            return False
        name = str(host).strip().lower()
        return any(marker in name for marker in self.critical_assets)

    def is_internal_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(str(ip))
        except ValueError:
            return False
        return any(addr in ipaddress.ip_network(net) for net in self.internal_networks)


@dataclass
class Alert:
    """One detection finding, with the evidence that produced it."""

    rule_id: str
    name: str
    severity: str
    category: str                     # ATT&CK tactic, for grouping
    description: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    source_ip: str = ""
    username: str = ""
    host: str = ""
    count: int = 1
    evidence: list[int] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    # Filled in later by scoring/risk.py and correlation/engine.py
    alert_id: str = ""
    risk: int = 0
    risk_band: str = ""
    risk_factors: dict[str, Any] = field(default_factory=dict)
    incident_id: str = ""

    @property
    def duration_minutes(self) -> float:
        if not self.first_seen or not self.last_seen:
            return 0.0
        return (self.last_seen - self.first_seen).total_seconds() / 60.0

    def to_row(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "risk": self.risk,
            "risk_band": self.risk_band,
            "category": self.category,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "source_ip": self.source_ip,
            "username": self.username,
            "host": self.host,
            "count": self.count,
            "mitre": ", ".join(self.mitre),
            "incident_id": self.incident_id,
            "description": self.description,
            "evidence_count": len(self.evidence),
        }


def alerts_to_frame(alerts: Iterable[Alert]) -> pd.DataFrame:
    rows = [a.to_row() for a in alerts]
    columns = [
        "alert_id", "rule_id", "name", "severity", "risk", "risk_band", "category",
        "first_seen", "last_seen", "source_ip", "username", "host", "count",
        "mitre", "incident_id", "description", "evidence_count",
    ]
    frame = pd.DataFrame(rows, columns=columns)
    if not frame.empty:
        frame["first_seen"] = pd.to_datetime(frame["first_seen"], errors="coerce")
        frame["last_seen"] = pd.to_datetime(frame["last_seen"], errors="coerce")
    return frame


def max_severity(severities: Sequence[str]) -> str:
    if not severities:
        return "info"
    return max(severities, key=lambda s: SEVERITY_RANK.get(s, 0))


def bump_severity(severity: str, steps: int = 1) -> str:
    idx = min(len(SEVERITIES) - 1, SEVERITY_RANK.get(severity, 0) + steps)
    return SEVERITIES[idx]


def window_bursts(timestamps: Sequence[pd.Timestamp], threshold: int,
                  window_minutes: int) -> list[tuple[int, int]]:
    """Find index ranges where >= ``threshold`` events fall inside the window.

    Returns ``(start, end)`` index pairs (inclusive) into the *sorted* input.
    A single sliding window over sorted timestamps, so consecutive bursts
    merge into one range instead of firing an alert per attempt.
    """
    n = len(timestamps)
    if n < threshold:
        return []
    window = pd.Timedelta(minutes=window_minutes)
    bursts: list[tuple[int, int]] = []
    left = 0
    current: Optional[list[int]] = None
    for right in range(n):
        while timestamps[right] - timestamps[left] > window:
            left += 1
        if right - left + 1 >= threshold:
            if current is None:
                current = [left, right]
            else:
                if left <= current[1]:      # overlaps the burst in progress
                    current[1] = right
                else:
                    bursts.append((current[0], current[1]))
                    current = [left, right]
    if current is not None:
        bursts.append((current[0], current[1]))
    return bursts
