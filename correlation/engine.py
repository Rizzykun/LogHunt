"""Event correlation: alerts in, incidents out.

An alert queue asks "what fired?". An investigation asks "what happened?".
This module answers the second question by grouping alerts that share an
entity (source IP, account, or host) and sit close together in time, then
ordering the group along the stages of an intrusion.

Grouping uses linking keys rather than comparing every alert to every other:
for each entity, alerts are sorted by time and linked when the gap between
one ending and the next starting is inside the correlation window.

The linking keys are source IP and account, deliberately *not* host. Host was
tried first and over-merged badly - on a busy server every unrelated alert of
the afternoon collapsed into one 10-hour "incident". IP and account still
carry a chain across log sources: the attacker's address ties the web
exploitation to the SSH brute force, and the account ties the Windows process
events (which carry no client address) back to the logon that spawned them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Optional

import pandas as pd

from detection.base import Alert, DetectionConfig, max_severity
from detection import mitre
from scoring import risk as risk_scoring

# Stages of an intrusion, roughly in the order they occur. The order is only a
# tiebreaker: a chain is presented in the order it was actually observed, since
# a real intruder does not follow the diagram.
STAGE_DEFINITIONS: tuple[tuple[str, frozenset[str]], ...] = (
    ("Reconnaissance", frozenset({"LH-009"})),
    ("Exploitation Attempt", frozenset({"LH-008"})),
    ("Credential Attack", frozenset({"LH-001", "LH-002"})),
    ("Successful Access", frozenset({"LH-003", "LH-004"})),
    ("Privilege Escalation", frozenset({"LH-005", "LH-007"})),
    ("Execution", frozenset({"LH-010", "LH-011"})),
    ("Persistence / Defense Evasion", frozenset({"LH-006"})),
)

STAGE_ORDER = {name: i for i, (name, _) in enumerate(STAGE_DEFINITIONS)}
RULE_TO_STAGE = {
    rule_id: name for name, rule_ids in STAGE_DEFINITIONS for rule_id in rule_ids
}


@dataclass
class Incident:
    """A correlated set of alerts that tell one story."""

    incident_id: str
    title: str
    alerts: list[Alert]
    risk: int = 0
    risk_band: str = ""
    severity: str = "info"
    risk_breakdown: dict[str, Any] = field(default_factory=dict)
    source_ips: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    log_sources: list[str] = field(default_factory=list)
    event_ids: list[int] = field(default_factory=list)
    stages: list[tuple[str, list[str]]] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)

    @property
    def first_seen(self) -> Optional[datetime]:
        stamps = [a.first_seen for a in self.alerts if a.first_seen is not None]
        return min(stamps) if stamps else None

    @property
    def last_seen(self) -> Optional[datetime]:
        stamps = [a.last_seen or a.first_seen for a in self.alerts if a.last_seen or a.first_seen]
        return max(stamps) if stamps else None

    @property
    def duration_minutes(self) -> float:
        if not self.first_seen or not self.last_seen:
            return 0.0
        return (self.last_seen - self.first_seen).total_seconds() / 60.0

    @property
    def stage_names(self) -> list[str]:
        return [name for name, _ in self.stages]

    @property
    def tactics(self) -> list[str]:
        return mitre.tactics_for(self.mitre)

    def chain(self) -> list[str]:
        return self.stage_names

    def summary(self) -> str:
        """One paragraph an analyst could paste into a ticket."""
        who = ", ".join(self.usernames[:3]) or "no account attributed"
        where = ", ".join(self.hosts[:3]) or "unknown host"
        src = ", ".join(self.source_ips[:3]) or "no source address"
        window = ""
        if self.first_seen and self.last_seen:
            window = (f" between {self.first_seen:%Y-%m-%d %H:%M:%S} and "
                      f"{self.last_seen:%H:%M:%S} ({self.duration_minutes:.0f} minutes)")
        return (
            f"{self.title}: {len(self.alerts)} correlated alert(s) covering "
            f"{len(self.stages)} stage(s) of activity{window}. "
            f"Source: {src}. Account(s): {who}. Host(s): {where}."
        )

    def to_row(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "risk": self.risk,
            "risk_band": self.risk_band,
            "severity": self.severity,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_min": round(self.duration_minutes, 1),
            "alerts": len(self.alerts),
            "stages": " -> ".join(self.stage_names),
            "source_ips": ", ".join(self.source_ips[:4]),
            "usernames": ", ".join(self.usernames[:4]),
            "hosts": ", ".join(self.hosts[:4]),
            "mitre": ", ".join(self.mitre),
            "events": len(self.event_ids),
        }


class _UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _entity_keys(alert: Alert) -> list[str]:
    """The entities an alert can be chained on. See the module docstring for
    why host is not one of them."""
    keys = []
    if alert.source_ip:
        keys.append("ip:" + str(alert.source_ip))
    if alert.username:
        keys.append("user:" + str(alert.username).lower())
    return keys


def _cluster(alerts: list[Alert], window_minutes: int) -> list[list[int]]:
    """Group alert indices that share an entity and overlap in time."""
    union = _UnionFind(len(alerts))
    window = pd.Timedelta(minutes=window_minutes)

    buckets: dict[str, list[int]] = {}
    for i, alert in enumerate(alerts):
        for key in _entity_keys(alert):
            buckets.setdefault(key, []).append(i)

    for indices in buckets.values():
        ordered = sorted(
            indices,
            key=lambda i: (alerts[i].first_seen is None, alerts[i].first_seen),
        )
        for prev, current in zip(ordered, ordered[1:]):
            a, b = alerts[prev], alerts[current]
            if a.first_seen is None or b.first_seen is None:
                union.union(prev, current)
                continue
            gap = b.first_seen - (a.last_seen or a.first_seen)
            if gap <= window:
                union.union(prev, current)

    groups: dict[int, list[int]] = {}
    for i in range(len(alerts)):
        groups.setdefault(union.find(i), []).append(i)
    return list(groups.values())


def _stages_for(alerts: list[Alert]) -> list[tuple[str, list[str]]]:
    """Group alerts by stage, ordered by when each stage was first observed.

    Ordering by observation rather than by the canonical kill chain means the
    chain shown is the one in the evidence. The canonical order is kept only
    as a tiebreaker for stages that start in the same second.
    """
    by_stage: dict[str, list[str]] = {}
    earliest: dict[str, Any] = {}
    for alert in alerts:
        stage = RULE_TO_STAGE.get(alert.rule_id)
        if stage is None:
            continue
        by_stage.setdefault(stage, []).append(alert.alert_id)
        if alert.first_seen is not None:
            current = earliest.get(stage)
            if current is None or alert.first_seen < current:
                earliest[stage] = alert.first_seen

    return sorted(
        by_stage.items(),
        key=lambda item: (earliest.get(item[0]) or datetime.max,
                          STAGE_ORDER.get(item[0], 99)),
    )


def _title_for(stage_names: list[str], alerts: list[Alert]) -> str:
    stages = set(stage_names)
    accessed = "Successful Access" in stages
    follow_on = bool(stages & {"Privilege Escalation", "Execution",
                               "Persistence / Defense Evasion"})

    if accessed and follow_on:
        return "Account Compromise with Post-Access Activity"
    if accessed:
        return "Possible Account Compromise"
    if "Credential Attack" in stages and follow_on:
        return "Credential Attack with Privileged Activity"
    if "Exploitation Attempt" in stages and follow_on:
        return "Web Exploitation with Follow-on Activity"
    if "Credential Attack" in stages:
        return "Authentication Brute Force Activity"
    if "Exploitation Attempt" in stages:
        return "Suspected Web Application Attack"
    if "Persistence / Defense Evasion" in stages:
        return "Account or Audit Policy Manipulation"
    if "Execution" in stages:
        return "Suspicious Execution Activity"
    if "Reconnaissance" in stages:
        return "Reconnaissance Activity"
    return alerts[0].name if alerts else "Unclassified Activity"


def _ordered_unique(values: Iterable[Any]) -> list[str]:
    seen: dict[str, None] = {}
    for value in values:
        if value:
            seen.setdefault(str(value), None)
    return list(seen)


def correlate(alerts: list[Alert], events: Optional[pd.DataFrame] = None,
              config: Optional[DetectionConfig] = None) -> list[Incident]:
    """Group alerts into incidents, then re-score both.

    Correlation feeds back into alert risk: an alert that turns out to sit in
    a four-stage chain is scored higher than the same alert on its own.
    """
    config = config or DetectionConfig()
    alerts = [a for a in alerts if a.rule_id != "LH-000"]
    if not alerts:
        return []

    source_by_event: dict[int, str] = {}
    if events is not None and not events.empty:
        source_by_event = dict(zip(events["event_id"], events["source"]))

    incidents: list[Incident] = []
    clusters = _cluster(alerts, config.correlation_window_minutes)
    # Order incidents by when they started so their ids read chronologically.
    clusters.sort(key=lambda idx: min(
        (alerts[i].first_seen for i in idx if alerts[i].first_seen is not None),
        default=datetime.max,
    ))

    for number, indices in enumerate(clusters, start=1):
        members = sorted(
            (alerts[i] for i in indices),
            key=lambda a: (a.first_seen is None, a.first_seen),
        )
        stages = _stages_for(members)
        event_ids = _dedupe_ints(eid for a in members for eid in a.evidence)
        log_sources = _ordered_unique(source_by_event.get(eid, "") for eid in event_ids)

        year = members[0].first_seen.year if members[0].first_seen else datetime.now().year
        incident = Incident(
            incident_id=f"LH-{year}-{number:03d}",
            title=_title_for([name for name, _ in stages], members),
            alerts=members,
            source_ips=_ordered_unique(a.source_ip for a in members),
            usernames=_ordered_unique(a.username for a in members),
            hosts=_ordered_unique(a.host for a in members),
            log_sources=log_sources,
            event_ids=event_ids,
            stages=stages,
            mitre=sorted({t for a in members for t in a.mitre}),
        )

        # Feed the chain context back into each alert, then re-score it.
        for alert in members:
            alert.incident_id = incident.incident_id
            alert.risk_factors["chain_stages"] = len(stages)
            alert.risk_factors["chain_log_sources"] = len(log_sources)
            risk_scoring.calculate_risk(alert, config)

        incident.risk, incident.risk_breakdown = risk_scoring.calculate_incident_risk(
            members, stages=len(stages), log_sources=len(log_sources)
        )
        incident.risk_band = risk_scoring.band(incident.risk)
        incident.severity = max_severity([a.severity for a in members])
        incidents.append(incident)

    incidents.sort(key=lambda inc: (-inc.risk, inc.first_seen or datetime.min))
    return incidents


def _dedupe_ints(values: Iterable[Any]) -> list[int]:
    seen: dict[int, None] = {}
    for value in values:
        try:
            seen.setdefault(int(value), None)
        except (TypeError, ValueError):
            continue
    return sorted(seen)


def incidents_to_frame(incidents: Iterable[Incident]) -> pd.DataFrame:
    rows = [inc.to_row() for inc in incidents]
    columns = ["incident_id", "title", "risk", "risk_band", "severity", "first_seen",
               "last_seen", "duration_min", "alerts", "stages", "source_ips",
               "usernames", "hosts", "mitre", "events"]
    return pd.DataFrame(rows, columns=columns)


def incident_timeline(incident: Incident, events: pd.DataFrame) -> pd.DataFrame:
    """Every raw event behind an incident, in order - the investigation view."""
    if events is None or events.empty or not incident.event_ids:
        return events.iloc[0:0] if events is not None else pd.DataFrame()
    subset = events[events["event_id"].isin(incident.event_ids)]
    return subset.sort_values("timestamp", kind="stable")


def attack_chain_rows(incident: Incident) -> list[dict[str, Any]]:
    """The chain as display rows: stage, when, what, which techniques."""
    rows: list[dict[str, Any]] = []
    by_id = {a.alert_id: a for a in incident.alerts}
    for stage, alert_ids in incident.stages:
        members = [by_id[aid] for aid in alert_ids if aid in by_id]
        stamps = [a.first_seen for a in members if a.first_seen]
        rows.append({
            "stage": stage,
            "when": min(stamps) if stamps else None,
            "alerts": ", ".join(alert_ids),
            "detail": "; ".join(dict.fromkeys(a.name for a in members)),
            "severity": max_severity([a.severity for a in members]),
            "risk": max((a.risk for a in members), default=0),
            "mitre": ", ".join(sorted({t for a in members for t in a.mitre})),
        })
    return rows
