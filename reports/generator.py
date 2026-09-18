"""Investigation report generation (Markdown).

The output is written to be pasted into a ticket: what happened, when, on
what evidence, which ATT&CK techniques it maps to, and what to check next.
Recommended actions are derived from the stages actually present in the
incident, so a reconnaissance-only finding does not come with instructions to
rotate credentials.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Optional

import pandas as pd

from correlation.engine import Incident, attack_chain_rows, incident_timeline
from detection import mitre
from detection.base import Alert, DetectionConfig
from scoring import risk as risk_scoring

# Follow-up actions per stage. Phrased as checks, not conclusions - the tool
# found log evidence, it did not confirm an intrusion.
STAGE_ACTIONS: dict[str, list[str]] = {
    "Reconnaissance": [
        "Confirm whether the scanning source is an authorised scanner or pentest before "
        "treating it as hostile.",
        "Check whether any probed path returned 200 and should not be reachable.",
    ],
    "Credential Attack": [
        "Confirm whether the targeted accounts exist and whether any lockout policy applied.",
        "Block or rate-limit the source address at the perimeter if it is not a known host.",
    ],
    "Exploitation Attempt": [
        "Review the application response bodies for the requests that returned 2xx - a match "
        "proves the payload was sent, not that it worked.",
        "Check the web application and database logs for the same timestamps.",
        "Verify the application is patched for the class of payload observed.",
    ],
    "Successful Access": [
        "Treat the account as potentially compromised: reset the credential and revoke active "
        "sessions and tokens.",
        "Confirm with the account owner whether the login was theirs.",
        "Pull the full session history for that login (commands, files accessed, network "
        "connections).",
    ],
    "Privilege Escalation": [
        "Establish whether the account is meant to hold that privilege.",
        "Review every command run in the elevated session for changes to persist.",
        "Check sudoers, group membership and scheduled tasks for modifications.",
    ],
    "Execution": [
        "Decode any encoded command line and identify the payload it retrieves.",
        "Search the environment for the same command line and the files it wrote.",
        "Isolate the host if the payload cannot be accounted for.",
    ],
    "Persistence / Defense Evasion": [
        "Disable and investigate any account created during the window.",
        "Verify privileged group membership against the expected baseline.",
        "Check whether audit logging was cleared and recover logs from a forwarder or SIEM "
        "copy - the local record may no longer be complete.",
    ],
}

DEFAULT_ACTIONS = [
    "Preserve the raw log files behind this report as evidence before rotation removes them.",
    "Widen the search window to look for earlier activity from the same source or account.",
]


def _fmt(ts: Any, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    if ts is None or (isinstance(ts, float) and pd.isna(ts)):
        return "unknown"
    if isinstance(ts, str):
        return ts
    if pd.isna(ts):
        return "unknown"
    return pd.Timestamp(ts).strftime(fmt)


def _event_line(row: pd.Series) -> str:
    who = row.get("username") or ""
    ip = row.get("source_ip") or ""
    host = row.get("host") or ""
    detail = str(row.get("action") or "")[:110]
    command = str(row.get("command_line") or "")
    if command:
        detail += " :: " + command[:110]
    status = row.get("http_status")
    if pd.notna(status):
        # The action for a web event is already "GET /path"; only the
        # response code needs adding.
        detail += f" -> {int(status)}"
    parts = [p for p in (who, ip, host) if p]
    return f"| {_fmt(row.get('timestamp'), '%H:%M:%S')} | {row.get('source', '')} | " \
           f"{' / '.join(parts) or '-'} | {detail} |"


def _recommended_actions(incident: Incident) -> list[str]:
    actions: list[str] = []
    for stage in incident.stage_names:
        for action in STAGE_ACTIONS.get(stage, []):
            if action not in actions:
                actions.append(action)
    for action in DEFAULT_ACTIONS:
        if action not in actions:
            actions.append(action)
    return actions


def _techniques_table(tids: Iterable[str]) -> list[str]:
    lines = ["| Technique | Name | Tactic(s) |", "|---|---|---|"]
    for tid in sorted(set(tids)):
        technique = mitre.get(tid)
        lines.append(f"| [{technique.tid}]({technique.url}) | {technique.name} | "
                     f"{', '.join(technique.tactics) or '-'} |")
    return lines


def incident_report(incident: Incident, events: Optional[pd.DataFrame] = None,
                    config: Optional[DetectionConfig] = None,
                    max_timeline_rows: int = 80) -> str:
    """Render one incident as a Markdown investigation report."""
    config = config or DetectionConfig()
    lines: list[str] = []

    lines += [
        f"# Incident Report {incident.incident_id}",
        "",
        f"**{incident.title}**",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Incident ID | `{incident.incident_id}` |",
        f"| Risk score | **{incident.risk}/100 ({incident.risk_band})** |",
        f"| Highest alert severity | {incident.severity.upper()} |",
        f"| First activity | {_fmt(incident.first_seen)} |",
        f"| Last activity | {_fmt(incident.last_seen)} |",
        f"| Duration | {incident.duration_minutes:.0f} minutes |",
        f"| Source address(es) | {', '.join(incident.source_ips) or 'not recorded'} |",
        f"| Account(s) | {', '.join(incident.usernames) or 'not attributed'} |",
        f"| Host(s) | {', '.join(incident.hosts) or 'unknown'} |",
        f"| Log sources | {', '.join(incident.log_sources) or 'unknown'} |",
        f"| Alerts | {len(incident.alerts)} |",
        f"| Supporting events | {len(incident.event_ids)} |",
        f"| Report generated | {datetime.now():%Y-%m-%d %H:%M:%S} |",
        "",
        "## Summary",
        "",
        incident.summary(),
        "",
    ]

    # What the evidence supports, and what it does not.
    lines += [
        "## Assessment",
        "",
    ]
    stages = set(incident.stage_names)
    if "Successful Access" in stages:
        lines.append("Log evidence shows failed authentication attempts followed by a "
                     "successful authentication from the same source address. That is "
                     "consistent with a guessed or otherwise obtained credential, and the "
                     "affected account should be treated as compromised until the owner "
                     "confirms the login.")
    elif "Credential Attack" in stages:
        lines.append("Log evidence shows repeated failed authentication from a single "
                     "source. No successful authentication from that source appears in the "
                     "data, so there is no evidence the attempt succeeded.")
    if "Exploitation Attempt" in stages:
        lines.append("")
        lines.append("Requests matching web attack signatures were observed. A signature "
                     "match confirms a payload was **sent**; it does not confirm the "
                     "application was vulnerable. The response codes recorded against each "
                     "alert are the first thing to check.")
    if stages & {"Execution", "Persistence / Defense Evasion"}:
        lines.append("")
        lines.append("Activity after the access stage (process execution, account or audit "
                     "policy changes) is what makes this more than an authentication event. "
                     "These are the items to scope first.")
    lines.append("")

    # Risk breakdown - the score should never be a bare number.
    if incident.risk_breakdown:
        lines += [
            "## How the risk score was reached",
            "",
            "| Component | Points |",
            "|---|---|",
        ]
        labels = {
            "highest_alert_risk": "Highest individual alert risk",
            "attack_chain_stages": "Attack chain breadth (stages observed)",
            "multiple_log_sources": "Corroboration across log sources",
            "alert_volume": "Number of correlated alerts",
        }
        for key, label in labels.items():
            if key in incident.risk_breakdown:
                lines.append(f"| {label} | {incident.risk_breakdown[key]} |")
        lines += [f"| **Total** | **{incident.risk}/100 "
                  f"({incident.risk_band})** |", ""]

    # Attack chain
    chain = attack_chain_rows(incident)
    if chain:
        lines += [
            "## Attack chain",
            "",
            "```",
            "\n".join(
                f"{'    ' * i}{row['stage']}" + ("\n" + "    " * i + "     |"
                                                 if i < len(chain) - 1 else "")
                for i, row in enumerate(chain)
            ),
            "```",
            "",
            "| Stage | First seen | Detections | Alerts | Techniques |",
            "|---|---|---|---|---|",
        ]
        for row in chain:
            lines.append(f"| {row['stage']} | {_fmt(row['when'], '%H:%M:%S')} | "
                         f"{row['detail']} | {row['alerts']} | {row['mitre']} |")
        lines.append("")

    # Alerts, worst first
    lines += [
        "## Detections",
        "",
        "| Alert | Rule | Risk | Severity | Description |",
        "|---|---|---|---|---|",
    ]
    for alert in sorted(incident.alerts, key=lambda a: -a.risk):
        description = alert.description.replace("|", "\\|")
        lines.append(f"| `{alert.alert_id}` | {alert.rule_id} | {alert.risk} | "
                     f"{alert.severity.upper()} | {description} |")
    lines.append("")

    # Timeline of the underlying events
    if events is not None and not events.empty:
        timeline = incident_timeline(incident, events)
        if not timeline.empty:
            shown = timeline.head(max_timeline_rows)
            lines += [
                "## Timeline",
                "",
                f"{len(timeline)} events support this incident"
                + (f"; the first {len(shown)} are shown." if len(timeline) > len(shown)
                   else "."),
                "",
                "| Time | Log source | Actor | Event |",
                "|---|---|---|---|",
            ]
            lines += [_event_line(row) for _, row in shown.iterrows()]
            lines.append("")

            lines += ["## Evidence (raw log lines)", "", "```log"]
            for _, row in shown.head(25).iterrows():
                raw = str(row.get("raw") or "").replace("\n", " ")
                lines.append(raw[:300])
            lines += ["```", ""]

    # ATT&CK
    if incident.mitre:
        lines += ["## MITRE ATT&CK", ""] + _techniques_table(incident.mitre) + [""]
        lines += [f"Tactics observed: {', '.join(incident.tactics)}.", ""]

    # Next steps
    lines += ["## Recommended investigation", ""]
    for i, action in enumerate(_recommended_actions(incident), start=1):
        lines.append(f"{i}. {action}")
    lines += [
        "",
        "## Limitations",
        "",
        "- Findings are derived only from the log files supplied. Absence of evidence here "
        "is not evidence that nothing happened.",
        "- Detections are threshold and signature based; both the thresholds and the "
        "signatures are listed in the rule catalogue and can be tuned.",
        "- Timestamps are taken from the logs as written and are not corrected for clock "
        "skew between hosts.",
        "",
        f"*Generated by LogHunt on {datetime.now():%Y-%m-%d %H:%M:%S}.*",
    ]
    return "\n".join(lines)


def investigation_report(incidents: list[Incident], alerts: list[Alert],
                         events: Optional[pd.DataFrame] = None,
                         parse_summary: str = "",
                         config: Optional[DetectionConfig] = None) -> str:
    """Render the whole dataset: one summary plus every incident in full."""
    config = config or DetectionConfig()
    bands = {}
    for alert in alerts:
        bands[alert.risk_band] = bands.get(alert.risk_band, 0) + 1

    lines = [
        "# LogHunt Investigation Report",
        "",
        f"Generated {datetime.now():%Y-%m-%d %H:%M:%S}",
        "",
        "## Scope",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Events analysed | {0 if events is None else len(events):,} |",
        f"| Alerts raised | {len(alerts)} |",
        f"| Incidents correlated | {len(incidents)} |",
        f"| Critical / high risk alerts | "
        f"{bands.get('CRITICAL', 0)} / {bands.get('HIGH', 0)} |",
    ]
    if events is not None and not events.empty and events["timestamp"].notna().any():
        lines.append(f"| Time range | {_fmt(events['timestamp'].min())} to "
                     f"{_fmt(events['timestamp'].max())} |")
    if parse_summary:
        lines.append(f"| Input | {parse_summary} |")
    lines += ["", "## Incidents", ""]

    if not incidents:
        lines += ["No incidents were correlated from the supplied logs.", ""]
    else:
        lines += ["| Incident | Risk | Title | Window | Stages |", "|---|---|---|---|---|"]
        for incident in incidents:
            lines.append(
                f"| `{incident.incident_id}` | {incident.risk} ({incident.risk_band}) | "
                f"{incident.title} | {_fmt(incident.first_seen, '%H:%M:%S')} - "
                f"{_fmt(incident.last_seen, '%H:%M:%S')} | "
                f"{' -> '.join(incident.stage_names)} |"
            )
        lines.append("")
        for incident in incidents:
            lines += ["---", "", incident_report(incident, events, config), ""]
    return "\n".join(lines)
