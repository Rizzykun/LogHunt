"""LogHunt - security log investigation dashboard.

Run with:  streamlit run app.py

The layout follows how an investigation actually proceeds: start at the
overview, triage the alert queue, read the attack chain, then pivot on an IP
or an account and export the report.
"""
from __future__ import annotations

import glob
import io
import os
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

import parser
from correlation import Incident, attack_chain_rows, correlate, incident_timeline
from detection import RULE_CATALOG, Alert, DetectionConfig, alerts_to_frame, mitre, run_all
from reports import incident_report, investigation_report
from scoring import risk as risk_scoring

st.set_page_config(page_title="LogHunt", page_icon="🔎", layout="wide")

DATA_DIR = "data"
SEVERITY_COLORS = {
    "critical": "#b3261e",
    "high": "#e8590c",
    "medium": "#c9a227",
    "low": "#2f6f4f",
    "info": "#4a6572",
}
BAND_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SOURCE_LABELS = {
    "linux_auth": "Linux auth",
    "windows_security": "Windows Security",
    "web_access": "Web access",
}


# --------------------------------------------------------------------------
# Analysis pipeline (cached)
# --------------------------------------------------------------------------
@dataclass
class Analysis:
    events: pd.DataFrame
    alerts: list[Alert]
    incidents: list[Incident]
    parse_summary: str
    file_stats: list[tuple[str, str, int, int]] = field(default_factory=list)
    elapsed: float = 0.0

    @property
    def alert_frame(self) -> pd.DataFrame:
        return alerts_to_frame(self.alerts)


def _config_from(values: dict[str, Any]) -> DetectionConfig:
    return DetectionConfig(
        bf_failure_threshold=values["bf_failure_threshold"],
        bf_window_minutes=values["bf_window_minutes"],
        compromise_window_minutes=values["compromise_window_minutes"],
        priv_window_minutes=values["priv_window_minutes"],
        scan_404_threshold=values["scan_404_threshold"],
        correlation_window_minutes=values["correlation_window_minutes"],
    )


@st.cache_data(show_spinner=False, max_entries=8)
def analyse(payloads: tuple[tuple[str, bytes], ...],
            config_values: tuple[tuple[str, int], ...]) -> Analysis:
    """Parse, detect, score and correlate. Cached on inputs plus thresholds."""
    started = datetime.now()
    config = _config_from(dict(config_values))

    results = []
    for name, blob in payloads:
        text = blob.decode("utf-8", errors="replace")
        results.append(parser.parse_text(text, name=name))
    result = parser.merge_results(results)

    alerts = risk_scoring.score_alerts(run_all(result.events, config), config)
    incidents = correlate(alerts, result.events, config)

    return Analysis(
        events=result.events,
        alerts=alerts,
        incidents=incidents,
        parse_summary=result.summary(),
        file_stats=[(f.name, f.log_format, f.total_lines, f.parsed_events)
                    for f in result.files],
        elapsed=(datetime.now() - started).total_seconds(),
    )


def _load_bundled(folder: str) -> tuple[tuple[str, bytes], ...]:
    payloads = []
    for path in sorted(glob.glob(os.path.join(DATA_DIR, folder, "*.log"))):
        with open(path, "rb") as handle:
            payloads.append((os.path.basename(path), handle.read()))
    return tuple(payloads)


# --------------------------------------------------------------------------
# Small rendering helpers
# --------------------------------------------------------------------------
def band_chip(band: str, score: Optional[int] = None) -> str:
    color = risk_scoring.BAND_COLORS.get(band, "#4a6572")
    text = band if score is None else f"{score}/100 {band}"
    return (f"<span style='background:{color};color:#fff;padding:2px 10px;"
            f"border-radius:10px;font-size:0.78rem;font-weight:600;"
            f"white-space:nowrap'>{text}</span>")


def severity_chip(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#4a6572")
    return (f"<span style='background:{color};color:#fff;padding:2px 9px;"
            f"border-radius:10px;font-size:0.75rem;font-weight:600'>"
            f"{severity.upper()}</span>")


def metric_row(items: list[tuple[str, Any, str]]) -> None:
    for column, (label, value, helptext) in zip(st.columns(len(items)), items):
        column.metric(label, value, help=helptext or None)


def alert_card(alert: Alert, events: Optional[pd.DataFrame] = None,
               expanded: bool = False) -> None:
    """One alert, with its score breakdown and evidence."""
    title = (f"{alert.risk_band} {alert.risk}/100 - {alert.name} "
             f"[{alert.alert_id} / {alert.rule_id}]")
    with st.expander(title, expanded=expanded):
        st.markdown(
            f"{band_chip(alert.risk_band, alert.risk)} &nbsp; "
            f"{severity_chip(alert.severity)} &nbsp; "
            f"<span style='color:#888'>{alert.category}</span>",
            unsafe_allow_html=True,
        )
        st.write(alert.description)

        left, right = st.columns([1, 1])
        with left:
            st.markdown("**Entities**")
            st.write(pd.DataFrame([
                {"field": "Source IP", "value": alert.source_ip or "-"},
                {"field": "Account", "value": alert.username or "-"},
                {"field": "Host", "value": alert.host or "-"},
                {"field": "First seen", "value": str(alert.first_seen or "-")},
                {"field": "Last seen", "value": str(alert.last_seen or "-")},
                {"field": "Events", "value": alert.count},
                {"field": "Incident", "value": alert.incident_id or "-"},
            ]).set_index("field"))
        with right:
            st.markdown("**Why this score**")
            rows = risk_scoring.explain(alert)
            if rows:
                breakdown = pd.DataFrame(rows, columns=["reason", "points"])
                st.write(breakdown.set_index("reason"))
            st.caption(f"Total: {alert.risk}/100 ({alert.risk_band})")

        if alert.mitre:
            st.markdown("**ATT&CK:** " + " &nbsp;·&nbsp; ".join(
                f"[{mitre.get(t).label}]({mitre.get(t).url})" for t in alert.mitre
            ))

        if alert.metadata:
            with st.popover("Detection detail"):
                st.json(alert.metadata, expanded=True)

        if events is not None and alert.evidence:
            evidence = events[events["event_id"].isin(alert.evidence)]
            st.markdown(f"**Evidence ({len(evidence)} events)**")
            st.dataframe(
                evidence[["timestamp", "source", "source_ip", "username", "host",
                          "event_type", "action", "raw"]].head(200),
                use_container_width=True, hide_index=True,
            )


def events_over_time(events: pd.DataFrame, freq: str = "5min") -> go.Figure:
    frame = events.dropna(subset=["timestamp"]).copy()
    if frame.empty:
        return go.Figure()
    frame["bucket"] = frame["timestamp"].dt.floor(freq)
    counts = (frame.groupby(["bucket", "source"]).size()
              .reset_index(name="events"))
    counts["source"] = counts["source"].map(lambda s: SOURCE_LABELS.get(s, s))
    figure = px.area(counts, x="bucket", y="events", color="source",
                     labels={"bucket": "", "events": "Events", "source": "Log source"})
    figure.update_layout(height=280, margin=dict(l=0, r=0, t=10, b=0),
                         legend=dict(orientation="h", y=1.15, x=0))
    return figure


def alert_markers(alerts: list[Alert], figure: go.Figure) -> go.Figure:
    """Drop alert markers onto a time axis, sized by risk."""
    plotted = [a for a in alerts if a.first_seen is not None]
    if not plotted:
        return figure
    figure.add_trace(go.Scatter(
        x=[a.first_seen for a in plotted],
        y=[0 for _ in plotted],
        mode="markers",
        marker=dict(size=[8 + a.risk / 8 for a in plotted],
                    color=[risk_scoring.BAND_COLORS.get(a.risk_band, "#888")
                           for a in plotted],
                    line=dict(width=1, color="#fff")),
        name="Alerts",
        text=[f"{a.alert_id} {a.name} ({a.risk}/100)" for a in plotted],
        hovertemplate="%{text}<br>%{x}<extra></extra>",
    ))
    return figure


def chain_html(rows: list[dict[str, Any]]) -> str:
    """Render an attack chain as a column of boxes joined by arrows."""
    blocks = []
    for i, row in enumerate(rows):
        color = SEVERITY_COLORS.get(row["severity"], "#4a6572")
        when = row["when"].strftime("%H:%M:%S") if row["when"] is not None else "-"
        blocks.append(
            f"<div style='border-left:4px solid {color};background:rgba(128,128,128,0.08);"
            f"padding:8px 12px;border-radius:4px;margin:0'>"
            f"<div style='font-size:0.72rem;color:#888'>STAGE {i + 1} &nbsp;·&nbsp; {when}"
            f" &nbsp;·&nbsp; risk {row['risk']}/100</div>"
            f"<div style='font-weight:600'>{row['stage']}</div>"
            f"<div style='font-size:0.82rem'>{row['detail']}</div>"
            f"<div style='font-size:0.72rem;color:#888'>{row['alerts']} &nbsp;|&nbsp; "
            f"{row['mitre']}</div></div>"
        )
    arrow = ("<div style='text-align:center;color:#888;font-size:1.1rem;"
             "line-height:1'>&#8595;</div>")
    return "<div style='display:flex;flex-direction:column;gap:4px'>" + \
        arrow.join(blocks) + "</div>"


# --------------------------------------------------------------------------
# Sidebar: input and tuning
# --------------------------------------------------------------------------
def sidebar() -> tuple[tuple[tuple[str, bytes], ...], tuple[tuple[str, int], ...], str]:
    st.sidebar.title("🔎 LogHunt")
    st.sidebar.caption("Security log investigation toolkit")

    st.sidebar.subheader("Log input")
    choice = st.sidebar.radio(
        "Dataset",
        ["Sample: attack scenario", "Sample: baseline (no attack)", "Upload logs"],
        label_visibility="collapsed",
    )

    payloads: tuple[tuple[str, bytes], ...] = ()
    label = ""
    if choice == "Sample: attack scenario":
        payloads = _load_bundled("attacks")
        label = "data/attacks"
        st.sidebar.caption("Scripted intrusion across all three log sources. "
                           "Ground truth in `data/attacks/GROUND_TRUTH.md`.")
    elif choice == "Sample: baseline (no attack)":
        payloads = _load_bundled("normal")
        label = "data/normal"
        st.sidebar.caption("Background activity only - use it to see what the rules "
                           "do *not* fire on.")
    else:
        uploaded = st.sidebar.file_uploader(
            "Log files", accept_multiple_files=True,
            type=["log", "txt", "csv", "json", "out"],
            help="Linux auth logs, Windows Security exports (text/CSV/JSON), or "
                 "Apache/Nginx access logs. The format is detected per file.",
        )
        if uploaded:
            payloads = tuple((f.name, f.getvalue()) for f in uploaded)
            label = f"{len(payloads)} uploaded file(s)"

    if not payloads and choice != "Upload logs":
        st.sidebar.error("No sample data found. Run `python tools/generate_scenario.py`.")

    st.sidebar.subheader("Detection tuning")
    with st.sidebar.expander("Thresholds", expanded=False):
        config_values = (
            ("bf_failure_threshold",
             st.slider("Brute force: failures", 3, 25, 5,
                       help="Failed authentications needed inside the window")),
            ("bf_window_minutes", st.slider("Brute force: window (min)", 1, 30, 5)),
            ("compromise_window_minutes",
             st.slider("Success-after-failures window (min)", 1, 60, 10)),
            ("priv_window_minutes",
             st.slider("Login to privileged action (min)", 1, 60, 15)),
            ("scan_404_threshold", st.slider("Scan: 404s in window", 5, 100, 20)),
            ("correlation_window_minutes",
             st.slider("Correlation window (min)", 5, 240, 30,
                       help="Largest gap allowed between two alerts in one incident")),
        )
    return payloads, config_values, label


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------
def page_overview(analysis: Analysis) -> None:
    st.header("Overview")
    events, alerts, incidents = analysis.events, analysis.alerts, analysis.incidents

    bands = pd.Series([a.risk_band for a in alerts]).value_counts() if alerts \
        else pd.Series(dtype=int)
    critical_incidents = [i for i in incidents if i.risk_band == "CRITICAL"]

    metric_row([
        ("Events", f"{len(events):,}", "Normalized events parsed from the input"),
        ("Alerts", len(alerts), "Detection findings before correlation"),
        ("High risk", int(bands.get("HIGH", 0)), "Alerts scoring 65-84"),
        ("Critical risk", int(bands.get("CRITICAL", 0)), "Alerts scoring 85+"),
        ("Incidents", len(incidents), "Correlated groups of alerts"),
        ("Critical incidents", len(critical_incidents), "Incidents scoring 85+"),
    ])

    if incidents:
        st.subheader("Highest-risk incident")
        top = incidents[0]
        left, right = st.columns([2, 3])
        with left:
            st.markdown(f"### {band_chip(top.risk_band, top.risk)}", unsafe_allow_html=True)
            st.markdown(f"**{top.incident_id} - {top.title}**")
            st.write(top.summary())
            st.markdown("**Chain:** " + " → ".join(top.stage_names))
        with right:
            st.markdown(chain_html(attack_chain_rows(top)[:4]), unsafe_allow_html=True)
            if len(top.stages) > 4:
                st.caption(f"+{len(top.stages) - 4} more stage(s) - see Attack Chains.")

    st.subheader("Activity and alerts over time")
    st.plotly_chart(alert_markers(alerts, events_over_time(events)),
                    use_container_width=True)

    left, right = st.columns(2)
    with left:
        st.subheader("Alerts by rule")
        if alerts:
            # Grouped by rule, not by alert title: LH-010 names itself after
            # the binary it saw, which would otherwise be one bar per binary.
            catalog = {r.rule_id: r.name for r in RULE_CATALOG}
            counts = (analysis.alert_frame.groupby("rule_id").size()
                      .reset_index(name="alerts").sort_values("alerts"))
            counts["rule"] = counts["rule_id"] + "  " + counts["rule_id"].map(
                lambda r: catalog.get(r, "")[:40])
            figure = px.bar(counts, x="alerts", y="rule", orientation="h",
                            labels={"alerts": "Alerts", "rule": ""})
            figure.update_layout(height=340, margin=dict(l=0, r=0, t=10, b=0))
            st.plotly_chart(figure, use_container_width=True)
        else:
            st.info("No alerts raised on this dataset.")
    with right:
        st.subheader("Risk distribution")
        if alerts:
            frame = pd.DataFrame({"band": [a.risk_band for a in alerts]})
            counts = frame["band"].value_counts().reindex(BAND_ORDER).dropna()
            figure = px.pie(values=counts.values, names=counts.index, hole=0.55,
                            color=counts.index,
                            color_discrete_map=risk_scoring.BAND_COLORS)
            figure.update_layout(height=340, margin=dict(l=0, r=0, t=10, b=0))
            st.plotly_chart(figure, use_container_width=True)

    st.subheader("Input")
    stats = pd.DataFrame(analysis.file_stats,
                         columns=["file", "detected format", "lines", "events"])
    stats["detected format"] = stats["detected format"].map(
        lambda s: SOURCE_LABELS.get(s, s))
    st.dataframe(stats, use_container_width=True, hide_index=True)
    st.caption(f"Parsed, detected and correlated in {analysis.elapsed:.2f}s. "
               "Windows records span many lines, so lines exceed events for that format.")


def page_alerts(analysis: Analysis) -> None:
    st.header("Alerts")
    if not analysis.alerts:
        st.info("No alerts raised on this dataset.")
        return

    frame = analysis.alert_frame
    left, mid, right, far = st.columns(4)
    bands = far.multiselect("Risk band", BAND_ORDER,
                            default=[b for b in BAND_ORDER if b in set(frame["risk_band"])])
    rules = left.multiselect("Rule", sorted(frame["rule_id"].unique()))
    ips = mid.multiselect("Source IP", sorted(x for x in frame["source_ip"].unique() if x))
    users = right.multiselect("Account", sorted(x for x in frame["username"].unique() if x))

    selection = frame[frame["risk_band"].isin(bands)]
    if rules:
        selection = selection[selection["rule_id"].isin(rules)]
    if ips:
        selection = selection[selection["source_ip"].isin(ips)]
    if users:
        selection = selection[selection["username"].isin(users)]
    selection = selection.sort_values("risk", ascending=False)

    st.caption(f"{len(selection)} of {len(frame)} alerts")
    st.dataframe(
        selection[["alert_id", "risk", "risk_band", "severity", "rule_id", "name",
                   "first_seen", "source_ip", "username", "host", "count",
                   "incident_id", "mitre"]],
        use_container_width=True, hide_index=True,
        column_config={"risk": st.column_config.ProgressColumn(
            "risk", min_value=0, max_value=100, format="%d")},
    )

    st.subheader("Alert detail")
    by_id = {a.alert_id: a for a in analysis.alerts}
    for alert_id in selection["alert_id"].head(40):
        alert_card(by_id[alert_id], analysis.events)
    if len(selection) > 40:
        st.caption("Showing the 40 highest-risk alerts; narrow the filters to see more.")


def page_timeline(analysis: Analysis) -> None:
    st.header("Investigation timeline")
    events = analysis.events
    if events.empty:
        st.info("No events parsed.")
        return

    evidence_ids = {eid for a in analysis.alerts for eid in a.evidence}
    incident_choices = ["(all events)"] + [
        f"{i.incident_id} - {i.title}" for i in analysis.incidents
    ]

    top = st.columns([2, 2, 2, 2])
    incident_pick = top[0].selectbox("Incident", incident_choices)
    sources = top[1].multiselect("Log source", sorted(events["source"].unique()),
                                 format_func=lambda s: SOURCE_LABELS.get(s, s))
    types = top[2].multiselect("Event type", sorted(events["event_type"].unique()))
    only_evidence = top[3].checkbox("Alert evidence only", value=False,
                                    help="Show only events cited by a detection")

    second = st.columns([2, 2, 3])
    ip_filter = second[0].multiselect(
        "Source IP", sorted(x for x in events["source_ip"].unique() if x))
    user_filter = second[1].multiselect(
        "Account", sorted(x for x in events["username"].unique() if x))
    search = second[2].text_input("Search raw text", placeholder="e.g. /etc/shadow, sudo")

    selection = events
    if incident_pick != "(all events)":
        incident_id = incident_pick.split(" - ")[0]
        incident = next(i for i in analysis.incidents if i.incident_id == incident_id)
        selection = incident_timeline(incident, events)
    if sources:
        selection = selection[selection["source"].isin(sources)]
    if types:
        selection = selection[selection["event_type"].isin(types)]
    if ip_filter:
        selection = selection[selection["source_ip"].isin(ip_filter)]
    if user_filter:
        selection = selection[selection["username"].isin(user_filter)]
    if only_evidence:
        selection = selection[selection["event_id"].isin(evidence_ids)]
    if search:
        selection = selection[selection["raw"].str.contains(search, case=False, na=False)]

    stamps = selection["timestamp"].dropna()
    if not stamps.empty and len(stamps) > 1:
        start, end = stamps.min().to_pydatetime(), stamps.max().to_pydatetime()
        if start != end:
            window = st.slider("Time window", min_value=start, max_value=end,
                               value=(start, end), format="HH:mm:ss")
            selection = selection[selection["timestamp"].between(window[0], window[1])]

    st.caption(f"{len(selection):,} of {len(events):,} events")

    if not selection.empty:
        sample = selection.dropna(subset=["timestamp"]).copy()
        sample["cited"] = sample["event_id"].isin(evidence_ids).map(
            {True: "cited by a detection", False: "context"})
        sample["source"] = sample["source"].map(lambda s: SOURCE_LABELS.get(s, s))
        figure = px.scatter(
            sample.head(6000), x="timestamp", y="event_type", color="source",
            symbol="cited", symbol_map={"cited by a detection": "x",
                                        "context": "circle-open"},
            hover_data=["source_ip", "username", "action"],
            labels={"timestamp": "", "event_type": "", "source": "Log source",
                    "cited": ""},
        )
        figure.update_layout(height=340, margin=dict(l=0, r=0, t=10, b=0),
                             legend=dict(orientation="h", y=1.2, x=0))
        st.plotly_chart(figure, use_container_width=True)

    st.dataframe(
        selection[["timestamp", "source", "event_type", "status", "source_ip",
                   "username", "host", "action", "command_line", "uri",
                   "http_status", "event_code", "raw"]],
        use_container_width=True, hide_index=True, height=460,
    )
    st.download_button(
        "Download this view as CSV",
        selection.to_csv(index=False).encode("utf-8"),
        file_name="loghunt_timeline.csv", mime="text/csv",
    )


def _entity_profile(analysis: Analysis, column: str, value: str) -> None:
    events = analysis.events
    subset = events[events[column] == value]
    alerts = [a for a in analysis.alerts
              if (a.source_ip if column == "source_ip" else a.username) == value]
    incidents = [i for i in analysis.incidents
                 if value in (i.source_ips if column == "source_ip" else i.usernames)]

    failed = subset[subset["event_type"].isin(("auth_failure", "auth_invalid_user"))]
    success = subset[subset["event_type"] == "auth_success"]
    web = subset[subset["event_type"] == "web_request"]
    privileged = subset[subset["event_type"].isin(("privilege_use", "privilege_assigned"))]
    processes = subset[subset["event_type"] == "process_creation"]
    worst = max((a.risk for a in alerts), default=0)

    metric_row([
        ("Events", f"{len(subset):,}", "All events involving this entity"),
        ("Failed logins", len(failed), ""),
        ("Successful logins", len(success), ""),
        ("Web requests", len(web), ""),
        ("Privileged actions", len(privileged), ""),
        ("Alerts", len(alerts), ""),
    ])
    st.markdown(f"**Highest risk:** {band_chip(risk_scoring.band(worst), worst)}",
                unsafe_allow_html=True)

    left, right = st.columns(2)
    with left:
        st.markdown("**Activity summary**")
        rows = [
            ("First seen", str(subset["timestamp"].min()) if not subset.empty else "-"),
            ("Last seen", str(subset["timestamp"].max()) if not subset.empty else "-"),
            ("Log sources", ", ".join(SOURCE_LABELS.get(s, s)
                                      for s in subset["source"].unique())),
            ("Hosts touched", ", ".join(h for h in subset["host"].unique() if h) or "-"),
            ("Processes", ", ".join(sorted({p for p in processes["process"] if p})[:6])
             or "-"),
            ("Incidents", ", ".join(i.incident_id for i in incidents) or "-"),
        ]
        if column == "source_ip":
            targeted = sorted({u for u in subset["username"] if u})
            rows.append(("Accounts targeted",
                         ", ".join(targeted[:10]) + (" ..." if len(targeted) > 10 else "")
                         or "-"))
        else:
            addresses = sorted({ip for ip in subset["source_ip"] if ip})
            rows.append(("Source addresses",
                         ", ".join(addresses[:10])
                         + (" ..." if len(addresses) > 10 else "") or "-"))
        st.write(pd.DataFrame(rows, columns=["field", "value"]).set_index("field"))
    with right:
        st.markdown("**Event breakdown**")
        counts = subset["event_type"].value_counts()
        if not counts.empty:
            figure = px.bar(x=counts.values, y=counts.index, orientation="h",
                            labels={"x": "Events", "y": ""})
            figure.update_layout(height=300, margin=dict(l=0, r=0, t=10, b=0))
            st.plotly_chart(figure, use_container_width=True)

    if column == "source_ip" and not web.empty:
        st.markdown("**Endpoints requested**")
        endpoints = (web.assign(path=web["uri"].astype(str).str.split("?").str[0])
                     .groupby("path")
                     .agg(requests=("event_id", "size"),
                          statuses=("http_status",
                                    lambda s: ", ".join(
                                        str(int(x)) for x in sorted(s.dropna().unique()))))
                     .sort_values("requests", ascending=False).head(25))
        st.dataframe(endpoints, use_container_width=True)

    st.markdown("**Detection history**")
    if alerts:
        st.dataframe(
            alerts_to_frame(sorted(alerts, key=lambda a: -a.risk))[
                ["alert_id", "risk", "risk_band", "rule_id", "name", "first_seen",
                 "count", "incident_id", "mitre"]],
            use_container_width=True, hide_index=True,
        )
        for alert in sorted(alerts, key=lambda a: -a.risk)[:6]:
            alert_card(alert, events)
    else:
        st.success("No detections reference this entity.")

    with st.expander(f"All {len(subset):,} raw events"):
        st.dataframe(
            subset[["timestamp", "source", "event_type", "status", "source_ip",
                    "username", "host", "action", "raw"]],
            use_container_width=True, hide_index=True, height=400,
        )


def page_ip_analysis(analysis: Analysis) -> None:
    st.header("IP investigation")
    events = analysis.events
    addresses = events[events["source_ip"] != ""]
    if addresses.empty:
        st.info("No source addresses in this dataset.")
        return

    risk_by_ip = {}
    for alert in analysis.alerts:
        if alert.source_ip:
            risk_by_ip[alert.source_ip] = max(risk_by_ip.get(alert.source_ip, 0), alert.risk)

    summary = (addresses.groupby("source_ip")
               .agg(events=("event_id", "size"),
                    first_seen=("timestamp", "min"),
                    last_seen=("timestamp", "max"),
                    accounts=("username", lambda s: len({u for u in s if u})))
               .reset_index())
    summary["failed_logins"] = summary["source_ip"].map(
        addresses[addresses["event_type"].isin(("auth_failure", "auth_invalid_user"))]
        ["source_ip"].value_counts()).fillna(0).astype(int)
    summary["alerts"] = summary["source_ip"].map(
        pd.Series([a.source_ip for a in analysis.alerts]).value_counts()
    ).fillna(0).astype(int)
    summary["risk"] = summary["source_ip"].map(risk_by_ip).fillna(0).astype(int)
    summary["band"] = summary["risk"].map(risk_scoring.band)
    summary = summary.sort_values(["risk", "events"], ascending=False)

    st.dataframe(
        summary[["source_ip", "risk", "band", "alerts", "events", "failed_logins",
                 "accounts", "first_seen", "last_seen"]].head(100),
        use_container_width=True, hide_index=True,
        column_config={"risk": st.column_config.ProgressColumn(
            "risk", min_value=0, max_value=100, format="%d")},
    )

    options = summary["source_ip"].tolist()
    chosen = st.selectbox("Investigate address", options,
                          format_func=lambda ip: f"{ip}  ({risk_by_ip.get(ip, 0)}/100)")
    st.divider()
    st.subheader(chosen)
    _entity_profile(analysis, "source_ip", chosen)


def page_user_analysis(analysis: Analysis) -> None:
    st.header("Account investigation")
    events = analysis.events
    accounts = events[events["username"] != ""]
    if accounts.empty:
        st.info("No accounts in this dataset.")
        return

    risk_by_user = {}
    for alert in analysis.alerts:
        if alert.username:
            risk_by_user[alert.username] = max(risk_by_user.get(alert.username, 0),
                                               alert.risk)

    summary = (accounts.groupby("username")
               .agg(events=("event_id", "size"),
                    first_seen=("timestamp", "min"),
                    last_seen=("timestamp", "max"),
                    source_ips=("source_ip", lambda s: len({ip for ip in s if ip})))
               .reset_index())
    for label, types in (("failed_logins", ("auth_failure", "auth_invalid_user")),
                         ("successful_logins", ("auth_success",)),
                         ("privileged", ("privilege_use", "privilege_assigned"))):
        summary[label] = summary["username"].map(
            accounts[accounts["event_type"].isin(types)]["username"].value_counts()
        ).fillna(0).astype(int)
    summary["alerts"] = summary["username"].map(
        pd.Series([a.username for a in analysis.alerts]).value_counts()
    ).fillna(0).astype(int)
    summary["risk"] = summary["username"].map(risk_by_user).fillna(0).astype(int)
    summary["band"] = summary["risk"].map(risk_scoring.band)
    summary = summary.sort_values(["risk", "events"], ascending=False)

    st.dataframe(
        summary[["username", "risk", "band", "alerts", "events", "failed_logins",
                 "successful_logins", "privileged", "source_ips",
                 "first_seen", "last_seen"]],
        use_container_width=True, hide_index=True,
        column_config={"risk": st.column_config.ProgressColumn(
            "risk", min_value=0, max_value=100, format="%d")},
    )

    chosen = st.selectbox("Investigate account", summary["username"].tolist(),
                          format_func=lambda u: f"{u}  ({risk_by_user.get(u, 0)}/100)")
    st.divider()
    st.subheader(chosen)
    _entity_profile(analysis, "username", chosen)


def page_attack_chains(analysis: Analysis) -> None:
    st.header("Attack chains")
    if not analysis.incidents:
        st.info("No incidents correlated from this dataset.")
        return

    st.dataframe(
        pd.DataFrame([i.to_row() for i in analysis.incidents])[
            ["incident_id", "risk", "risk_band", "title", "first_seen", "duration_min",
             "alerts", "events", "stages", "source_ips", "usernames", "hosts"]],
        use_container_width=True, hide_index=True,
        column_config={"risk": st.column_config.ProgressColumn(
            "risk", min_value=0, max_value=100, format="%d")},
    )

    labels = {f"{i.incident_id} - {i.title} ({i.risk}/100)": i for i in analysis.incidents}
    chosen = st.selectbox("Incident", list(labels))
    incident = labels[chosen]
    st.divider()

    left, right = st.columns([2, 3])
    with left:
        st.markdown(f"## {band_chip(incident.risk_band, incident.risk)}",
                    unsafe_allow_html=True)
        st.markdown(f"### {incident.incident_id}")
        st.markdown(f"**{incident.title}**")
        st.write(incident.summary())
        st.write(pd.DataFrame([
            {"field": "Window", "value": f"{incident.first_seen} → {incident.last_seen}"},
            {"field": "Duration", "value": f"{incident.duration_minutes:.0f} min"},
            {"field": "Source IPs", "value": ", ".join(incident.source_ips) or "-"},
            {"field": "Accounts", "value": ", ".join(incident.usernames) or "-"},
            {"field": "Hosts", "value": ", ".join(incident.hosts) or "-"},
            {"field": "Log sources",
             "value": ", ".join(SOURCE_LABELS.get(s, s) for s in incident.log_sources)},
            {"field": "Alerts", "value": len(incident.alerts)},
            {"field": "Events", "value": len(incident.event_ids)},
        ]).set_index("field"))

        st.markdown("**Risk breakdown**")
        st.write(pd.DataFrame(
            [(k.replace("_", " "), v) for k, v in incident.risk_breakdown.items()
             if isinstance(v, (int, float))],
            columns=["component", "points"]).set_index("component"))
    with right:
        st.markdown("**Chain, in the order observed**")
        st.markdown(chain_html(attack_chain_rows(incident)), unsafe_allow_html=True)

    st.subheader("Alerts in this incident")
    for alert in sorted(incident.alerts, key=lambda a: -a.risk):
        alert_card(alert, analysis.events)

    st.subheader("Supporting events")
    timeline = incident_timeline(incident, analysis.events)
    st.dataframe(
        timeline[["timestamp", "source", "event_type", "source_ip", "username",
                  "host", "action", "command_line", "raw"]],
        use_container_width=True, hide_index=True, height=420,
    )


def page_mitre(analysis: Analysis) -> None:
    st.header("MITRE ATT&CK coverage")
    st.caption("Techniques are attached to a detection only where log evidence supports "
               "them. This is coverage of what these rules can see, not of ATT&CK.")

    if not analysis.alerts:
        st.info("No alerts to map.")
        return

    rows = []
    for alert in analysis.alerts:
        for tid in alert.mitre:
            technique = mitre.get(tid)
            rows.append({
                "technique": tid,
                "name": technique.name,
                "tactics": ", ".join(technique.tactics),
                "alert_id": alert.alert_id,
                "risk": alert.risk,
                "rule_id": alert.rule_id,
            })
    frame = pd.DataFrame(rows)

    counts = (frame.groupby(["technique", "name"])
              .agg(alerts=("alert_id", "nunique"), peak_risk=("risk", "max"))
              .reset_index().sort_values("alerts"))
    counts["label"] = counts["technique"] + "  " + counts["name"].str.slice(0, 44)
    figure = px.bar(counts, x="alerts", y="label", orientation="h", color="peak_risk",
                    color_continuous_scale="OrRd", range_color=(0, 100),
                    labels={"alerts": "Alerts", "label": "", "peak_risk": "Peak risk"})
    figure.update_layout(height=max(320, 26 * len(counts)),
                         margin=dict(l=0, r=0, t=10, b=0))
    st.plotly_chart(figure, use_container_width=True)

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Techniques observed")
        table = (frame.groupby(["technique", "name", "tactics"])
                 .agg(alerts=("alert_id", "nunique"),
                      rules=("rule_id", lambda s: ", ".join(sorted(set(s)))),
                      peak_risk=("risk", "max"))
                 .reset_index().sort_values("peak_risk", ascending=False))
        table["link"] = table["technique"].map(lambda t: mitre.get(t).url)
        st.dataframe(table, use_container_width=True, hide_index=True,
                     column_config={"link": st.column_config.LinkColumn(
                         "attack.mitre.org", display_text="open")})
    with right:
        st.subheader("Tactics")
        tactics: dict[str, int] = {}
        for _, row in frame.iterrows():
            for tactic in mitre.get(row["technique"]).tactics:
                tactics[tactic] = tactics.get(tactic, 0) + 1
        ordered = [t for t in mitre.TACTIC_ORDER if t in tactics]
        series = pd.Series({t: tactics[t] for t in ordered})
        if not series.empty:
            figure = px.bar(x=series.values, y=series.index, orientation="h",
                            labels={"x": "Alert-technique pairs", "y": ""})
            figure.update_layout(height=max(320, 30 * len(series)),
                                 margin=dict(l=0, r=0, t=10, b=0),
                                 yaxis=dict(autorange="reversed"))
            st.plotly_chart(figure, use_container_width=True)


def page_rules(analysis: Analysis) -> None:
    st.header("Detection rules")
    st.caption("Eleven rules across six detection families. Every threshold shown here "
               "is adjustable in the sidebar.")

    fired = pd.Series([a.rule_id for a in analysis.alerts]).value_counts() \
        if analysis.alerts else pd.Series(dtype=int)
    frame = pd.DataFrame([{
        "rule_id": r.rule_id,
        "family": r.family,
        "name": r.name,
        "logic": r.logic,
        "log sources": ", ".join(r.log_sources),
        "ATT&CK": ", ".join(r.mitre),
        "alerts on this dataset": int(fired.get(r.rule_id, 0)),
    } for r in RULE_CATALOG])
    st.dataframe(frame, use_container_width=True, hide_index=True)

    st.subheader("Pipeline")
    st.code(
        "log file\n"
        "   -> parser/          format detection, then regex/CSV/JSON parsing\n"
        "   -> parser/schema    normalization to one 20-field event schema\n"
        "   -> detection/       11 rules over the normalized frame\n"
        "   -> scoring/risk     base severity + frequency + context + correlation\n"
        "   -> correlation/     alerts grouped by entity and time into incidents\n"
        "   -> reports/         Markdown investigation report",
        language="text",
    )


def page_reports(analysis: Analysis) -> None:
    st.header("Reports")
    if not analysis.incidents:
        st.info("No incidents to report on.")
        return

    labels = {f"{i.incident_id} - {i.title} ({i.risk}/100)": i for i in analysis.incidents}
    chosen = st.selectbox("Incident", list(labels))
    incident = labels[chosen]

    report = incident_report(incident, analysis.events)
    left, right, _ = st.columns([1, 1, 2])
    left.download_button("Download incident report (.md)", report.encode("utf-8"),
                         file_name=f"{incident.incident_id}.md", mime="text/markdown",
                         type="primary")

    full = investigation_report(analysis.incidents, analysis.alerts, analysis.events,
                                analysis.parse_summary)
    right.download_button("Download full investigation (.md)", full.encode("utf-8"),
                          file_name="loghunt_investigation.md", mime="text/markdown")

    bundle = io.BytesIO()
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("investigation.md", full)
        for inc in analysis.incidents:
            archive.writestr(f"incidents/{inc.incident_id}.md",
                             incident_report(inc, analysis.events))
        archive.writestr("alerts.csv", analysis.alert_frame.to_csv(index=False))
        archive.writestr("events.csv", analysis.events.to_csv(index=False))
    st.download_button("Download everything (.zip)", bundle.getvalue(),
                       file_name="loghunt_case_file.zip", mime="application/zip")

    st.divider()
    st.markdown(report)


PAGES = {
    "Overview": page_overview,
    "Alerts": page_alerts,
    "Timeline": page_timeline,
    "Attack chains": page_attack_chains,
    "IP investigation": page_ip_analysis,
    "Account investigation": page_user_analysis,
    "MITRE ATT&CK": page_mitre,
    "Detection rules": page_rules,
    "Reports": page_reports,
}


def main() -> None:
    payloads, config_values, label = sidebar()
    page = st.sidebar.radio("View", list(PAGES), index=0)

    if not payloads:
        st.title("🔎 LogHunt")
        st.subheader("Security log investigation and threat hunting toolkit")
        st.write("Pick a sample dataset or upload logs from the sidebar to begin.")
        st.markdown(
            "**Supported input**\n"
            "- Linux authentication logs (`auth.log`, `secure`) - syslog or RFC3339\n"
            "- Windows Security event logs - Event Viewer text, CSV, or JSON export\n"
            "- Apache/Nginx access logs - common and combined formats"
        )
        return

    with st.spinner("Parsing, detecting and correlating..."):
        analysis = analyse(payloads, config_values)

    st.sidebar.divider()
    st.sidebar.caption(
        f"**{label}**  \n{len(analysis.events):,} events · {len(analysis.alerts)} alerts · "
        f"{len(analysis.incidents)} incidents  \n{analysis.elapsed:.2f}s"
    )
    PAGES[page](analysis)


if __name__ == "__main__":
    main()
