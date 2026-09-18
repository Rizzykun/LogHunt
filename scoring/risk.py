"""Risk scoring.

A severity label alone cannot rank an alert queue: twenty "high" alerts still
leave the analyst choosing at random. Every score here is the sum of four
named components, and the breakdown is kept on the alert so the dashboard can
answer "why is this 92?" instead of presenting a number on faith.

    risk = base severity
         + frequency        (how much of it there was)
         + context          (who and what it touched)
         + correlation      (how far along an attack chain it sits)
"""
from __future__ import annotations

from typing import Any, Iterable, Optional

from detection.base import Alert, DetectionConfig

# Component ceilings. They sum past 100 on purpose - the score is clamped, so
# a maximal alert saturates rather than needing perfect weights.
BASE_SEVERITY_SCORE = {"info": 5, "low": 20, "medium": 40, "high": 58, "critical": 70}
MAX_FREQUENCY = 10
MAX_CONTEXT = 12
MAX_CORRELATION = 14

RISK_BANDS = (
    (85, "CRITICAL"),
    (65, "HIGH"),
    (45, "MEDIUM"),
    (25, "LOW"),
    (0, "INFO"),
)

BAND_COLORS = {
    "CRITICAL": "#b3261e",
    "HIGH": "#e8590c",
    "MEDIUM": "#c9a227",
    "LOW": "#2f6f4f",
    "INFO": "#4a6572",
}


def band(score: int) -> str:
    for threshold, name in RISK_BANDS:
        if score >= threshold:
            return name
    return "INFO"


def frequency_score(count: int) -> int:
    """Volume, on a deliberately flat curve.

    Five failed logins and five hundred are different; five hundred and five
    thousand are not, for triage purposes.
    """
    if count <= 1:
        return 0
    if count <= 5:
        return 3
    if count <= 20:
        return 6
    if count <= 100:
        return 8
    return MAX_FREQUENCY


def _apply_cap(factors: dict[str, int], cap: int) -> tuple[int, dict[str, int]]:
    """Trim a factor breakdown so it sums to at most ``cap``.

    Capping the total while reporting uncapped factors would make the "why this
    score" breakdown disagree with the score itself, which defeats the point of
    showing it. Factors are taken in order until the cap is reached; the last
    one to fit is trimmed and anything past the cap is dropped.
    """
    applied: dict[str, int] = {}
    remaining = cap
    for reason, points in factors.items():
        if remaining <= 0:
            break
        granted = min(points, remaining)
        applied[reason] = granted
        remaining -= granted
    return sum(applied.values()), applied


def context_score(alert: Alert, config: DetectionConfig) -> tuple[int, dict[str, int]]:
    """Asset criticality, account privilege, and whether it came from outside."""
    factors: dict[str, int] = {}
    meta = alert.metadata

    privileged = bool(meta.get("privileged_account")) or config.is_privileged_user(alert.username)
    if privileged:
        factors["privileged account"] = 4
    if config.is_critical_asset(alert.host) or meta.get("critical_asset"):
        factors["business-critical asset"] = 4
    if alert.source_ip and not config.is_internal_ip(alert.source_ip):
        factors["external source address"] = 3
    if meta.get("successful_responses"):
        factors["payload reached the application"] = 4
    if meta.get("sensitive_activity") or meta.get("indicators"):
        factors["high-signal command indicators"] = 3

    return _apply_cap(factors, MAX_CONTEXT)


def correlation_score(alert: Alert) -> tuple[int, dict[str, int]]:
    """How much of an attack chain this alert is part of.

    Populated by ``correlation.engine`` once incidents exist; a standalone
    alert scores zero here, which is the point - the same brute force is worth
    less on its own than it is followed by a login and a privileged command.
    """
    factors: dict[str, int] = {}
    stages = int(alert.risk_factors.get("chain_stages", 0) or 0)
    sources = int(alert.risk_factors.get("chain_log_sources", 0) or 0)
    if stages > 1:
        factors[f"part of a {stages}-stage attack chain"] = min(10, (stages - 1) * 4)
    if sources > 1:
        factors["chain spans multiple log sources"] = 4
    return _apply_cap(factors, MAX_CORRELATION)


def calculate_risk(alert: Alert, config: Optional[DetectionConfig] = None) -> int:
    """Score one alert in place and return the score."""
    config = config or DetectionConfig()

    base = BASE_SEVERITY_SCORE.get(alert.severity, 20)
    frequency = frequency_score(alert.count)
    context, context_factors = context_score(alert, config)
    correlation, correlation_factors = correlation_score(alert)

    score = max(0, min(100, base + frequency + context + correlation))
    alert.risk = score
    alert.risk_band = band(score)
    alert.risk_factors.update({
        "base_severity": base,
        "frequency": frequency,
        "context": context,
        "correlation": correlation,
        "context_detail": context_factors,
        "correlation_detail": correlation_factors,
        "total": score,
    })
    return score


def score_alerts(alerts: Iterable[Alert],
                 config: Optional[DetectionConfig] = None) -> list[Alert]:
    config = config or DetectionConfig()
    alerts = list(alerts)
    for alert in alerts:
        calculate_risk(alert, config)
    return alerts


def calculate_incident_risk(alerts: list[Alert], stages: int = 0,
                            log_sources: int = 1) -> tuple[int, dict[str, Any]]:
    """Score a correlated incident.

    An incident is worth at least its worst alert, plus credit for how many
    distinct stages of an intrusion it covers. Ten brute force alerts are one
    problem; a brute force plus a login plus a privileged command plus an
    encoded PowerShell payload is a different problem.
    """
    if not alerts:
        return 0, {}

    worst = max(a.risk for a in alerts)
    stage_bonus = min(14, max(0, stages - 1) * 5)
    breadth_bonus = min(6, max(0, log_sources - 1) * 3)
    volume_bonus = min(4, max(0, len(alerts) - 1))

    score = max(0, min(100, worst + stage_bonus + breadth_bonus + volume_bonus))
    breakdown = {
        "highest_alert_risk": worst,
        "attack_chain_stages": stage_bonus,
        "multiple_log_sources": breadth_bonus,
        "alert_volume": volume_bonus,
        "total": score,
        "band": band(score),
    }
    return score, breakdown


def explain(alert: Alert) -> list[tuple[str, int]]:
    """Flatten an alert's score into ordered (reason, points) rows for the UI."""
    factors = alert.risk_factors
    rows: list[tuple[str, int]] = [
        (f"base severity ({alert.severity})", int(factors.get("base_severity", 0))),
    ]
    if factors.get("frequency"):
        rows.append((f"event frequency ({alert.count} events)", int(factors["frequency"])))
    for reason, points in (factors.get("context_detail") or {}).items():
        rows.append((reason, int(points)))
    for reason, points in (factors.get("correlation_detail") or {}).items():
        rows.append((reason, int(points)))

    # A maximal alert saturates the scale. Show that rather than leaving the
    # reader to wonder why the column does not add up.
    overflow = sum(points for _, points in rows) - alert.risk
    if overflow > 0:
        rows.append(("capped at the 100-point ceiling", -overflow))
    return rows
