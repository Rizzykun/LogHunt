"""Detection 5: suspected web attacks and content-discovery scanning.

Signature matching on URIs is cheap and noisy, so two things keep it honest:

* requests are URL-decoded (twice, to catch double-encoded traversal) and
  lower-cased before matching, so trivial evasion does not slip past;
* every finding is worded as *suspected*. A string match proves an attack was
  attempted, never that it succeeded - so the HTTP status is reported beside
  it, since a 200 on an injection attempt is what changes an analyst's day.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote_plus

import pandas as pd

from parser.schema import WEB_REQUEST

from .base import Alert, DetectionConfig

WEB_ATTACK_RULE_ID = "LH-008"
SCAN_RULE_ID = "LH-009"


@dataclass(frozen=True)
class Signature:
    category: str
    pattern: re.Pattern
    severity: str
    mitre: tuple[str, ...]
    note: str


SIGNATURES: tuple[Signature, ...] = (
    Signature(
        "SQL Injection",
        re.compile(r"union\s+(?:all\s+)?select|\bor\s+1\s*=\s*1\b|'\s*or\s*'|information_schema"
                   r"|\bsleep\s*\(|benchmark\s*\(|\bwaitfor\s+delay\b|concat\s*\(.*0x"),
        "high",
        ("T1190",),
        "SQL syntax in a request parameter",
    ),
    Signature(
        "Path Traversal",
        re.compile(r"\.\./|\.\.\\|/\.\.%2f|%2e%2e[/\\]"),
        "high",
        ("T1190", "T1083"),
        "directory traversal sequence",
    ),
    Signature(
        "Local File Inclusion",
        re.compile(r"/etc/passwd|/etc/shadow|/proc/self/environ|boot\.ini|win\.ini"
                   r"|php://(?:input|filter)|file://"),
        "high",
        ("T1190", "T1083"),
        "reference to a sensitive local file",
    ),
    Signature(
        "Cross-Site Scripting",
        re.compile(r"<script|javascript:|onerror\s*=|onload\s*=|<svg|<img[^>]+src\s*="
                   r"|document\.cookie|alert\s*\("),
        "medium",
        ("T1190",),
        "script markup in a request parameter",
    ),
    Signature(
        "Command Injection",
        re.compile(r"[;|&`]\s*(?:cat|ls|id|whoami|uname|curl|wget|nc|bash|sh|powershell)\b"
                   r"|\bcmd\s*=|\bexec\s*=|\$\(.*\)|%0a"),
        "critical",
        ("T1190", "T1059"),
        "shell metacharacters with a command",
    ),
    Signature(
        "Web Shell Access",
        re.compile(r"/(?:c99|r57|shell|cmd|backdoor|wso|b374k|webshell)[\w\-]*\.(?:php|asp|aspx|jsp)"
                   r"|/uploads?/[\w\-]+\.(?:php|jsp|aspx)"),
        "critical",
        ("T1505.003",),
        "request for a file name typical of a web shell",
    ),
    Signature(
        "Server-Side Template / Code Injection",
        re.compile(r"\{\{.*\}\}|\$\{.*\}|<\?php|eval\s*\(|base64_decode\s*\("),
        "high",
        ("T1190",),
        "template or code-evaluation syntax",
    ),
    Signature(
        "Sensitive Path Probing",
        re.compile(r"/\.(?:git|env|svn|aws|ssh)\b|/\.git/config|/wp-config\.php|/phpmyadmin"
                   r"|/\.ds_store|/backup\.(?:zip|sql|tar\.gz)|/config\.(?:php|json|yml)"),
        "medium",
        ("T1595.003",),
        "request for a path that should not be exposed",
    ),
)

# User agents that announce themselves. Not proof of malice - a pentest and an
# attack look identical here - but worth surfacing.
SCANNER_UA_RE = re.compile(
    r"sqlmap|nikto|nmap|masscan|dirbuster|gobuster|feroxbuster|wpscan|acunetix|nessus"
    r"|zgrab|hydra|havij|arachni|w3af|metasploit",
    re.IGNORECASE,
)


def _decode(value: str) -> str:
    """URL-decode twice and lower-case, to defeat simple encoding tricks."""
    text = str(value or "")
    for _ in range(2):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return text.lower()


def detect_signatures(events: pd.DataFrame,
                      config: DetectionConfig | None = None) -> list[Alert]:
    config = config or DetectionConfig()
    requests = events[events["event_type"] == WEB_REQUEST] if not events.empty else events
    if requests.empty:
        return []

    requests = requests.copy()
    # Match against the decoded URI plus the raw line, so payloads sent in the
    # user agent or referrer are not missed.
    haystack = (requests["uri"].fillna("").astype(str) + " "
                + requests["raw"].fillna("").astype(str)).map(_decode)
    requests["_haystack"] = haystack

    alerts: list[Alert] = []
    for signature in SIGNATURES:
        hits = requests[requests["_haystack"].str.contains(signature.pattern, regex=True,
                                                           na=False)]
        if hits.empty:
            continue
        for source_ip, group in hits.groupby("source_ip", sort=False):
            endpoints = group["uri"].astype(str).str.split("?").str[0].unique().tolist()
            successful = group[group["http_status"].between(200, 299, inclusive="both")]
            severity = signature.severity
            if not successful.empty and severity in ("medium", "high"):
                # A 2xx means the application processed the payload.
                severity = "high" if severity == "medium" else "critical"

            sample = str(group["uri"].iloc[0])[:200]
            status_counts = (group["http_status"].dropna().astype(int)
                             .value_counts().sort_index())
            status_summary = ", ".join(f"{int(k)} x{int(v)}" for k, v in status_counts.items())

            alerts.append(Alert(
                rule_id=WEB_ATTACK_RULE_ID,
                name=f"Suspected Web Attack: {signature.category}",
                severity=severity,
                category="Initial Access",
                description=(
                    f"{len(group)} request(s) from {source_ip} matched {signature.category} "
                    f"indicators ({signature.note}) across {len(endpoints)} endpoint(s). "
                    f"Response codes: {status_summary or 'unknown'}. "
                    f"Example: {sample}"
                    + ("" if successful.empty else
                       f" - {len(successful)} of these returned 2xx, so the payload reached "
                       f"the application and the response needs review.")
                ),
                first_seen=group["timestamp"].min(),
                last_seen=group["timestamp"].max(),
                source_ip=source_ip,
                username=next((u for u in group["username"] if u), ""),
                host=next((h for h in group["host"] if h), ""),
                count=len(group),
                evidence=group["event_id"].tolist(),
                mitre=list(signature.mitre),
                metadata={
                    "attack_class": signature.category,
                    "indicator": signature.note,
                    "endpoints": endpoints[:25],
                    "requests": len(group),
                    "successful_responses": int(len(successful)),
                    "status_codes": {int(k): int(v) for k, v in status_counts.items()},
                    "user_agents": [u for u in group["user_agent"].unique().tolist() if u][:5],
                    "example_request": sample,
                },
            ))
    return alerts


def detect_scanning(events: pd.DataFrame,
                    config: DetectionConfig | None = None) -> list[Alert]:
    """Bursts of 404s, or a self-identifying scanner, from one source."""
    config = config or DetectionConfig()
    requests = events[events["event_type"] == WEB_REQUEST] if not events.empty else events
    if requests.empty:
        return []

    alerts: list[Alert] = []
    window = pd.Timedelta(minutes=config.scan_window_minutes)

    for source_ip, group in requests.groupby("source_ip", sort=False):
        group = group.sort_values("timestamp", kind="stable")
        agents = [a for a in group["user_agent"].unique().tolist() if a]
        scanner_agents = [a for a in agents if SCANNER_UA_RE.search(a)]

        not_found = group[group["http_status"] == 404]
        burst = pd.DataFrame()
        if len(not_found) >= config.scan_404_threshold and not_found["timestamp"].notna().all():
            stamps = not_found["timestamp"]
            counts = [
                ((stamps >= ts) & (stamps <= ts + window)).sum() for ts in stamps
            ]
            if max(counts, default=0) >= config.scan_404_threshold:
                burst = not_found

        if burst.empty and not scanner_agents:
            continue

        evidence_rows = burst if not burst.empty else group
        paths = evidence_rows["uri"].astype(str).str.split("?").str[0].nunique()
        severity = "medium"
        if scanner_agents:
            severity = "high"
        reasons = []
        if not burst.empty:
            reasons.append(f"{len(burst)} HTTP 404 responses across {paths} distinct paths")
        if scanner_agents:
            reasons.append(f"user agent identifies as a scanner ({', '.join(scanner_agents[:3])})")

        alerts.append(Alert(
            rule_id=SCAN_RULE_ID,
            name="Possible Content Discovery Scan",
            severity=severity,
            category="Reconnaissance",
            description=(
                f"{source_ip} shows scanning behaviour: " + "; ".join(reasons)
                + f". Total requests from this source: {len(group)}."
            ),
            first_seen=evidence_rows["timestamp"].min(),
            last_seen=evidence_rows["timestamp"].max(),
            source_ip=source_ip,
            host=next((h for h in group["host"] if h), ""),
            count=len(evidence_rows),
            evidence=evidence_rows["event_id"].tolist()[:500],
            mitre=["T1595.003", "T1046"] if not burst.empty else ["T1595.003"],
            metadata={
                "total_requests": len(group),
                "not_found_responses": int(len(not_found)),
                "distinct_paths": int(paths),
                "scanner_user_agents": scanner_agents[:5],
            },
        ))
    return alerts


def detect(events: pd.DataFrame, config: DetectionConfig | None = None) -> list[Alert]:
    return detect_signatures(events, config) + detect_scanning(events, config)
