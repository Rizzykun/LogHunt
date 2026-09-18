"""The slice of MITRE ATT&CK this toolkit actually uses.

Only techniques a detection can justify from log evidence are listed. Mapping
a rule to a technique it cannot really prove makes coverage charts look good
and investigations worse.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    tid: str
    name: str
    tactics: tuple[str, ...]

    @property
    def url(self) -> str:
        parts = self.tid.split(".")
        if len(parts) == 2:
            return f"https://attack.mitre.org/techniques/{parts[0]}/{parts[1]}/"
        return f"https://attack.mitre.org/techniques/{self.tid}/"

    @property
    def label(self) -> str:
        return f"{self.tid} - {self.name}"


TECHNIQUES: dict[str, Technique] = {
    t.tid: t
    for t in [
        Technique("T1110", "Brute Force", ("Credential Access",)),
        Technique("T1110.001", "Brute Force: Password Guessing", ("Credential Access",)),
        Technique("T1110.003", "Brute Force: Password Spraying", ("Credential Access",)),
        Technique("T1078", "Valid Accounts",
                  ("Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access")),
        Technique("T1021.001", "Remote Services: Remote Desktop Protocol", ("Lateral Movement",)),
        Technique("T1059.001", "Command and Scripting Interpreter: PowerShell", ("Execution",)),
        Technique("T1059.003", "Command and Scripting Interpreter: Windows Command Shell",
                  ("Execution",)),
        Technique("T1059.005", "Command and Scripting Interpreter: Visual Basic", ("Execution",)),
        Technique("T1059.004", "Command and Scripting Interpreter: Unix Shell", ("Execution",)),
        Technique("T1027", "Obfuscated Files or Information", ("Defense Evasion",)),
        Technique("T1105", "Ingress Tool Transfer", ("Command and Control",)),
        Technique("T1218.011", "System Binary Proxy Execution: Rundll32", ("Defense Evasion",)),
        Technique("T1218.005", "System Binary Proxy Execution: Mshta", ("Defense Evasion",)),
        Technique("T1218.010", "System Binary Proxy Execution: Regsvr32", ("Defense Evasion",)),
        Technique("T1003", "OS Credential Dumping", ("Credential Access",)),
        Technique("T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow",
                  ("Credential Access",)),
        Technique("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
                  ("Privilege Escalation", "Defense Evasion")),
        Technique("T1136.001", "Create Account: Local Account", ("Persistence",)),
        Technique("T1098", "Account Manipulation", ("Persistence", "Privilege Escalation")),
        Technique("T1070.001", "Indicator Removal: Clear Windows Event Logs",
                  ("Defense Evasion",)),
        Technique("T1190", "Exploit Public-Facing Application", ("Initial Access",)),
        Technique("T1505.003", "Server Software Component: Web Shell", ("Persistence",)),
        Technique("T1046", "Network Service Discovery", ("Discovery",)),
        Technique("T1595.003", "Active Scanning: Wordlist Scanning", ("Reconnaissance",)),
        Technique("T1083", "File and Directory Discovery", ("Discovery",)),
        Technique("T1087", "Account Discovery", ("Discovery",)),
        Technique("T1082", "System Information Discovery", ("Discovery",)),
        Technique("T1057", "Process Discovery", ("Discovery",)),
        Technique("T1053.005", "Scheduled Task/Job: Scheduled Task", ("Execution", "Persistence")),
        Technique("T1569.002", "System Services: Service Execution", ("Execution",)),
    ]
}

# Rough ordering of tactics along an intrusion, used to sort attack chains.
TACTIC_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def get(tid: str) -> Technique:
    """Look up a technique, tolerating ids this catalog does not carry."""
    if tid in TECHNIQUES:
        return TECHNIQUES[tid]
    return Technique(tid, "Unmapped technique", ())


def label(tid: str) -> str:
    return get(tid).label


def tactics_for(tids) -> list[str]:
    """Tactics covered by a set of technique ids, in intrusion order."""
    found: set[str] = set()
    for tid in tids:
        found.update(get(tid).tactics)
    ordered = [t for t in TACTIC_ORDER if t in found]
    return ordered + sorted(found - set(ordered))
