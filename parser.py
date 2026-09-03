import datetime
import re
from collections import defaultdict

from models import Finding, LogAnalysisResponse, TimeRange

# --- Detection thresholds (tune here) ---
BRUTE_FORCE_THRESHOLD = 5  # failed SSH attempts from one source IP
SCAN_USER_THRESHOLD = 5  # distinct invalid usernames tried from one source IP
OFF_HOURS_START = 0  # inclusive, 24h clock, local to whatever produced the log
OFF_HOURS_END = 5  # exclusive
MAX_SAMPLE_LINES = 5
MAX_LISTED_ITEMS = 10

SUSPICIOUS_SUDO_RE = re.compile(
    r"\b(passwd|useradd|userdel|visudo|chmod\s+777|/bin/(ba)?sh|\bnc\b|netcat|wget|curl|base64\s+-d|python3?\s+-c)\b",
    re.IGNORECASE,
)

# Classic syslog format: "Mon D HH:MM:SS ..." (no year — see _parse_timestamp).
TIMESTAMP_RE = re.compile(r"^(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

SSHD_FAILED_PASSWORD_RE = re.compile(
    r"sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>\S+)"
    r" from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
SSHD_INVALID_USER_RE = re.compile(
    r"sshd\[\d+\]:\s+Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
SSHD_ACCEPTED_RE = re.compile(
    r"sshd\[\d+\]:\s+Accepted (?P<method>\S+) for (?P<user>\S+)"
    r" from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
SUDO_COMMAND_RE = re.compile(
    r"sudo(?:\[\d+\])?:\s*(?P<user>\S+)\s*:.*?USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)$"
)
SU_SUCCESS_RE = re.compile(
    r"su(?:\[\d+\])?:\s*(?:\(to (?P<target_user1>\S+)\)\s*(?P<user1>\S+) on"
    r"|Successful su for (?P<target_user2>\S+) by (?P<user2>\S+))"
)

LINUX_AUTH_SIGNATURE_RE = re.compile(r"sshd\[\d+\]:|sudo(?:\[\d+\])?:\s")


def _parse_timestamp(line: str) -> datetime.datetime | None:
    match = TIMESTAMP_RE.match(line)
    if not match:
        return None
    ts = re.sub(r"\s+", " ", match.group("ts"))
    try:
        parsed = datetime.datetime.strptime(ts, "%b %d %H:%M:%S")
    except ValueError:
        return None
    # Syslog timestamps have no year; assume the current year, rolling back
    # one if that would put the entry implausibly in the future.
    now = datetime.datetime.now()
    parsed = parsed.replace(year=now.year)
    if parsed > now + datetime.timedelta(days=1):
        parsed = parsed.replace(year=now.year - 1)
    return parsed


def _fmt(ts: datetime.datetime | None) -> str | None:
    return ts.isoformat() if ts else None


def _severity_rank(severity: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(severity, 5)


def detect_log_type(lines: list[str]) -> str:
    sample = lines[:200]
    if not sample:
        return "unknown"
    hits = sum(1 for line in sample if LINUX_AUTH_SIGNATURE_RE.search(line))
    if hits >= 3 or hits / len(sample) > 0.1:
        return "linux_auth"
    return "unknown"


def analyze_log_content(content: str) -> LogAnalysisResponse:
    lines = content.splitlines()
    log_type = detect_log_type(lines)

    if log_type == "linux_auth":
        return _analyze_linux_auth(lines)

    return LogAnalysisResponse(
        log_type=log_type,
        total_lines=len(lines),
        parsed_lines=0,
        time_range=TimeRange(),
        findings=[],
        summary={
            "note": (
                "This doesn't look like a supported log format yet. Currently "
                "supported: Linux auth.log (sshd/sudo). More formats are "
                "being added."
            )
        },
    )


def _analyze_linux_auth(lines: list[str]) -> LogAnalysisResponse:
    failed_by_ip: dict[str, list[dict]] = defaultdict(list)
    invalid_users_by_ip: dict[str, set[str]] = defaultdict(set)
    accepted_events: list[dict] = []
    sudo_events: list[dict] = []
    su_events: list[dict] = []

    parsed_lines = 0
    timestamps: list[datetime.datetime] = []

    for line in lines:
        ts = _parse_timestamp(line)
        if ts:
            timestamps.append(ts)

        match = SSHD_FAILED_PASSWORD_RE.search(line)
        if match:
            parsed_lines += 1
            failed_by_ip[match.group("ip")].append(
                {"user": match.group("user"), "ts": ts, "line": line.strip()}
            )
            if "invalid user" in line:
                invalid_users_by_ip[match.group("ip")].add(match.group("user"))
            continue

        match = SSHD_INVALID_USER_RE.search(line)
        if match:
            parsed_lines += 1
            invalid_users_by_ip[match.group("ip")].add(match.group("user"))
            continue

        match = SSHD_ACCEPTED_RE.search(line)
        if match:
            parsed_lines += 1
            accepted_events.append(
                {
                    "user": match.group("user"),
                    "ip": match.group("ip"),
                    "method": match.group("method"),
                    "ts": ts,
                    "line": line.strip(),
                }
            )
            continue

        match = SUDO_COMMAND_RE.search(line)
        if match:
            parsed_lines += 1
            sudo_events.append(
                {
                    "user": match.group("user"),
                    "target_user": match.group("target_user"),
                    "command": match.group("command").strip(),
                    "ts": ts,
                    "line": line.strip(),
                }
            )
            continue

        match = SU_SUCCESS_RE.search(line)
        if match:
            parsed_lines += 1
            su_events.append(
                {
                    "user": match.group("user1") or match.group("user2"),
                    "target_user": match.group("target_user1") or match.group("target_user2"),
                    "ts": ts,
                    "line": line.strip(),
                }
            )
            continue

    findings = _build_findings(failed_by_ip, invalid_users_by_ip, accepted_events, sudo_events, su_events)
    findings.sort(key=lambda f: _severity_rank(f.severity))

    summary = {
        "failed_logins": sum(len(v) for v in failed_by_ip.values()),
        "successful_logins": len(accepted_events),
        "unique_attacking_ips": len(failed_by_ip),
        "unique_usernames_tried": len(
            {a["user"] for attempts in failed_by_ip.values() for a in attempts}
        ),
        "sudo_commands": len(sudo_events),
    }

    return LogAnalysisResponse(
        log_type="linux_auth",
        total_lines=len(lines),
        parsed_lines=parsed_lines,
        time_range=TimeRange(
            start=_fmt(min(timestamps)) if timestamps else None,
            end=_fmt(max(timestamps)) if timestamps else None,
        ),
        findings=findings,
        summary=summary,
    )


def _build_findings(failed_by_ip, invalid_users_by_ip, accepted_events, sudo_events, su_events) -> list[Finding]:
    findings: list[Finding] = []

    for ip, attempts in failed_by_ip.items():
        count = len(attempts)
        if count < BRUTE_FORCE_THRESHOLD:
            continue
        users = sorted({a["user"] for a in attempts})
        times = [a["ts"] for a in attempts if a["ts"]]
        severity = "critical" if count >= 50 else "high" if count >= 20 else "medium"
        findings.append(
            Finding(
                id=f"brute_force_{ip}",
                title=f"Brute-force SSH attempts from {ip}",
                severity=severity,
                category="brute_force",
                description=(
                    f"{count} failed password attempts from {ip} against "
                    f"{len(users)} username(s): {', '.join(users[:MAX_LISTED_ITEMS])}"
                    f"{'…' if len(users) > MAX_LISTED_ITEMS else ''}."
                ),
                count=count,
                source_ips=[ip],
                users=users[:MAX_LISTED_ITEMS],
                first_seen=_fmt(min(times)) if times else None,
                last_seen=_fmt(max(times)) if times else None,
                sample_lines=[a["line"] for a in attempts[:MAX_SAMPLE_LINES]],
            )
        )

    for ip, users in invalid_users_by_ip.items():
        if len(users) < SCAN_USER_THRESHOLD:
            continue
        findings.append(
            Finding(
                id=f"user_enum_{ip}",
                title=f"Username enumeration from {ip}",
                severity="medium",
                category="reconnaissance",
                description=(
                    f"{ip} tried {len(users)} different non-existent usernames, "
                    "consistent with automated account scanning."
                ),
                count=len(users),
                source_ips=[ip],
                users=sorted(users)[:MAX_LISTED_ITEMS],
            )
        )

    for event in accepted_events:
        ip = event["ip"]
        prior_failures = [
            a
            for a in failed_by_ip.get(ip, [])
            if not event["ts"] or not a["ts"] or a["ts"] <= event["ts"]
        ]
        if len(prior_failures) >= BRUTE_FORCE_THRESHOLD:
            findings.append(
                Finding(
                    id=f"compromise_suspected_{ip}_{event['user']}",
                    title=f"Successful login from {ip} after repeated failures",
                    severity="critical",
                    category="possible_compromise",
                    description=(
                        f"{ip} succeeded logging in as '{event['user']}' via "
                        f"{event['method']} after {len(prior_failures)} prior "
                        "failed attempts — the credentials may have been "
                        "guessed or brute-forced."
                    ),
                    count=1,
                    source_ips=[ip],
                    users=[event["user"]],
                    first_seen=_fmt(event["ts"]),
                    last_seen=_fmt(event["ts"]),
                    sample_lines=[event["line"]],
                )
            )

    root_logins = [e for e in accepted_events if e["user"] == "root"]
    if root_logins:
        times = [e["ts"] for e in root_logins if e["ts"]]
        findings.append(
            Finding(
                id="root_login_success",
                title="Direct root login(s) succeeded",
                severity="high",
                category="privilege_escalation",
                description=(
                    f"{len(root_logins)} successful direct login(s) as root from "
                    f"{len({e['ip'] for e in root_logins})} source IP(s). Direct "
                    "root SSH access is best avoided."
                ),
                count=len(root_logins),
                source_ips=sorted({e["ip"] for e in root_logins}),
                users=["root"],
                first_seen=_fmt(min(times)) if times else None,
                last_seen=_fmt(max(times)) if times else None,
                sample_lines=[e["line"] for e in root_logins[:MAX_SAMPLE_LINES]],
            )
        )

    off_hours = [
        e for e in accepted_events if e["ts"] and OFF_HOURS_START <= e["ts"].hour < OFF_HOURS_END
    ]
    if off_hours:
        times = [e["ts"] for e in off_hours]
        findings.append(
            Finding(
                id="off_hours_logins",
                title="Logins during unusual hours",
                severity="low",
                category="anomaly",
                description=(
                    f"{len(off_hours)} successful login(s) between "
                    f"{OFF_HOURS_START:02d}:00 and {OFF_HOURS_END:02d}:00, "
                    "outside typical working hours."
                ),
                count=len(off_hours),
                source_ips=sorted({e["ip"] for e in off_hours})[:MAX_LISTED_ITEMS],
                users=sorted({e["user"] for e in off_hours})[:MAX_LISTED_ITEMS],
                first_seen=_fmt(min(times)),
                last_seen=_fmt(max(times)),
                sample_lines=[e["line"] for e in off_hours[:MAX_SAMPLE_LINES]],
            )
        )

    suspicious_sudo = [e for e in sudo_events if SUSPICIOUS_SUDO_RE.search(e["command"])]
    if suspicious_sudo:
        times = [e["ts"] for e in suspicious_sudo if e["ts"]]
        findings.append(
            Finding(
                id="suspicious_sudo_commands",
                title="Sensitive commands run via sudo",
                severity="high",
                category="privilege_escalation",
                description=(
                    f"{len(suspicious_sudo)} sudo command(s) matched sensitive "
                    "patterns (user/password management, shells, network tools, "
                    "encoded payloads)."
                ),
                count=len(suspicious_sudo),
                users=sorted({e["user"] for e in suspicious_sudo})[:MAX_LISTED_ITEMS],
                first_seen=_fmt(min(times)) if times else None,
                last_seen=_fmt(max(times)) if times else None,
                sample_lines=[e["line"] for e in suspicious_sudo[:MAX_SAMPLE_LINES]],
            )
        )

    su_root = [e for e in su_events if e["target_user"] == "root"]
    if su_root:
        findings.append(
            Finding(
                id="su_to_root",
                title="Users switched to root via su",
                severity="medium",
                category="privilege_escalation",
                description=f"{len(su_root)} successful 'su' session(s) to root.",
                count=len(su_root),
                users=sorted({e["user"] for e in su_root})[:MAX_LISTED_ITEMS],
                sample_lines=[e["line"] for e in su_root[:MAX_SAMPLE_LINES]],
            )
        )

    return findings
