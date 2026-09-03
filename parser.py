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
# How far back a successful login's own timestamp can reach to count a prior
# failed attempt as part of "the same" brute-force burst for the
# possible-compromise finding - see _build_findings.
COMPROMISE_LOOKBACK = datetime.timedelta(minutes=30)
# Cap how many full raw lines we retain per bucket in memory - beyond this we
# still count the attempt (for totals/severity) but stop holding its text,
# since only MAX_SAMPLE_LINES of it is ever shown. Protects memory on a
# multi-million-line brute-force flood.
MAX_RETAINED_LINES_PER_BUCKET = MAX_SAMPLE_LINES

SUSPICIOUS_SUDO_RE = re.compile(
    r"\b(passwd|useradd|userdel|visudo|chmod\s+777|/bin/(ba)?sh|\bnc\b|netcat|wget|curl|base64\s+-d|python3?\s+-c)\b",
    re.IGNORECASE,
)

# Classic syslog format: "Mon D HH:MM:SS ..." (no year — see _parse_timestamp).
TIMESTAMP_RE = re.compile(r"^(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

# rsyslog (and other syslog daemons) collapse runs of identical consecutive
# messages into a single "message repeated N times: [ <original message> ]"
# line. Left unhandled, this silently undercounts brute-force volume - and it
# kicks in *more* under a heavier attack, hiding scale exactly when it
# matters. We unwrap it back to the original message and weight it by N.
MESSAGE_REPEATED_RE = re.compile(
    r"^(?P<prefix>.*?:)\s*message repeated (?P<n>\d+) times:\s*\[\s*(?P<inner>.*?)\s*\]\s*$"
)

# Syslog daemons on some distros (notably RHEL/CentOS) tag the facility itself
# with the PAM module name - e.g. "sshd(pam_unix)[1234]:" instead of
# "sshd[1234]:" - rather than only wrapping it inside the message body. Every
# program-name prefix below tolerates an optional "(...)" for this.
SSHD_PREFIX = r"sshd(?:\([^)]*\))?(?:\[\d+\])?:"
SUDO_PREFIX = r"sudo(?:\([^)]*\))?(?:\[\d+\])?:"
SU_PREFIX = r"su(?:\([^)]*\))?(?:\[\d+\])?:"

SSHD_FAILED_PASSWORD_RE = re.compile(
    SSHD_PREFIX + r"\s+Failed password for (?:invalid user )?(?P<user>\S+)"
    r" from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
SSHD_INVALID_USER_RE = re.compile(
    SSHD_PREFIX + r"\s+Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
SSHD_ACCEPTED_RE = re.compile(
    SSHD_PREFIX + r"\s+Accepted (?P<method>\S+) for (?P<user>\S+)"
    r" from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
# The RHEL/CentOS-style facility tag above doesn't get an OpenSSH-native
# "Failed password" line at all for many auth failures - PAM logs its own
# generic message instead. We only match this when the PAM tag is on the
# facility itself (sshd(pam_unix)[...]) to avoid double-counting against
# OpenSSH's own embedded "pam_unix(sshd:auth): authentication failure" lines
# (seen on standard OpenSSH logs), which use an unwrapped sshd[pid]: facility.
PAM_AUTH_FAILURE_RE = re.compile(
    r"sshd\([^)]*\)(?:\[\d+\])?:\s+authentication failure;.*?\brhost=(?P<ip>\S+)"
    r"(?:\s+user=(?P<user>\S+))?"
)
SUDO_COMMAND_RE = re.compile(
    SUDO_PREFIX + r"\s*(?P<user>\S+)\s*:.*?USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)$"
)
# su's own PAM module logs successes as "session opened for user <target> by
# <actor>(uid=<n>)" - <actor> is blank when root/system performed it directly
# (e.g. "by (uid=0)"). This is the standard message on virtually every modern
# distro; the two alternatives after it are kept for older/rarer formats.
SU_SUCCESS_RE = re.compile(
    SU_PREFIX + r"\s*(?:pam_unix\([^)]*\):\s*)?"
    r"(?:session opened for user (?P<target_user3>\S+) by (?P<user3>\S*)\(uid=\d+\)"
    r"|\(to (?P<target_user1>\S+)\)\s*(?P<user1>\S+) on"
    r"|Successful su for (?P<target_user2>\S+) by (?P<user2>\S+))"
)

LINUX_AUTH_SIGNATURE_RE = re.compile(
    SSHD_PREFIX + r"|" + SUDO_PREFIX + r"\s|" + SU_PREFIX + r"\s"
)


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


def _normalize_for_matching(line: str) -> str:
    # Malformed/irregular runs of whitespace (rare, but seen in the wild - a
    # doubled space in a field breaks patterns that hardcode single spaces)
    # shouldn't silently drop an otherwise-parseable line.
    return re.sub(r"[ \t]+", " ", line)


def _unwrap_repeated(line: str) -> tuple[str, int]:
    match = MESSAGE_REPEATED_RE.match(line)
    if not match:
        return line, 1
    n = int(match.group("n"))
    return f"{match.group('prefix')} {match.group('inner')}", max(n, 1)


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

    for raw_line in lines:
        ts = _parse_timestamp(raw_line)
        if ts:
            timestamps.append(ts)

        # Match against a normalized/unwrapped copy (irregular whitespace and
        # rsyslog's "message repeated N times: [...]" collapsing both defeat
        # the regexes below otherwise), but keep the original raw text as the
        # evidence line shown to the user.
        line, weight = _unwrap_repeated(_normalize_for_matching(raw_line))
        stored_line = raw_line.strip()

        match = SSHD_FAILED_PASSWORD_RE.search(line)
        if match:
            parsed_lines += 1
            ip = match.group("ip")
            bucket = failed_by_ip[ip]
            entry_line = stored_line if len(bucket) < MAX_RETAINED_LINES_PER_BUCKET else None
            bucket.append({"user": match.group("user"), "ts": ts, "line": entry_line, "weight": weight})
            if "invalid user" in line:
                invalid_users_by_ip[ip].add(match.group("user"))
            continue

        match = SSHD_INVALID_USER_RE.search(line)
        if match:
            parsed_lines += 1
            invalid_users_by_ip[match.group("ip")].add(match.group("user"))
            continue

        match = PAM_AUTH_FAILURE_RE.search(line)
        if match:
            parsed_lines += 1
            ip = match.group("ip")
            bucket = failed_by_ip[ip]
            entry_line = stored_line if len(bucket) < MAX_RETAINED_LINES_PER_BUCKET else None
            bucket.append(
                {"user": match.group("user") or "(unknown)", "ts": ts, "line": entry_line, "weight": weight}
            )
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
                    "line": stored_line,
                    "weight": weight,
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
                    "line": stored_line,
                    "weight": weight,
                }
            )
            continue

        match = SU_SUCCESS_RE.search(line)
        if match:
            parsed_lines += 1
            su_events.append(
                {
                    # Empty when root/system performed the su directly (e.g.
                    # "session opened for user X by (uid=0)") - never leave
                    # this None, since it lands in a set that later gets
                    # sorted() alongside real usernames.
                    "user": match.group("user1") or match.group("user2") or match.group("user3") or "(root)",
                    "target_user": (
                        match.group("target_user1")
                        or match.group("target_user2")
                        or match.group("target_user3")
                    ),
                    "ts": ts,
                    "line": stored_line,
                    "weight": weight,
                }
            )
            continue

    findings = _build_findings(failed_by_ip, invalid_users_by_ip, accepted_events, sudo_events, su_events)
    findings.sort(key=lambda f: _severity_rank(f.severity))

    summary = {
        "failed_logins": sum(a["weight"] for attempts in failed_by_ip.values() for a in attempts),
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
        count = sum(a["weight"] for a in attempts)
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
                sample_lines=[a["line"] for a in attempts[:MAX_SAMPLE_LINES] if a["line"]],
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
        # Only password-based logins can plausibly be the result of a
        # brute-forced/guessed password - a key-based (publickey) success
        # right after unrelated password failures from the same IP isn't
        # evidence of anything (the two credentials are unrelated).
        if event["method"] != "password":
            continue
        ip = event["ip"]
        # Require both timestamps and a tight lookback window: without this,
        # a single old brute-force burst permanently poisons every future
        # login from that IP, including a legitimate one months later (IPs
        # get reassigned/shared/NAT'd). A miss when timestamps fail to parse
        # is the safer tradeoff than that kind of standing false positive.
        prior_failures = [
            a
            for a in failed_by_ip.get(ip, [])
            if event["ts"]
            and a["ts"]
            and a["ts"] <= event["ts"]
            and event["ts"] - a["ts"] <= COMPROMISE_LOOKBACK
        ]
        prior_count = sum(a["weight"] for a in prior_failures)
        if prior_count >= BRUTE_FORCE_THRESHOLD:
            findings.append(
                Finding(
                    id=f"compromise_suspected_{ip}_{event['user']}",
                    title=f"Successful login from {ip} after repeated failures",
                    severity="critical",
                    category="possible_compromise",
                    description=(
                        f"{ip} succeeded logging in as '{event['user']}' via "
                        f"{event['method']} after {prior_count} prior "
                        "failed attempts within "
                        f"{int(COMPROMISE_LOOKBACK.total_seconds() // 60)} minutes — "
                        "the credentials may have been guessed or brute-forced."
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
        root_count = sum(e["weight"] for e in root_logins)
        times = [e["ts"] for e in root_logins if e["ts"]]
        findings.append(
            Finding(
                id="root_login_success",
                title="Direct root login(s) succeeded",
                severity="high",
                category="privilege_escalation",
                description=(
                    f"{root_count} successful direct login(s) as root from "
                    f"{len({e['ip'] for e in root_logins})} source IP(s). Direct "
                    "root SSH access is best avoided."
                ),
                count=root_count,
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
        off_hours_count = sum(e["weight"] for e in off_hours)
        times = [e["ts"] for e in off_hours]
        findings.append(
            Finding(
                id="off_hours_logins",
                title="Logins during unusual hours",
                severity="low",
                category="anomaly",
                description=(
                    f"{off_hours_count} successful login(s) between "
                    f"{OFF_HOURS_START:02d}:00 and {OFF_HOURS_END:02d}:00, "
                    "outside typical working hours."
                ),
                count=off_hours_count,
                source_ips=sorted({e["ip"] for e in off_hours})[:MAX_LISTED_ITEMS],
                users=sorted({e["user"] for e in off_hours})[:MAX_LISTED_ITEMS],
                first_seen=_fmt(min(times)),
                last_seen=_fmt(max(times)),
                sample_lines=[e["line"] for e in off_hours[:MAX_SAMPLE_LINES]],
            )
        )

    suspicious_sudo = [e for e in sudo_events if SUSPICIOUS_SUDO_RE.search(e["command"])]
    if suspicious_sudo:
        suspicious_sudo_count = sum(e["weight"] for e in suspicious_sudo)
        times = [e["ts"] for e in suspicious_sudo if e["ts"]]
        findings.append(
            Finding(
                id="suspicious_sudo_commands",
                title="Sensitive commands run via sudo",
                severity="high",
                category="privilege_escalation",
                description=(
                    f"{suspicious_sudo_count} sudo command(s) matched sensitive "
                    "patterns (user/password management, shells, network tools, "
                    "encoded payloads)."
                ),
                count=suspicious_sudo_count,
                users=sorted({e["user"] for e in suspicious_sudo})[:MAX_LISTED_ITEMS],
                first_seen=_fmt(min(times)) if times else None,
                last_seen=_fmt(max(times)) if times else None,
                sample_lines=[e["line"] for e in suspicious_sudo[:MAX_SAMPLE_LINES]],
            )
        )

    su_root = [e for e in su_events if e["target_user"] == "root"]
    if su_root:
        su_root_count = sum(e["weight"] for e in su_root)
        findings.append(
            Finding(
                id="su_to_root",
                title="Users switched to root via su",
                severity="medium",
                category="privilege_escalation",
                description=f"{su_root_count} successful 'su' session(s) to root.",
                count=su_root_count,
                users=sorted({e["user"] for e in su_root})[:MAX_LISTED_ITEMS],
                sample_lines=[e["line"] for e in su_root[:MAX_SAMPLE_LINES]],
            )
        )

    return findings
