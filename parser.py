import datetime
import re
from collections import defaultdict
from urllib.parse import unquote_plus

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

# --- Apache/Nginx access log (Combined/Common Log Format) ---
EXPLOIT_PROBE_THRESHOLD = 3  # exploit-pattern-matching requests from one IP
SCAN_404_THRESHOLD = 10  # distinct 404-returning paths from one IP
SENSITIVE_PATH_THRESHOLD = 3  # sensitive-path hits from one IP
WEB_BRUTE_FORCE_THRESHOLD = 8  # POSTs to an auth-looking path from one IP

WEB_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)
REQUEST_LINE_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+$")

# Real, well-documented payloads/signatures - not fabricated - drawn from how
# these tools/attacks actually appear in access logs.
EXPLOIT_PATTERN_RE = re.compile(
    r"union\s+select|select.+from|'\s*or\s*'?1'?\s*=\s*'?1|;\s*--|sleep\(\d|"
    r"benchmark\(|<script|onerror\s*=|javascript:|\.\./\.\./|"
    r"/etc/passwd|/etc/shadow|cmd\.exe|powershell|\$\{jndi:|"
    r"union.{0,20}select|eval\(|base64_decode\(|/wp-config\.php",
    re.IGNORECASE,
)
SCANNER_USER_AGENT_RE = re.compile(
    r"sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|acunetix|nessus|"
    r"w3af|havij|netsparker|nuclei|zgrab|metasploit",
    re.IGNORECASE,
)
SENSITIVE_PATH_RE = re.compile(
    r"/\.env\b|/\.git/config|/wp-login\.php|/wp-admin|/phpmyadmin|"
    r"/\.aws/credentials|/\.ssh/|/server-status|/config\.php\.bak|"
    r"/xmlrpc\.php|/\.htpasswd|/actuator/",
    re.IGNORECASE,
)
AUTH_PATH_RE = re.compile(r"/(?:wp-)?login|/admin/login|/signin|/xmlrpc\.php", re.IGNORECASE)

WEB_ACCESS_SIGNATURE_RE = re.compile(
    r'^\S+ \S+ \S+ \[[^\]]+\] "\S+ \S+ HTTP/[\d.]+" \d{3} \S+'
)

# --- Linux firewall logs (iptables/ufw LOG target via kernel/syslog) ---
PORT_SCAN_THRESHOLD = 15  # distinct destination ports from one source IP
BLOCKED_FLOOD_THRESHOLD = 30  # total blocked packets from one source IP
SENSITIVE_PORT_THRESHOLD = 3  # hits on commonly-exploited ports from one IP

# Netfilter always emits these key=value fields in this relative order
# (SRC, then DST, then PROTO, then SPT/DPT when present) regardless of which
# tool (raw iptables --log-prefix, ufw, firewalld) generated the line - the
# non-greedy .*? below relies on that fixed ordering, not just presence.
FIREWALL_FIELDS_RE = re.compile(
    r"\bSRC=(?P<src>[0-9a-fA-F:.]+)\b.*?"
    r"\bDST=(?P<dst>[0-9a-fA-F:.]+)\b.*?"
    r"\bPROTO=(?P<proto>\S+)\b"
    r"(?:.*?\bSPT=(?P<spt>\d+)\b)?"
    r"(?:.*?\bDPT=(?P<dpt>\d+)\b)?"
)
# ufw tags its own action; plain iptables --log-prefix text is whatever the
# admin configured, so we recognize the common conventions and otherwise
# default to "blocked" - a firewall LOG rule is set up to log drops/rejects
# in the overwhelming majority of real configs, not accepted traffic.
FIREWALL_ACTION_RE = re.compile(
    r"\[(?:UFW\s+)?(?P<action>BLOCK|ALLOW|ACCEPT|DENY|DROP|REJECT|AUDIT)\]",
    re.IGNORECASE,
)
# Ports frequently targeted by mass internet scanning/exploitation - not an
# exhaustive list, just enough to flag "someone is probing infrastructure
# ports," similar in spirit to SENSITIVE_PATH_RE for web logs.
SENSITIVE_PORTS = {
    23: "Telnet", 445: "SMB", 1433: "MSSQL", 2375: "Docker API",
    3306: "MySQL", 3389: "RDP", 5900: "VNC", 6379: "Redis",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

FIREWALL_SIGNATURE_RE = re.compile(r"\bSRC=[0-9a-fA-F:.]+\b.*\bDST=[0-9a-fA-F:.]+\b.*\bPROTO=\S+\b")

# --- Windows Event Log exports (wevtutil "/f:text" output) ---
# `wevtutil qe Security /f:text > security.txt` is the standard way to get a
# Windows security event log into a plaintext file - this is the format we
# target, not raw .evtx (binary) or the XML export.
WINDOWS_BRUTE_FORCE_THRESHOLD = 5  # failed logons from one source
WINDOWS_EVENT_HEADER_RE = re.compile(r"^Event\[\d+\]:\s*$")

WINDOWS_EVENT_ID_RE = re.compile(r"^\s*Event ID:\s*(?P<id>\d+)\s*$", re.MULTILINE)
WINDOWS_DATE_RE = re.compile(r"^\s*Date:\s*(?P<date>\S+)\s*$", re.MULTILINE)
WINDOWS_COMPUTER_RE = re.compile(r"^\s*Computer:\s*(?P<computer>\S+)\s*$", re.MULTILINE)
WINDOWS_LOGON_TYPE_RE = re.compile(r"^\s*Logon Type:\s*(?P<logon_type>\d+)\s*$", re.MULTILINE)
WINDOWS_SOURCE_IP_RE = re.compile(r"^\s*Source Network Address:\s*(?P<ip>\S+)\s*$", re.MULTILINE)
# Most of these event templates list the acting Subject's account first and
# the actual target account later (e.g. 4625's "Account For Which Logon
# Failed", 4732's "Member") - taking the *last* match consistently lands on
# the one that matters, since "-"/blank Subject fields are common and appear
# earlier in the block.
WINDOWS_ACCOUNT_NAME_RE = re.compile(r"^\s*Account Name:\s*(?P<name>\S+)\s*$", re.MULTILINE)
WINDOWS_GROUP_NAME_RE = re.compile(r"^\s*Group Name:\s*(?P<name>\S+)\s*$", re.MULTILINE)
WINDOWS_SERVICE_NAME_RE = re.compile(r"^\s*Service Name:\s*(?P<name>.+?)\s*$", re.MULTILINE)

WINDOWS_LOGON_TYPE_LABELS = {
    "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service",
    "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials",
    "10": "RemoteInteractive (RDP)", "11": "CachedInteractive",
}

WINDOWS_EVENT_FAILED_LOGON = "4625"
WINDOWS_EVENT_SUCCESSFUL_LOGON = "4624"
WINDOWS_EVENT_ACCOUNT_LOCKOUT = "4740"
WINDOWS_EVENT_ACCOUNT_CREATED = "4720"
WINDOWS_EVENT_PRIV_GROUP_CHANGE = {"4728", "4732", "4756"}  # global/local/universal group member added
WINDOWS_EVENT_AUDIT_LOG_CLEARED = "1102"
WINDOWS_EVENT_SERVICE_INSTALLED = {"7045", "4697"}


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


def _parse_web_timestamp(ts: str) -> datetime.datetime | None:
    # Apache/Nginx timestamps carry their own timezone offset, unlike
    # syslog's - e.g. "10/Oct/2023:13:55:36 -0700".
    try:
        return datetime.datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def _parse_windows_timestamp(ts: str) -> datetime.datetime | None:
    # wevtutil emits ISO-8601 UTC with a trailing "Z" and up to 7 fractional
    # digits (100ns ticks) - fromisoformat only accepts up to 6, so trim.
    ts = ts.strip().replace("Z", "+00:00")
    if "." in ts:
        head, _, tail = ts.partition(".")
        frac, _, tz = tail.partition("+")
        ts = f"{head}.{frac[:6]}+{tz}" if tz else f"{head}.{frac[:6]}"
    try:
        return datetime.datetime.fromisoformat(ts)
    except ValueError:
        return None


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
    auth_hits = sum(1 for line in sample if LINUX_AUTH_SIGNATURE_RE.search(line))
    if auth_hits >= 3 or auth_hits / len(sample) > 0.1:
        return "linux_auth"
    web_hits = sum(1 for line in sample if WEB_ACCESS_SIGNATURE_RE.search(line))
    if web_hits >= 3 or web_hits / len(sample) > 0.1:
        return "web_access"
    firewall_hits = sum(1 for line in sample if FIREWALL_SIGNATURE_RE.search(line))
    if firewall_hits >= 3 or firewall_hits / len(sample) > 0.1:
        return "firewall"
    windows_hits = sum(1 for line in sample if WINDOWS_EVENT_HEADER_RE.match(line))
    if windows_hits >= 3 or windows_hits / len(sample) > 0.1:
        return "windows_event"
    return "unknown"


def analyze_log_content(content: str) -> LogAnalysisResponse:
    lines = content.splitlines()
    log_type = detect_log_type(lines)

    if log_type == "linux_auth":
        return _analyze_linux_auth(lines)
    if log_type == "web_access":
        return _analyze_web_access(lines)
    if log_type == "firewall":
        return _analyze_firewall(lines)
    if log_type == "windows_event":
        return _analyze_windows_events(lines)

    return LogAnalysisResponse(
        log_type=log_type,
        total_lines=len(lines),
        parsed_lines=0,
        time_range=TimeRange(),
        findings=[],
        summary={
            "note": (
                "This doesn't look like a supported log format yet. Currently "
                "supported: Linux auth.log (sshd/sudo), Apache/Nginx access "
                "logs, firewall logs (iptables/ufw), Windows Event Log exports "
                "(wevtutil text format). More formats are being added."
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


def _analyze_web_access(lines: list[str]) -> LogAnalysisResponse:
    # Keyed by IP, holding every parsed request for that IP - unlike
    # failed_by_ip in the auth analyzer, this isn't capped at ingestion,
    # because each detector below filters a different heterogeneous subset
    # of it (an exploit-pattern hit might be request #200 for an IP that's
    # otherwise browsing normally) - truncating early could discard the
    # exact requests a detector is looking for.
    events_by_ip: dict[str, list[dict]] = defaultdict(list)

    parsed_lines = 0
    timestamps: list[datetime.datetime] = []

    for raw_line in lines:
        match = WEB_ACCESS_RE.search(raw_line)
        if not match:
            continue
        parsed_lines += 1

        ts = _parse_web_timestamp(match.group("ts"))
        if ts:
            timestamps.append(ts)

        request = match.group("request")
        req_match = REQUEST_LINE_RE.match(request)
        method = req_match.group("method") if req_match else None
        raw_path = req_match.group("path") if req_match else request
        try:
            decoded_path = unquote_plus(raw_path)
        except Exception:
            decoded_path = raw_path

        events_by_ip[match.group("ip")].append(
            {
                "method": method,
                "path": raw_path,
                "decoded_path": decoded_path,
                "status": match.group("status"),
                "agent": match.group("agent") or "",
                "ts": ts,
                "line": raw_line.strip(),
            }
        )

    findings = _build_web_findings(events_by_ip)
    findings.sort(key=lambda f: _severity_rank(f.severity))

    # Real-world testing (a genuine public web server's access log) showed
    # sensitive-path probing is usually *distributed* - many different bot
    # IPs each trying one path once, not one IP repeating it - which the
    # per-IP threshold above correctly doesn't alert on individually (that
    # would be constant noise; virtually every public server sees this).
    # Surface it in aggregate instead so it's not simply invisible.
    sensitive_ips = {
        ip
        for ip, evs in events_by_ip.items()
        for e in evs
        if SENSITIVE_PATH_RE.search(e["decoded_path"])
    }
    sensitive_requests = sum(
        1 for evs in events_by_ip.values() for e in evs if SENSITIVE_PATH_RE.search(e["decoded_path"])
    )

    summary = {
        "total_requests": sum(len(v) for v in events_by_ip.values()),
        "unique_source_ips": len(events_by_ip),
        "requests_4xx": sum(
            1 for evs in events_by_ip.values() for e in evs if e["status"].startswith("4")
        ),
        "requests_5xx": sum(
            1 for evs in events_by_ip.values() for e in evs if e["status"].startswith("5")
        ),
        "background_sensitive_path_probes": sensitive_requests,
        "background_sensitive_path_probe_ips": len(sensitive_ips),
    }

    return LogAnalysisResponse(
        log_type="web_access",
        total_lines=len(lines),
        parsed_lines=parsed_lines,
        time_range=TimeRange(
            start=_fmt(min(timestamps)) if timestamps else None,
            end=_fmt(max(timestamps)) if timestamps else None,
        ),
        findings=findings,
        summary=summary,
    )


def _build_web_findings(events_by_ip: dict[str, list[dict]]) -> list[Finding]:
    findings: list[Finding] = []

    for ip, events in events_by_ip.items():
        exploit_hits = [e for e in events if EXPLOIT_PATTERN_RE.search(e["decoded_path"])]
        if len(exploit_hits) >= EXPLOIT_PROBE_THRESHOLD:
            times = [e["ts"] for e in exploit_hits if e["ts"]]
            severity = "critical" if len(exploit_hits) >= 20 else "high"
            findings.append(
                Finding(
                    id=f"exploit_probing_{ip}",
                    title=f"Exploit/injection probing from {ip}",
                    severity=severity,
                    category="web_attack",
                    description=(
                        f"{len(exploit_hits)} request(s) from {ip} matched known "
                        "SQLi/XSS/path-traversal/RCE attack patterns."
                    ),
                    count=len(exploit_hits),
                    source_ips=[ip],
                    first_seen=_fmt(min(times)) if times else None,
                    last_seen=_fmt(max(times)) if times else None,
                    sample_lines=[e["line"] for e in exploit_hits[:MAX_SAMPLE_LINES]],
                )
            )

        scanner_hits = [e for e in events if SCANNER_USER_AGENT_RE.search(e["agent"])]
        if scanner_hits:
            times = [e["ts"] for e in scanner_hits if e["ts"]]
            agents = sorted({e["agent"] for e in scanner_hits})
            findings.append(
                Finding(
                    id=f"scanner_user_agent_{ip}",
                    title=f"Known scanning tool detected from {ip}",
                    severity="high",
                    category="reconnaissance",
                    description=(
                        f"{len(scanner_hits)} request(s) from {ip} used a known "
                        f"scanner/exploit-tool user-agent: "
                        f"{', '.join(agents[:MAX_LISTED_ITEMS])}."
                    ),
                    count=len(scanner_hits),
                    source_ips=[ip],
                    first_seen=_fmt(min(times)) if times else None,
                    last_seen=_fmt(max(times)) if times else None,
                    sample_lines=[e["line"] for e in scanner_hits[:MAX_SAMPLE_LINES]],
                )
            )

        sensitive_hits = [e for e in events if SENSITIVE_PATH_RE.search(e["decoded_path"])]
        if len(sensitive_hits) >= SENSITIVE_PATH_THRESHOLD:
            times = [e["ts"] for e in sensitive_hits if e["ts"]]
            paths = sorted({e["path"] for e in sensitive_hits})
            findings.append(
                Finding(
                    id=f"sensitive_path_probing_{ip}",
                    title=f"Sensitive path probing from {ip}",
                    severity="medium",
                    category="reconnaissance",
                    description=(
                        f"{len(sensitive_hits)} request(s) from {ip} targeted "
                        f"sensitive paths: {', '.join(paths[:MAX_LISTED_ITEMS])}"
                        f"{'…' if len(paths) > MAX_LISTED_ITEMS else ''}."
                    ),
                    count=len(sensitive_hits),
                    source_ips=[ip],
                    first_seen=_fmt(min(times)) if times else None,
                    last_seen=_fmt(max(times)) if times else None,
                    sample_lines=[e["line"] for e in sensitive_hits[:MAX_SAMPLE_LINES]],
                )
            )

        not_found = [e for e in events if e["status"] == "404"]
        distinct_404_paths = {e["path"] for e in not_found}
        if len(distinct_404_paths) >= SCAN_404_THRESHOLD:
            times = [e["ts"] for e in not_found if e["ts"]]
            findings.append(
                Finding(
                    id=f"scan_404_{ip}",
                    title=f"Directory/endpoint scanning from {ip}",
                    severity="medium",
                    category="reconnaissance",
                    description=(
                        f"{ip} requested {len(distinct_404_paths)} distinct "
                        "nonexistent paths, consistent with automated content "
                        "discovery (dirb/gobuster-style scanning)."
                    ),
                    count=len(distinct_404_paths),
                    source_ips=[ip],
                    first_seen=_fmt(min(times)) if times else None,
                    last_seen=_fmt(max(times)) if times else None,
                    sample_lines=[e["line"] for e in not_found[:MAX_SAMPLE_LINES]],
                )
            )

        auth_posts = [
            e for e in events if e["method"] == "POST" and AUTH_PATH_RE.search(e["decoded_path"])
        ]
        if len(auth_posts) >= WEB_BRUTE_FORCE_THRESHOLD:
            times = [e["ts"] for e in auth_posts if e["ts"]]
            paths = sorted({e["path"] for e in auth_posts})
            findings.append(
                Finding(
                    id=f"web_brute_force_{ip}",
                    title=f"Brute-force attempts on login endpoint from {ip}",
                    severity="high",
                    category="brute_force",
                    description=(
                        f"{len(auth_posts)} POST request(s) from {ip} to "
                        f"login-like endpoint(s): {', '.join(paths[:MAX_LISTED_ITEMS])}."
                    ),
                    count=len(auth_posts),
                    source_ips=[ip],
                    first_seen=_fmt(min(times)) if times else None,
                    last_seen=_fmt(max(times)) if times else None,
                    sample_lines=[e["line"] for e in auth_posts[:MAX_SAMPLE_LINES]],
                )
            )

    return findings


def _analyze_firewall(lines: list[str]) -> LogAnalysisResponse:
    events_by_src: dict[str, list[dict]] = defaultdict(list)

    parsed_lines = 0
    timestamps: list[datetime.datetime] = []

    for raw_line in lines:
        match = FIREWALL_FIELDS_RE.search(raw_line)
        if not match:
            continue
        parsed_lines += 1

        ts = _parse_timestamp(raw_line)
        if ts:
            timestamps.append(ts)

        action_match = FIREWALL_ACTION_RE.search(raw_line)
        action = action_match.group("action").upper() if action_match else "BLOCK"
        blocked = action not in ("ALLOW", "ACCEPT")

        events_by_src[match.group("src")].append(
            {
                "dst": match.group("dst"),
                "proto": match.group("proto"),
                "spt": match.group("spt"),
                "dpt": match.group("dpt"),
                "blocked": blocked,
                "ts": ts,
                "line": raw_line.strip(),
            }
        )

    findings = _build_firewall_findings(events_by_src)
    findings.sort(key=lambda f: _severity_rank(f.severity))

    blocked_events = [e for evs in events_by_src.values() for e in evs if e["blocked"]]
    # Same "distributed, one-off ambient scanning" pattern seen with web
    # sensitive-path probing - surface it in aggregate rather than
    # per-source-IP alerting, which would just be internet background noise.
    sensitive_srcs = {
        src
        for src, evs in events_by_src.items()
        for e in evs
        if e["blocked"] and e["dpt"] and int(e["dpt"]) in SENSITIVE_PORTS
    }
    sensitive_hits_total = sum(
        1
        for evs in events_by_src.values()
        for e in evs
        if e["blocked"] and e["dpt"] and int(e["dpt"]) in SENSITIVE_PORTS
    )

    summary = {
        "total_packets": sum(len(v) for v in events_by_src.values()),
        "blocked_packets": len(blocked_events),
        "unique_source_ips": len(events_by_src),
        "background_sensitive_port_probes": sensitive_hits_total,
        "background_sensitive_port_probe_ips": len(sensitive_srcs),
    }

    return LogAnalysisResponse(
        log_type="firewall",
        total_lines=len(lines),
        parsed_lines=parsed_lines,
        time_range=TimeRange(
            start=_fmt(min(timestamps)) if timestamps else None,
            end=_fmt(max(timestamps)) if timestamps else None,
        ),
        findings=findings,
        summary=summary,
    )


def _build_firewall_findings(events_by_src: dict[str, list[dict]]) -> list[Finding]:
    findings: list[Finding] = []

    for src, events in events_by_src.items():
        blocked = [e for e in events if e["blocked"]]
        if not blocked:
            continue

        distinct_ports = {e["dpt"] for e in blocked if e["dpt"]}
        if len(distinct_ports) >= PORT_SCAN_THRESHOLD:
            times = [e["ts"] for e in blocked if e["ts"]]
            findings.append(
                Finding(
                    id=f"port_scan_{src}",
                    title=f"Port scan from {src}",
                    severity="high",
                    category="reconnaissance",
                    description=(
                        f"{src} probed {len(distinct_ports)} distinct destination "
                        "ports, consistent with automated port scanning."
                    ),
                    count=len(distinct_ports),
                    source_ips=[src],
                    first_seen=_fmt(min(times)) if times else None,
                    last_seen=_fmt(max(times)) if times else None,
                    sample_lines=[e["line"] for e in blocked[:MAX_SAMPLE_LINES]],
                )
            )

        if len(blocked) >= BLOCKED_FLOOD_THRESHOLD:
            times = [e["ts"] for e in blocked if e["ts"]]
            severity = "critical" if len(blocked) >= 500 else "high" if len(blocked) >= 100 else "medium"
            findings.append(
                Finding(
                    id=f"blocked_flood_{src}",
                    title=f"Repeated blocked connections from {src}",
                    severity=severity,
                    category="brute_force",
                    description=(
                        f"{len(blocked)} blocked/dropped packets from {src}, "
                        "consistent with a persistent attacker or scanning/flood "
                        "traffic."
                    ),
                    count=len(blocked),
                    source_ips=[src],
                    first_seen=_fmt(min(times)) if times else None,
                    last_seen=_fmt(max(times)) if times else None,
                    sample_lines=[e["line"] for e in blocked[:MAX_SAMPLE_LINES]],
                )
            )

        sensitive_hits = [e for e in blocked if e["dpt"] and int(e["dpt"]) in SENSITIVE_PORTS]
        if len(sensitive_hits) >= SENSITIVE_PORT_THRESHOLD:
            times = [e["ts"] for e in sensitive_hits if e["ts"]]
            ports = sorted({f"{e['dpt']}/{SENSITIVE_PORTS[int(e['dpt'])]}" for e in sensitive_hits})
            findings.append(
                Finding(
                    id=f"sensitive_port_probing_{src}",
                    title=f"Sensitive port probing from {src}",
                    severity="medium",
                    category="reconnaissance",
                    description=(
                        f"{len(sensitive_hits)} connection attempt(s) from {src} "
                        "targeted commonly-exploited ports: "
                        f"{', '.join(ports[:MAX_LISTED_ITEMS])}."
                    ),
                    count=len(sensitive_hits),
                    source_ips=[src],
                    first_seen=_fmt(min(times)) if times else None,
                    last_seen=_fmt(max(times)) if times else None,
                    sample_lines=[e["line"] for e in sensitive_hits[:MAX_SAMPLE_LINES]],
                )
            )

    return findings


def _analyze_windows_events(lines: list[str]) -> LogAnalysisResponse:
    # Each event is a multi-line block starting at an "Event[N]:" header -
    # unlike every other format here, a single "line" of evidence isn't one
    # source line, so blocks are re-joined for multi-line field extraction.
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if WINDOWS_EVENT_HEADER_RE.match(line):
            if current:
                blocks.append(current)
            current = [line]
        else:
            current.append(line)
    if current:
        blocks.append(current)

    failed_logons_by_source: dict[str, list[dict]] = defaultdict(list)
    successful_logons: list[dict] = []
    lockouts: list[dict] = []
    accounts_created: list[dict] = []
    priv_group_changes: list[dict] = []
    audit_clears: list[dict] = []
    services_installed: list[dict] = []

    parsed_lines = 0
    timestamps: list[datetime.datetime] = []

    for block_lines in blocks:
        block_text = "\n".join(block_lines)
        id_match = WINDOWS_EVENT_ID_RE.search(block_text)
        if not id_match:
            continue
        event_id = id_match.group("id")
        parsed_lines += len(block_lines)

        date_match = WINDOWS_DATE_RE.search(block_text)
        ts = _parse_windows_timestamp(date_match.group("date")) if date_match else None
        if ts:
            timestamps.append(ts)

        computer_match = WINDOWS_COMPUTER_RE.search(block_text)
        computer = computer_match.group("computer") if computer_match else None

        # The Subject's account (often "-" for anonymous/failed attempts)
        # appears first in these templates, the target account later -
        # taking the last non-placeholder match lands on the one that
        # matters (e.g. the actual username a failed logon attempted).
        account_matches = WINDOWS_ACCOUNT_NAME_RE.findall(block_text)
        account = next((a for a in reversed(account_matches) if a and a != "-"), None) or "(unknown)"

        source_ip_match = WINDOWS_SOURCE_IP_RE.search(block_text)
        source_ip = source_ip_match.group("ip") if source_ip_match else None
        if source_ip in ("-", "127.0.0.1", "::1", "::ffff:127.0.0.1"):
            source_ip = None

        logon_type_match = WINDOWS_LOGON_TYPE_RE.search(block_text)
        logon_type = logon_type_match.group("logon_type") if logon_type_match else None

        entry = {
            "event_id": event_id,
            "ts": ts,
            "computer": computer,
            "account": account,
            "source_ip": source_ip,
            "logon_type": logon_type,
            "line": (
                f"Event ID {event_id} | {date_match.group('date') if date_match else '?'} | "
                f"Computer={computer or '?'} | Account={account} | "
                f"LogonType={WINDOWS_LOGON_TYPE_LABELS.get(logon_type, logon_type or '-')} | "
                f"SourceIP={source_ip or '-'}"
            ),
        }

        if event_id == WINDOWS_EVENT_FAILED_LOGON:
            source_key = source_ip or f"{account}@{computer or 'local'}"
            failed_logons_by_source[source_key].append(entry)
        elif event_id == WINDOWS_EVENT_SUCCESSFUL_LOGON:
            successful_logons.append(entry)
        elif event_id == WINDOWS_EVENT_ACCOUNT_LOCKOUT:
            lockouts.append(entry)
        elif event_id == WINDOWS_EVENT_ACCOUNT_CREATED:
            accounts_created.append(entry)
        elif event_id in WINDOWS_EVENT_PRIV_GROUP_CHANGE:
            group_match = WINDOWS_GROUP_NAME_RE.search(block_text)
            entry["group"] = group_match.group("name") if group_match else "(unknown)"
            priv_group_changes.append(entry)
        elif event_id == WINDOWS_EVENT_AUDIT_LOG_CLEARED:
            audit_clears.append(entry)
        elif event_id in WINDOWS_EVENT_SERVICE_INSTALLED:
            service_match = WINDOWS_SERVICE_NAME_RE.search(block_text)
            entry["service"] = service_match.group("name") if service_match else "(unknown)"
            services_installed.append(entry)

    findings = _build_windows_findings(
        failed_logons_by_source,
        successful_logons,
        lockouts,
        accounts_created,
        priv_group_changes,
        audit_clears,
        services_installed,
    )
    findings.sort(key=lambda f: _severity_rank(f.severity))

    summary = {
        "failed_logons": sum(len(v) for v in failed_logons_by_source.values()),
        "successful_logons": len(successful_logons),
        "account_lockouts": len(lockouts),
        "accounts_created": len(accounts_created),
        "privileged_group_changes": len(priv_group_changes),
    }

    return LogAnalysisResponse(
        log_type="windows_event",
        total_lines=len(lines),
        parsed_lines=parsed_lines,
        time_range=TimeRange(
            start=_fmt(min(timestamps)) if timestamps else None,
            end=_fmt(max(timestamps)) if timestamps else None,
        ),
        findings=findings,
        summary=summary,
    )


def _build_windows_findings(
    failed_logons_by_source: dict[str, list[dict]],
    successful_logons: list[dict],
    lockouts: list[dict],
    accounts_created: list[dict],
    priv_group_changes: list[dict],
    audit_clears: list[dict],
    services_installed: list[dict],
) -> list[Finding]:
    findings: list[Finding] = []

    for source, attempts in failed_logons_by_source.items():
        count = len(attempts)
        if count < WINDOWS_BRUTE_FORCE_THRESHOLD:
            continue
        times = [a["ts"] for a in attempts if a["ts"]]
        accounts = sorted({a["account"] for a in attempts})
        is_rdp = any(a["logon_type"] == "10" for a in attempts)
        severity = "critical" if count >= 50 else "high" if count >= 20 else "medium"
        title = f"RDP brute-force from {source}" if is_rdp else f"Windows logon brute-force from {source}"
        findings.append(
            Finding(
                id=f"windows_brute_force_{source}",
                title=title,
                severity=severity,
                category="brute_force",
                description=(
                    f"{count} failed logon attempt(s) from {source} against "
                    f"{len(accounts)} account(s): {', '.join(accounts[:MAX_LISTED_ITEMS])}."
                ),
                count=count,
                source_ips=[source] if any(a["source_ip"] == source for a in attempts) else [],
                users=accounts[:MAX_LISTED_ITEMS],
                first_seen=_fmt(min(times)) if times else None,
                last_seen=_fmt(max(times)) if times else None,
                sample_lines=[a["line"] for a in attempts[:MAX_SAMPLE_LINES]],
            )
        )

    for event in successful_logons:
        source = event["source_ip"] or f"{event['account']}@{event['computer'] or 'local'}"
        prior_failures = [
            a
            for a in failed_logons_by_source.get(source, [])
            if event["ts"]
            and a["ts"]
            and a["ts"] <= event["ts"]
            and event["ts"] - a["ts"] <= COMPROMISE_LOOKBACK
        ]
        if len(prior_failures) >= WINDOWS_BRUTE_FORCE_THRESHOLD:
            findings.append(
                Finding(
                    id=f"windows_compromise_suspected_{source}_{event['account']}",
                    title=f"Successful logon from {source} after repeated failures",
                    severity="critical",
                    category="possible_compromise",
                    description=(
                        f"{source} succeeded logging in as '{event['account']}' "
                        f"after {len(prior_failures)} prior failed attempts within "
                        f"{int(COMPROMISE_LOOKBACK.total_seconds() // 60)} minutes — "
                        "the credentials may have been guessed or brute-forced."
                    ),
                    count=1,
                    source_ips=[source] if event["source_ip"] else [],
                    users=[event["account"]],
                    first_seen=_fmt(event["ts"]),
                    last_seen=_fmt(event["ts"]),
                    sample_lines=[event["line"]],
                )
            )

    if lockouts:
        times = [e["ts"] for e in lockouts if e["ts"]]
        accounts = sorted({e["account"] for e in lockouts})
        findings.append(
            Finding(
                id="account_lockouts",
                title="Account lockout(s) occurred",
                severity="medium",
                category="anomaly",
                description=(
                    f"{len(lockouts)} account(s) locked out after repeated failed "
                    f"logons: {', '.join(accounts[:MAX_LISTED_ITEMS])}."
                ),
                count=len(lockouts),
                users=accounts[:MAX_LISTED_ITEMS],
                first_seen=_fmt(min(times)) if times else None,
                last_seen=_fmt(max(times)) if times else None,
                sample_lines=[e["line"] for e in lockouts[:MAX_SAMPLE_LINES]],
            )
        )

    if accounts_created:
        times = [e["ts"] for e in accounts_created if e["ts"]]
        accounts = sorted({e["account"] for e in accounts_created})
        findings.append(
            Finding(
                id="accounts_created",
                title="New user account(s) created",
                severity="medium",
                category="anomaly",
                description=(
                    f"{len(accounts_created)} new account(s) created: "
                    f"{', '.join(accounts[:MAX_LISTED_ITEMS])}."
                ),
                count=len(accounts_created),
                users=accounts[:MAX_LISTED_ITEMS],
                first_seen=_fmt(min(times)) if times else None,
                last_seen=_fmt(max(times)) if times else None,
                sample_lines=[e["line"] for e in accounts_created[:MAX_SAMPLE_LINES]],
            )
        )

    if priv_group_changes:
        times = [e["ts"] for e in priv_group_changes if e["ts"]]
        accounts = sorted({e["account"] for e in priv_group_changes})
        changes_desc = ", ".join(
            f"{e['account']} → {e.get('group', '(unknown)')}" for e in priv_group_changes[:MAX_LISTED_ITEMS]
        )
        findings.append(
            Finding(
                id="privileged_group_changes",
                title="Account(s) added to a privileged group",
                severity="high",
                category="privilege_escalation",
                description=f"{len(priv_group_changes)} membership change(s): {changes_desc}.",
                count=len(priv_group_changes),
                users=accounts[:MAX_LISTED_ITEMS],
                first_seen=_fmt(min(times)) if times else None,
                last_seen=_fmt(max(times)) if times else None,
                sample_lines=[e["line"] for e in priv_group_changes[:MAX_SAMPLE_LINES]],
            )
        )

    if audit_clears:
        times = [e["ts"] for e in audit_clears if e["ts"]]
        findings.append(
            Finding(
                id="audit_log_cleared",
                title="Security audit log was cleared",
                severity="critical",
                category="anti_forensics",
                description=(
                    f"The security event log was cleared {len(audit_clears)} "
                    "time(s) - a common step attackers take to erase evidence. "
                    "Legitimate causes are rare and should be verified."
                ),
                count=len(audit_clears),
                first_seen=_fmt(min(times)) if times else None,
                last_seen=_fmt(max(times)) if times else None,
                sample_lines=[e["line"] for e in audit_clears[:MAX_SAMPLE_LINES]],
            )
        )

    if services_installed:
        times = [e["ts"] for e in services_installed if e["ts"]]
        services = sorted({e.get("service", "(unknown)") for e in services_installed})
        findings.append(
            Finding(
                id="services_installed",
                title="New service(s) installed",
                severity="medium",
                category="persistence",
                description=(
                    f"{len(services_installed)} new service(s) installed: "
                    f"{', '.join(services[:MAX_LISTED_ITEMS])}."
                ),
                count=len(services_installed),
                first_seen=_fmt(min(times)) if times else None,
                last_seen=_fmt(max(times)) if times else None,
                sample_lines=[e["line"] for e in services_installed[:MAX_SAMPLE_LINES]],
            )
        )

    return findings
