import re
from collections import Counter

from models import GroupedIssue, LogAnalysisResponse

SUSPICIOUS_PATTERNS = {
    "failed_login": re.compile(r"failed login", re.IGNORECASE),
    "timeout": re.compile(r"timeout", re.IGNORECASE),
    "connection_refused": re.compile(r"connection refused", re.IGNORECASE),
    "unauthorized": re.compile(r"unauthorized|403", re.IGNORECASE),
}

SEVERITY_MAP = {
    "critical": re.compile(r"critical|fatal", re.IGNORECASE),
    "error": re.compile(r"error|exception|failed", re.IGNORECASE),
    "warning": re.compile(r"warn|warning", re.IGNORECASE),
    "info": re.compile(r"info", re.IGNORECASE),
}

TIMESTAMP_PATTERNS = [
    re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b"),
    re.compile(r"\b\d{4}/\d{2}/\d{2}[ T]\d{2}:\d{2}:\d{2}\b"),
    re.compile(r"\b\d{2}-\d{2}-\d{4}[ T]\d{2}:\d{2}:\d{2}\b"),
]

ERROR_PATTERN = re.compile(r"\b(error|exception|fatal|critical)\b", re.IGNORECASE)
WARNING_PATTERN = re.compile(r"\b(warn|warning)\b", re.IGNORECASE)

ISSUE_TYPE_PATTERN = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_.]*(?:Exception|Error))\b"
)

LEVEL_PREFIX_PATTERN = re.compile(
    r"^\s*(?:\[[^\]]+\]\s*)?"
    r"(?:\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}\s*)?"
    r"(?:ERROR|WARN(?:ING)?|INFO|DEBUG|TRACE)[:\-\s]*",
    re.IGNORECASE,
)


def extract_timestamps(line: str) -> list[str]:
    matches: list[str] = []

    for pattern in TIMESTAMP_PATTERNS:
        matches.extend(pattern.findall(line))

    return matches


def extract_issue_type(line: str) -> str:
    exception_match = ISSUE_TYPE_PATTERN.search(line)

    if exception_match:
        return exception_match.group(1)

    cleaned = LEVEL_PREFIX_PATTERN.sub("", line).strip()

    cleaned = re.sub(
        r"\b\d+\.\d+\.\d+\.\d+\b",
        "<ip>",
        cleaned,
    )

    cleaned = re.sub(
        r"\b\d+\b",
        "<num>",
        cleaned,
    )

    cleaned = re.sub(r"\s+", " ", cleaned)

    return cleaned[:80] or "UnknownError"


def analyze_log_content(content: str) -> LogAnalysisResponse:
    lines = content.splitlines()

    timestamps: list[str] = []
    grouped_error_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    top_lines: Counter[str] = Counter()
    suspicious_counts: Counter[str] = Counter()

    total_errors = 0
    total_warnings = 0

    for line in lines:

        if len(timestamps) < 100:
            new_ts = extract_timestamps(line)
            remaining = 100 - len(timestamps)
            timestamps.extend(new_ts[:remaining])

        for level, pattern in SEVERITY_MAP.items():
            if pattern.search(line):
                severity_counts[level] += 1
                break

        for key, pattern in SUSPICIOUS_PATTERNS.items():
            if pattern.search(line):
                suspicious_counts[key] += 1

        if ERROR_PATTERN.search(line):
            total_errors += 1

            issue = extract_issue_type(line)

            grouped_error_counts[issue] += 1

            clean_line = line.strip()[:120]

            top_lines[clean_line] += 1

        elif WARNING_PATTERN.search(line):
            total_warnings += 1

    grouped_issues = [
        GroupedIssue(issue_type=k, count=v)
        for k, v in grouped_error_counts.most_common()
    ]

    most_frequent_issues = grouped_issues[:5]

    severity_breakdown = [
        GroupedIssue(issue_type=k.upper(), count=v)
        for k, v in sorted(
            severity_counts.items(),
            key=lambda x: -x[1]
        )
    ]

    top_problem_lines = [
        {"line": line, "count": count}
        for line, count in top_lines.most_common(5)
    ]

    suspicious_activity = [
        GroupedIssue(issue_type=k.upper(), count=v)
        for k, v in suspicious_counts.most_common()
        if v > 1
    ]

    if not suspicious_activity:
        suspicious_activity = [
            GroupedIssue(issue_type="NONE", count=0)
        ]

    summary = {
        "total_lines": len(lines),
        "error_rate": round(
            total_errors / max(len(lines), 1),
            3,
        ),
        "warning_rate": round(
            total_warnings / max(len(lines), 1),
            3,
        ),
        "unique_error_types": len(grouped_error_counts),
    }

    return LogAnalysisResponse(
        total_errors=total_errors,
        total_warnings=total_warnings,
        timestamps=timestamps,
        grouped_issues=grouped_issues,
        most_frequent_issues=most_frequent_issues,
        severity_breakdown=severity_breakdown,
        suspicious_activity=suspicious_activity,
        top_problem_lines=top_problem_lines,
        summary=summary,
    )