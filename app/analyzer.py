from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from re import IGNORECASE, compile, findall
from typing import Iterable


LOG_PATTERN = compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>[^"]*?) (?P<protocol>HTTP/[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

SENSITIVE_PATHS = (
    "/.env",
    "/admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/.git",
    "/config.php",
    "/backup",
)

SQLI_PATTERN = compile(r"('|%27|--|%2d%2d|\bunion\b|\bselect\b|\bor\b\s+1=1)", IGNORECASE)
XSS_PATTERN = compile(r"(<script|%3cscript|javascript:|onerror=)", IGNORECASE)
TRAVERSAL_PATTERN = compile(r"(\.\./|%2e%2e%2f|/etc/passwd|boot\.ini)", IGNORECASE)
SUSPICIOUS_AGENT_PATTERN = compile(r"(sqlmap|nikto|nmap|masscan|acunetix|dirbuster|gobuster)", IGNORECASE)


@dataclass(frozen=True)
class LogEntry:
    ip: str
    time: datetime | None
    method: str
    path: str
    status: int
    size: str
    agent: str
    raw: str
    user: str = ""
    action: str = ""
    app: str = ""
    host: str = ""
    outcome: str = ""
    group: str = ""


@dataclass(frozen=True)
class Alert:
    title: str
    severity: str
    ip: str
    evidence: str
    recommendation: str


def parse_log_line(line: str) -> LogEntry | None:
    siem_entry = _parse_siem_line(line)
    if siem_entry:
        return siem_entry

    match = LOG_PATTERN.search(line.strip())
    if not match:
        return None

    parsed_time = None
    try:
        parsed_time = datetime.strptime(match.group("time"), TIME_FORMAT)
    except ValueError:
        pass

    return LogEntry(
        ip=match.group("ip"),
        time=parsed_time,
        method=match.group("method"),
        path=match.group("path"),
        status=int(match.group("status")),
        size=match.group("size"),
        agent=match.group("agent"),
        raw=line.strip(),
    )


def _parse_siem_line(line: str) -> LogEntry | None:
    stripped = line.strip()
    if "src_ip=" not in stripped or "action=" not in stripped:
        return None

    parts = dict(findall(r"(\w+)=([^\s]+)", stripped))
    if "src_ip" not in parts:
        return None

    parsed_time = None
    timestamp = stripped.split(" ", 1)[0]
    try:
        parsed_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        pass

    return LogEntry(
        ip=parts.get("src_ip", "unknown"),
        time=parsed_time,
        method=parts.get("action", "EVENT").upper(),
        path=parts.get("host", parts.get("app", "siem-event")),
        status=_status_from_outcome(parts.get("status", "")),
        size="-",
        agent=parts.get("app", ""),
        raw=stripped,
        user=parts.get("user", ""),
        action=parts.get("action", ""),
        app=parts.get("app", ""),
        host=parts.get("host", ""),
        outcome=parts.get("status", ""),
        group=parts.get("group", ""),
    )


def parse_logs(text: str) -> tuple[list[LogEntry], int]:
    entries: list[LogEntry] = []
    skipped = 0

    for line in text.splitlines():
        if not line.strip():
            continue
        entry = parse_log_line(line)
        if entry is None:
            skipped += 1
            continue
        entries.append(entry)

    return entries, skipped


def analyze_logs(text: str) -> dict:
    entries, skipped = parse_logs(text)
    alerts = _build_alerts(entries)
    status_counts = Counter(entry.status for entry in entries)
    ip_counts = Counter(entry.ip for entry in entries)
    path_counts = Counter(entry.path.split("?")[0] for entry in entries)

    severity_weight = {"High": 35, "Medium": 18, "Low": 8}
    risk_score = min(100, sum(severity_weight[alert.severity] for alert in alerts))

    return {
        "total_lines": len([line for line in text.splitlines() if line.strip()]),
        "parsed_lines": len(entries),
        "skipped_lines": skipped,
        "risk_score": risk_score,
        "risk_label": _risk_label(risk_score),
        "alerts": alerts,
        "top_ips": ip_counts.most_common(5),
        "status_counts": sorted(status_counts.items()),
        "top_paths": path_counts.most_common(5),
    }


def _build_alerts(entries: Iterable[LogEntry]) -> list[Alert]:
    alerts: list[Alert] = []
    entries = list(entries)
    by_ip: dict[str, list[LogEntry]] = defaultdict(list)

    for entry in entries:
        by_ip[entry.ip].append(entry)

        if any(entry.path.startswith(path) for path in SENSITIVE_PATHS):
            alerts.append(
                Alert(
                    "Sensitive path probe",
                    "Medium",
                    entry.ip,
                    f"{entry.method} {entry.path} returned {entry.status}",
                    "Restrict admin paths, remove exposed config files, and return generic 404 responses.",
                )
            )

        if SQLI_PATTERN.search(entry.path):
            alerts.append(
                Alert(
                    "SQL injection pattern",
                    "High",
                    entry.ip,
                    f"Suspicious payload in {entry.path}",
                    "Validate inputs server-side, use parameterized queries, and review application logs.",
                )
            )

        if XSS_PATTERN.search(entry.path):
            alerts.append(
                Alert(
                    "XSS pattern",
                    "High",
                    entry.ip,
                    f"Script-like payload in {entry.path}",
                    "Escape output, sanitize rich text, and check whether the payload reached the app.",
                )
            )

        if TRAVERSAL_PATTERN.search(entry.path):
            alerts.append(
                Alert(
                    "Path traversal pattern",
                    "High",
                    entry.ip,
                    f"Traversal marker in {entry.path}",
                    "Normalize file paths and block access outside expected directories.",
                )
            )

        if SUSPICIOUS_AGENT_PATTERN.search(entry.agent):
            alerts.append(
                Alert(
                    "Known scanning tool",
                    "Medium",
                    entry.ip,
                    f"User-Agent: {entry.agent}",
                    "Rate-limit noisy clients and confirm whether this was an approved security test.",
                )
            )

    for ip, ip_entries in by_ip.items():
        not_found = [entry for entry in ip_entries if entry.status == 404]
        auth_failures = [entry for entry in ip_entries if entry.status in {401, 403}]
        failed_logins = [
            entry
            for entry in ip_entries
            if entry.action == "login" and entry.outcome == "failed"
        ]
        successful_logins = [
            entry
            for entry in ip_entries
            if entry.action == "login" and entry.outcome == "success"
        ]
        privilege_changes = [
            entry
            for entry in ip_entries
            if entry.action == "privilege_change" and entry.outcome == "success"
        ]

        if len(not_found) >= 6:
            alerts.append(
                Alert(
                    "Possible directory brute force",
                    "Medium",
                    ip,
                    f"{len(not_found)} requests returned 404",
                    "Block repeated scanners and review requested paths for exposed files.",
                )
            )

        if len(auth_failures) >= 4:
            alerts.append(
                Alert(
                    "Possible brute force or access probing",
                    "High",
                    ip,
                    f"{len(auth_failures)} requests returned 401/403",
                    "Check authentication logs, add rate limits, and require MFA for admin areas.",
                )
            )

        if len(failed_logins) >= 5:
            users = ", ".join(sorted({entry.user for entry in failed_logins if entry.user}))
            alerts.append(
                Alert(
                    "Multiple failed logins",
                    "High",
                    ip,
                    f"{len(failed_logins)} failed login attempts for users: {users or 'unknown'}",
                    "Check whether this IP is trusted, review VPN auth logs, and consider temporary blocking.",
                )
            )

        if failed_logins and successful_logins:
            alerts.append(
                Alert(
                    "Failed logins followed by success",
                    "High",
                    ip,
                    "Same source IP had failed login attempts and then a successful login.",
                    "Investigate account owner activity, reset credentials if suspicious, and verify MFA events.",
                )
            )

        if successful_logins and privilege_changes:
            groups = ", ".join(sorted({entry.group for entry in privilege_changes if entry.group}))
            alerts.append(
                Alert(
                    "Privilege escalation after login",
                    "High",
                    ip,
                    f"Successful login followed by privilege change{f' to {groups}' if groups else ''}.",
                    "Review admin group changes, identify who approved them, and roll back unauthorized access.",
                )
            )

    return _deduplicate_alerts(alerts)


def _deduplicate_alerts(alerts: list[Alert]) -> list[Alert]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Alert] = []

    for alert in alerts:
        key = (alert.title, alert.severity, alert.ip)
        if key in seen:
            continue
        seen.add(key)
        unique.append(alert)

    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    return sorted(unique, key=lambda alert: (severity_order[alert.severity], alert.ip, alert.title))


def _risk_label(score: int) -> str:
    if score >= 70:
        return "High"
    if score >= 35:
        return "Medium"
    if score > 0:
        return "Low"
    return "Clean"


def _status_from_outcome(outcome: str) -> int:
    if outcome == "success":
        return 200
    if outcome == "failed":
        return 401
    return 0
