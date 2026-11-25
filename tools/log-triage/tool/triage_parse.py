"""Log ingestion, tolerant line parsing, and IOC extraction.

Supports four common text log shapes plus a generic fallback:

* OpenSSH auth logs (syslog)
* Apache/Nginx combined access logs
* dnsmasq query logs
* UFW/iptables firewall blocks
* ISO-8601 endpoint/EDR lines

Everything is best-effort: unknown lines are still scanned for indicators so
that the tool can triage mixed or partially understood logs.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import unquote, urlsplit

from triage_types import (
    MAX_LINE_CHARS,
    Config,
    Event,
    IOC,
    Watchlist,
)

IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}"
    r"(?![A-Za-z0-9_-])"
)
HASH_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,64}(?![0-9A-Fa-f])")
URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.IGNORECASE)
ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

ISO_TS_RE = re.compile(
    r"(?<!\d)"
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"(?!\d)"
)
HTTP_TS_RE = re.compile(
    r"\b(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\b"
)
SYSLOG_TS_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b")
EPOCH_TS_RE = re.compile(r"(?<!\d)(1[5-9]\d{8})(?:\.\d+)?(?!\d)")

SYSLOG_PREFIX_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[A-Za-z0-9_.-]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)
ISO_PREFIX_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[A-Za-z0-9_.-]+)(?:\[\d+\])?:\s*"
    r"(?P<msg>.*)$"
)

SSH_FAILED_RE = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive(?:/pam)?) "
    r"for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)",
    re.IGNORECASE,
)
SSH_INVALID_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+)", re.IGNORECASE
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive(?:/pam)?) "
    r"for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)",
    re.IGNORECASE,
)
SSH_PREAUTH_RE = re.compile(
    r"Connection closed by (?:(?:authenticating|invalid) user \S+ )?"
    r"(?P<ip>\S+) port \d+ \[preauth\]",
    re.IGNORECASE,
)

HTTP_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

DNS_QUERY_RE = re.compile(
    r"query\[(?P<qtype>[A-Za-z]+)\]\s+(?P<domain>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)
UFW_RE = re.compile(
    r"\[UFW (?:BLOCK|AUDIT|LIMIT)\].*?\bSRC=(?P<src>\S+).*?\bDPT=(?P<dpt>\d+)",
    re.IGNORECASE,
)

MALICIOUS_VERDICT_RE = re.compile(
    r"verdict\s*=\s*(?:malicious|infected|suspicious)|action\s*=\s*quarantin",
    re.IGNORECASE,
)

FILE_EXTENSION_TLDS = {
    "php", "html", "htm", "js", "css", "png", "jpg", "jpeg", "gif", "svg",
    "ico", "txt", "log", "gz", "zip", "tar", "exe", "dll", "json", "xml",
    "pdf", "asp", "aspx", "jsp", "cgi", "sh", "py", "md", "conf", "ini",
    "yml", "yaml", "sql", "bak", "old", "tmp", "bin", "dat", "db", "lock",
    "map", "woff", "woff2", "ttf", "eot", "pem", "crt", "key", "rpm", "deb",
}

INTERNAL_NETS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "0.0.0.0/8",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)
TEST_NET_NETS = tuple(
    ipaddress.ip_network(value)
    for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)

SENSITIVE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("env_file", re.compile(r"(?:^|/)\.env(?:$|[./])", re.IGNORECASE)),
    ("git_metadata", re.compile(r"(?:^|/)\.git(?:/|$)", re.IGNORECASE)),
    ("aws_credentials", re.compile(r"(?:^|/)\.aws/credentials$", re.IGNORECASE)),
    ("ssh_private_key", re.compile(
        r"(?:^|/)\.ssh/(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)$", re.IGNORECASE
    )),
    ("database_dump", re.compile(
        r"(?:^|/)(?:backup|dump|db|database)[^/]*\.(?:sql|bak|old|zip|tar|gz|7z)$",
        re.IGNORECASE,
    )),
    ("admin_panel", re.compile(
        r"/(?:wp-login\.php|wp-admin(?:/|$)|phpmyadmin(?:/|$)|admin(?:/|$)|"
        r"manager/html|xmlrpc\.php)",
        re.IGNORECASE,
    )),
    ("server_status", re.compile(r"(?:server-status|server-info)", re.IGNORECASE)),
    ("phpunit_rce", re.compile(r"vendor/phpunit", re.IGNORECASE)),
    ("cgi_bin", re.compile(r"/cgi-bin/", re.IGNORECASE)),
)


def normalise_ip(value: str) -> str | None:
    """Validate and canonicalise an IP address, returning None if invalid."""
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        return None


def parse_timestamp(line: str, assume_year: int) -> datetime | None:
    """Extract the first plausible timestamp and normalise it to naive UTC.

    Syslog timestamps have no year, so ``assume_year`` is used. Timestamps
    without a zone are treated as UTC (documented assumption).
    """
    match = ISO_TS_RE.search(line)
    if match:
        value = match.group(1).replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
            return parsed
        except ValueError:
            pass

    match = HTTP_TS_RE.search(line)
    if match:
        try:
            parsed = datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S %z")
            return parsed.astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            pass

    match = SYSLOG_TS_RE.search(line)
    if match:
        try:
            parsed = datetime.strptime(
                f"{assume_year} {match.group(1)}", "%Y %b %d %H:%M:%S"
            )
            return parsed
        except ValueError:
            pass

    match = EPOCH_TS_RE.search(line)
    if match:
        try:
            return datetime.fromtimestamp(
                int(match.group(1)), tz=timezone.utc
            ).replace(tzinfo=None)
        except (ValueError, OSError):
            return None
    return None


def extract_ipv4(text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for match in IPV4_RE.finditer(text):
        value = match.group(0)
        try:
            canonical = str(ipaddress.ip_address(value))
        except ValueError:
            continue
        if canonical in {"0.0.0.0", "255.255.255.255"} or canonical in seen:
            continue
        seen.add(canonical)
        values.append(canonical)
    return values


def is_domain_candidate(value: str) -> bool:
    value = value.strip().rstrip(".").lower()
    if "." not in value or len(value) > 253:
        return False
    tld = value.rsplit(".", 1)[-1]
    if tld in FILE_EXTENSION_TLDS:
        return False
    return bool(re.fullmatch(r"[a-z]{2,63}", tld))


def extract_domains(text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for match in DOMAIN_RE.finditer(text):
        value = match.group(0).rstrip(".").lower()
        if not is_domain_candidate(value) or value in seen:
            continue
        seen.add(value)
        values.append(value)
    return values


def extract_hashes(text: str) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    seen: set[str] = set()
    for match in HASH_RE.finditer(text):
        value = match.group(0).lower()
        length = len(value)
        if length not in {32, 40, 64} or value in seen:
            continue
        if set(value) == {"0"}:
            continue
        seen.add(value)
        hash_type = {32: "md5", 40: "sha1", 64: "sha256"}[length]
        values.append((value, hash_type))
    return values


def extract_urls(text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for match in URL_RE.finditer(text):
        value = match.group(0).rstrip(").,;'\"")
        if len(value) > 8 and value not in seen:
            seen.add(value)
            values.append(value)
    return values


def classify_ipv4(value: str) -> tuple[str, str | None]:
    """Return (scope, note). Test-net ranges are treated as external."""
    address = ipaddress.ip_address(value)
    if any(address in network for network in INTERNAL_NETS):
        return "internal", "Private or non-routable address"
    if any(address in network for network in TEST_NET_NETS):
        return "external", "RFC 5737 documentation range (synthetic sample)"
    if address.is_global:
        return "external", None
    return "reserved", "Special-purpose or reserved address"


def sensitive_labels(path: str) -> list[str]:
    """Return labels for sensitive paths requested by a web client."""
    if not path:
        return []
    candidate = path
    if "://" in candidate:
        candidate = urlsplit(candidate).path or "/"
    candidate = unquote(candidate.split("?", 1)[0])
    normalised = candidate.replace("\\", "/")
    labels: set[str] = set()
    for label, pattern in SENSITIVE_PATTERNS:
        if pattern.search(normalised):
            labels.add(label)
    if "../" in normalised or "%2e%2e" in candidate.lower():
        labels.add("path_traversal")
    return sorted(labels)


def _syslog_base(
    raw: str, line_no: int, timestamp: datetime | None, match: re.Match[str]
) -> Event:
    return Event(
        line_no=line_no,
        raw=raw,
        timestamp=timestamp,
        source_type="syslog",
        event="generic",
        host=match.group("host"),
        message=match.group("msg"),
    )


def _parse_ssh(event: Event) -> Event:
    event.source_type = "ssh"
    message = event.message
    match = SSH_FAILED_RE.search(message)
    if match:
        event.event = "ssh_failed_login"
        event.src_ip = normalise_ip(match.group("ip"))
        event.username = match.group("user")
        return event

    match = SSH_INVALID_RE.search(message)
    if match:
        event.event = "ssh_invalid_user"
        event.src_ip = normalise_ip(match.group("ip"))
        event.username = match.group("user")
        return event

    match = SSH_ACCEPTED_RE.search(message)
    if match:
        event.event = "ssh_success_login"
        event.src_ip = normalise_ip(match.group("ip"))
        event.username = match.group("user")
        return event

    match = SSH_PREAUTH_RE.search(message)
    if match:
        event.event = "ssh_preauth_close"
        event.src_ip = normalise_ip(match.group("ip"))
        return event

    if "authentication failure" in message.lower():
        event.event = "ssh_auth_failure"
        ip_match = re.search(r"rhost=(\S+)", message)
        user_match = re.search(r"user=(\S+)", message)
        if ip_match:
            event.src_ip = normalise_ip(ip_match.group(1))
        if user_match:
            event.username = user_match.group(1)
        return event

    event.event = "ssh_other"
    return event


def _parse_http(raw: str, line_no: int, timestamp: datetime | None,
                match: re.Match[str]) -> Event | None:
    event = Event(
        line_no=line_no,
        raw=raw,
        timestamp=timestamp,
        source_type="http",
        event="http_request",
        src_ip=normalise_ip(match.group("ip")),
        status=int(match.group("status")),
        user_agent=match.group("ua"),
    )
    request = match.group("request").strip()
    parts = request.split()
    if len(parts) >= 2 and parts[0].isalpha():
        event.method = parts[0].upper()
        target = parts[1]
    else:
        target = request
    if "://" in target:
        try:
            event.path = urlsplit(target).path or "/"
        except ValueError:
            event.path = target
    else:
        event.path = target.split("?", 1)[0] or "/"
    event.message = request
    return event


def parse_line(raw_line: str, line_no: int, assume_year: int) -> Event | None:
    """Parse one log line into an Event. Blank lines return None."""
    raw = raw_line.rstrip("\r\n")
    raw = ANSI_ESCAPE_RE.sub("", raw)
    raw = CONTROL_CHAR_RE.sub("", raw)
    if not raw.strip():
        return None
    if len(raw) > MAX_LINE_CHARS:
        raw = raw[:MAX_LINE_CHARS] + " ...[truncated]"

    timestamp = parse_timestamp(raw, assume_year)

    http_match = HTTP_RE.match(raw)
    if http_match:
        return _parse_http(raw, line_no, timestamp, http_match)

    syslog_match = SYSLOG_PREFIX_RE.match(raw)
    if syslog_match:
        event = _syslog_base(raw, line_no, timestamp, syslog_match)
        proc = syslog_match.group("proc").lower()
        message = syslog_match.group("msg")
        if proc.startswith("sshd"):
            return _parse_ssh(event)
        if proc.startswith("dnsmasq"):
            dns_match = DNS_QUERY_RE.search(message)
            if dns_match:
                event.source_type = "dns"
                event.event = "dns_query"
                event.domain = dns_match.group("domain").rstrip(".").lower()
                event.src_ip = normalise_ip(dns_match.group("ip"))
                return event
        if "UFW BLOCK" in message or "UFW AUDIT" in message:
            ufw_match = UFW_RE.search(message)
            if ufw_match:
                event.source_type = "firewall"
                event.event = "firewall_block"
                event.src_ip = normalise_ip(ufw_match.group("src"))
                event.dst_port = int(ufw_match.group("dpt"))
                return event
        if proc.startswith("sudo") or "sudo:" in raw.lower():
            event.source_type = "sudo"
            event.event = "sudo_command"
            user_match = re.search(r"\buser=(\S+)", message)
            if user_match:
                event.username = user_match.group(1)
            return event
        event.source_type = "syslog"
        event.event = "syslog"
        return event

    ufw_match = UFW_RE.search(raw)
    if ufw_match:
        return Event(
            line_no=line_no,
            raw=raw,
            timestamp=timestamp,
            source_type="firewall",
            event="firewall_block",
            src_ip=normalise_ip(ufw_match.group("src")),
            dst_port=int(ufw_match.group("dpt")),
            message=raw,
        )

    dns_match = DNS_QUERY_RE.search(raw)
    if dns_match:
        return Event(
            line_no=line_no,
            raw=raw,
            timestamp=timestamp,
            source_type="dns",
            event="dns_query",
            src_ip=normalise_ip(dns_match.group("ip")),
            domain=dns_match.group("domain").rstrip(".").lower(),
            message=raw,
        )

    if "sshd" in raw:
        event = Event(
            line_no=line_no,
            raw=raw,
            timestamp=timestamp,
            source_type="ssh",
            event="ssh_other",
            message=raw,
        )
        return _parse_ssh(event)

    iso_match = ISO_PREFIX_RE.match(raw)
    if iso_match and (
        "verdict=" in raw.lower()
        or "edr" in raw.lower()
        or "quarantine" in raw.lower()
        or "clamav" in raw.lower()
    ):
        message = iso_match.group("msg")
        event = Event(
            line_no=line_no,
            raw=raw,
            timestamp=timestamp,
            source_type="edr",
            event="endpoint_scan",
            host=iso_match.group("host"),
            message=message,
        )
        if MALICIOUS_VERDICT_RE.search(message):
            event.event = "malware_alert"
        return event

    if "sudo:" in raw.lower():
        user_match = re.search(r"\buser=(\S+)", raw)
        return Event(
            line_no=line_no,
            raw=raw,
            timestamp=timestamp,
            source_type="sudo",
            event="sudo_command",
            username=user_match.group(1) if user_match else None,
            message=raw,
        )

    has_indicator = bool(
        extract_ipv4(raw) or extract_domains(raw) or extract_hashes(raw)
    )
    return Event(
        line_no=line_no,
        raw=raw,
        timestamp=timestamp,
        source_type="generic" if (timestamp or has_indicator) else "unparsed",
        event="generic" if (timestamp or has_indicator) else "unparsed",
        message=raw,
    )


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ingest_file(
    path: Path, config: Config
) -> tuple[list[Event], int, int, int, str]:
    """Read a log file and return (events, lines, nonblank, size, sha256)."""
    if not path.exists():
        raise FileNotFoundError(f"input file not found: {path}")
    if not path.is_file():
        raise ValueError(f"input path is not a file: {path}")
    size = path.stat().st_size
    if size == 0:
        raise ValueError("input file is empty")
    if size > config.max_bytes:
        raise ValueError(
            f"input file is {size} bytes, above the {config.max_bytes} byte limit"
        )

    events: list[Event] = []
    line_count = 0
    nonblank = 0
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for line_count, line in enumerate(handle, start=1):
            event = parse_line(line, line_count, config.assume_year)
            if event is not None:
                events.append(event)
                nonblank += 1
    if not events:
        raise ValueError("input file contains no non-blank log lines")
    return events, line_count, nonblank, size, file_sha256(path)


def build_iocs(events: Iterable[Event], watchlist: Watchlist) -> list[IOC]:
    """Aggregate IPv4, domain, URL and hash indicators across all events."""
    index: dict[tuple[str, str], IOC] = {}

    def get(kind: str, value: str, hash_type: str | None = None) -> IOC:
        key = (kind, value.lower() if kind in {"domain", "hash"} else value)
        if key not in index:
            ioc = IOC(value=value, kind=kind, hash_type=hash_type)
            if kind == "ipv4":
                scope, note = classify_ipv4(value)
                ioc.scope, ioc.note = scope, note
            index[key] = ioc
        return index[key]

    for event in events:
        text = event.raw
        for value in extract_ipv4(text):
            get("ipv4", value).observe(event)
        for value in extract_domains(text):
            get("domain", value).observe(event)
        for value, hash_type in extract_hashes(text):
            get("hash", value, hash_type).observe(event)
        for value in extract_urls(text):
            get("url", value).observe(event)

    iocs = list(index.values())
    for ioc in iocs:
        ioc.watchlist = watchlist.lookup(ioc.kind, ioc.value)
    iocs.sort(
        key=lambda item: (
            item.watchlist is None,
            -item.hits,
            item.kind,
            item.value,
        )
    )
    return iocs
