#!/usr/bin/env python3
"""Generate the synthetic log used by the LogTriage demo.

Safety: every address is RFC 5737 documentation space or RFC 1918 private
space, every domain is under the reserved `.example` TLD, usernames and hosts
are invented, and the file hashes are digests of fixed demo strings. No real
users, companies, malware, or company data are represented.

Run from the repository root:
    python sample_input/generate_sample.py
"""
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

OUTPUT = Path(__file__).with_name("triage_sample.log")
MONTHS = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)
BASE = datetime(2026, 3, 12, 3, 0, 0)
records: list[tuple[datetime, str]] = []

# Hashes of fixed synthetic strings. The malicious one is watchlisted.
MALICIOUS_SHA256 = "d235842f1fa6b2bf5afef3c941af2bf777ea0ddd6a2d7370db75563248d729f3"
CLEAN_SHA256 = "b0c98431229bdb155964ce2609b9f0e102c1672300069f10beee4f4f2ce93277"
CLEAN_MD5 = "90fe540a068e4954aca2a7f6969e0f65"

BENIGN_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
NIKTO_UA = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)"
SQLMAP_UA = "sqlmap/1.8.3#stable"


def stamp(moment: datetime) -> str:
    return f"{MONTHS[moment.month - 1]} {moment.day:02d} {moment:%H:%M:%S}"


def syslog(moment: datetime, host: str, process: str, message: str) -> str:
    return f"{stamp(moment)} {host} {process}: {message}"


def nginx_stamp(moment: datetime) -> str:
    return (
        f"{moment.day:02d}/{MONTHS[moment.month - 1]}/{moment.year}:"
        f"{moment:%H:%M:%S} +0000"
    )


def http(
    moment: datetime,
    client: str,
    path: str,
    status: int,
    user_agent: str = BENIGN_UA,
    size: int = 512,
) -> str:
    return (
        f'{client} - - [{nginx_stamp(moment)}] "GET {path} HTTP/1.1" '
        f'{status} {size} "-" "{user_agent}"'
    )


def ssh(moment: datetime, pid: int, message: str) -> str:
    return syslog(moment, "lab-ubuntu", f"sshd[{pid}]", message)


def ufw(moment: datetime, source: str, destination_port: int, source_port: int) -> str:
    return syslog(
        moment,
        "lab-gw",
        "kernel",
        "[12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=02:00:00:00:00:01 "
        f"SRC={source} DST=10.0.0.5 LEN=44 TOS=0x00 PREC=0x00 TTL=52 "
        f"ID=54321 PROTO=TCP SPT={source_port} DPT={destination_port} "
        "WINDOW=1024 RES=0x00 SYN URGP=0",
    )


def add(moment: datetime, line: str) -> None:
    records.append((moment, line))


# ---------------------------------------------------------------------------
# Normal activity: a small lab with routine SSH, web traffic, sudo, and cron.
# ---------------------------------------------------------------------------
benign_logins = [
    (10, "10.0.0.15", "ops1"),
    (85, "10.0.0.18", "svc_deploy"),
    (160, "10.0.0.15", "ops1"),
    (245, "10.0.0.21", "labadmin"),
    (320, "10.0.0.18", "svc_deploy"),
    (395, "10.0.0.15", "ops1"),
    (470, "10.0.0.21", "labadmin"),
    (545, "10.0.0.18", "svc_deploy"),
]
for offset, client, user in benign_logins:
    add(
        BASE + timedelta(seconds=offset),
        ssh(
            BASE + timedelta(seconds=offset),
            2100 + offset,
            f"Accepted publickey for {user} from {client} port 51000 ssh2: "
            "RSA SHA256:demoKeyFingerprint",
        ),
    )

add(BASE + timedelta(minutes=6, seconds=40),
    syslog(BASE + timedelta(minutes=6, seconds=40), "lab-ubuntu", "sudo",
           "ops1 : TTY=pts/0 ; PWD=/home/ops1 ; USER=root ; "
           "COMMAND=/usr/bin/apt-get update"))
add(BASE + timedelta(minutes=8, seconds=10),
    syslog(BASE + timedelta(minutes=8, seconds=10), "lab-ubuntu", "sudo",
           "ops1 : TTY=pts/0 ; PWD=/home/ops1 ; USER=root ; "
           "COMMAND=/usr/bin/systemctl restart nginx"))
add(BASE + timedelta(minutes=8, seconds=45),
    syslog(BASE + timedelta(minutes=8, seconds=45), "lab-web01", "systemd[1]",
           "Started Daily apt upgrade and clean activities."))
add(BASE + timedelta(minutes=9, seconds=30),
    syslog(BASE + timedelta(minutes=9, seconds=30), "lab-ubuntu", "CRON[3001]",
           "(root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)"))

web_paths = ["/", "/health", "/api/v1/status", "/assets/app.js", "/login"]
web_clients = ["10.0.0.31", "10.0.0.32", "198.51.100.10"]
for index in range(20):
    moment = BASE + timedelta(seconds=20 + index * 42)
    path = web_paths[index % len(web_paths)]
    client = web_clients[index % len(web_clients)]
    add(moment, http(moment, client, path, 200, size=1024 + index * 13))

for index, (client, path) in enumerate([
    ("198.51.100.11", "/favicon.ico"),
    ("198.51.100.11", "/old-page"),
    ("198.51.100.12", "/missing.png"),
    ("198.51.100.12", "/robots.txt"),
]):
    moment = BASE + timedelta(minutes=14, seconds=index * 20)
    add(moment, http(moment, client, path, 404))

# One isolated failed login is normal user error, below the threshold.
add(BASE + timedelta(minutes=19),
    ssh(BASE + timedelta(minutes=19), 2199,
        "Failed password for ops1 from 10.0.0.77 port 50111 ssh2"))

# ---------------------------------------------------------------------------
# Scenario 1: SSH brute force / password spraying, then a successful login.
# ---------------------------------------------------------------------------
spray_users = [
    "root", "admin", "oracle", "postgres", "test", "ubuntu", "deploy", "root", "admin",
]
for index, user in enumerate(spray_users):
    moment = BASE + timedelta(minutes=10, seconds=index * 18)
    add(
        moment,
        ssh(
            moment,
            2400 + index,
            f"Failed password for invalid user {user} from 203.0.113.45 "
            f"port {45001 + index} ssh2",
        ),
    )
add(
    BASE + timedelta(minutes=13, seconds=40),
    ssh(
        BASE + timedelta(minutes=13, seconds=40),
        2410,
        "Accepted password for deploy from 203.0.113.45 port 45990 ssh2",
    ),
)

# ---------------------------------------------------------------------------
# Scenario 2: automated web content discovery. One sensitive file returns 200.
# ---------------------------------------------------------------------------
scans = [
    ("/.env", 403, NIKTO_UA, 0),
    ("/.git/config", 404, NIKTO_UA, 0),
    ("/backup.sql", 200, NIKTO_UA, 18432),
    ("/wp-login.php", 404, NIKTO_UA, 0),
    ("/phpmyadmin/", 404, NIKTO_UA, 0),
    ("/admin", 403, NIKTO_UA, 0),
    ("/server-status", 403, NIKTO_UA, 0),
    ("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", 404, SQLMAP_UA, 0),
    ("/cgi-bin/test.cgi", 404, NIKTO_UA, 0),
    ("/xmlrpc.php", 404, NIKTO_UA, 0),
    ("/.aws/credentials", 404, NIKTO_UA, 0),
    ("/../../etc/passwd", 400, NIKTO_UA, 0),
    ("/shell.php", 404, NIKTO_UA, 0),
    ("/.ssh/id_rsa", 404, NIKTO_UA, 0),
]
for index, (path, status, user_agent, size) in enumerate(scans):
    moment = BASE + timedelta(minutes=20, seconds=index * 8)
    add(
        moment,
        http(
            moment,
            "198.51.100.77",
            path,
            status,
            user_agent=user_agent,
            size=size or 233,
        ),
    )

# ---------------------------------------------------------------------------
# Scenario 3: network reconnaissance blocked by the host firewall.
# ---------------------------------------------------------------------------
for index, port in enumerate([21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]):
    moment = BASE + timedelta(minutes=25, seconds=index * 4)
    add(moment, ufw(moment, "192.0.2.88", port, 41000 + index))

# Watchlisted command-and-control address, seen once.
add(
    BASE + timedelta(minutes=30, seconds=1),
    ufw(BASE + timedelta(minutes=30, seconds=1), "192.0.2.200", 4444, 55555),
)

# ---------------------------------------------------------------------------
# Scenario 4: DNS lookups for a watchlisted domain, plus benign lookups.
# ---------------------------------------------------------------------------
dns_queries = [
    (27 * 60 + 5, "A", "update-check.example", "10.0.0.23"),
    (27 * 60 + 8, "A", "update-check.example", "10.0.0.23"),
    (27 * 60 + 30, "A", "deb.debian.org", "10.0.0.23"),
    (27 * 60 + 45, "AAAA", "github.com", "10.0.0.23"),
    (28 * 60 + 0, "A", "telemetry.example", "10.0.0.44"),
]
for offset, query_type, domain, client in dns_queries:
    moment = BASE + timedelta(seconds=offset)
    add(
        moment,
        syslog(
            moment,
            "lab-dns",
            "dnsmasq[811]",
            f"query[{query_type}] {domain} from {client}",
        ),
    )

# ---------------------------------------------------------------------------
# Scenario 5: endpoint malware verdict with a watchlisted hash, plus a clean scan.
# ---------------------------------------------------------------------------
add(
    BASE + timedelta(minutes=28, seconds=14),
    f"2026-03-12T03:28:14Z lab-edr1 edr-agent[221]: ALERT verdict=malicious "
    f'action=quarantined file="/tmp/invoice_scan.pdf" sha256={MALICIOUS_SHA256}',
)
add(
    BASE + timedelta(minutes=29, seconds=2),
    f"2026-03-12T03:29:02Z lab-edr1 edr-agent[221]: scan file=\"/usr/bin/curl\" "
    f"sha256={CLEAN_SHA256} md5={CLEAN_MD5} verdict=clean",
)

# Normal activity continues after the incidents.
add(
    BASE + timedelta(minutes=31, seconds=20),
    ssh(BASE + timedelta(minutes=31, seconds=20), 2500,
        "Accepted publickey for ops1 from 10.0.0.15 port 51222 ssh2: "
        "RSA SHA256:demoKeyFingerprint"),
)
add(
    BASE + timedelta(minutes=32),
    http(BASE + timedelta(minutes=32), "198.51.100.10", "/health", 200),
)

records.sort(key=lambda item: item[0])
OUTPUT.write_text(
    "\n".join(line for _moment, line in records) + "\n",
    encoding="utf-8",
    newline="\n",
)
print(f"Wrote {len(records)} synthetic log lines to {OUTPUT.name}")
