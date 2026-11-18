# Log Triage Report

**Tool:** LogTriage v1.0.0  
**Generated (UTC):** 2026-11-18T11:31:37Z  
**Input:** `sample_input/triage_sample.log` (11,934 bytes, 83 lines)  
**SHA-256:** `577e7d1e1d5ed1dbe4ffac1bb29bf8a18c75a546c41c9164561ed57cad553e62`  
**Watchlist:** `tool/watchlist.json` (3 indicators)  

## Risk Summary

| Metric | Value |
|---|---|
| Overall risk | **CRITICAL** (100/100) |
| Findings | 9 (2 critical, 5 high, 2 medium, 0 low) |
| Parsed events | 83 / 83 non-blank lines |
| External IPv4 | 7 |
| Internal IPv4 | 9 |
| Domains | 4 |
| File hashes | 3 |
| URLs | 0 |
| Watchlist hits | 3 |

**Assessment:** 9 findings produced a CRITICAL risk score. The highest-severity items are listed first and should be validated using the evidence lines.

## Findings

| ID | Severity | Rule | Indicator / source | Count | First seen (UTC) |
|---|---|---|---|---:|---|
| F-001 | **CRITICAL** | brute_force | `203.0.113.45` | 9 | 2026-03-12T03:10:00Z |
| F-002 | **CRITICAL** | sensitive_file_exposure | `198.51.100.77` | 1 | 2026-03-12T03:20:16Z |
| F-003 | **HIGH** | http_scanning | `198.51.100.77` | 13 | 2026-03-12T03:20:00Z |
| F-004 | **HIGH** | port_scanning | `192.0.2.88` | 12 | 2026-03-12T03:25:00Z |
| F-005 | **HIGH** | watchlist_domain | `10.0.0.23` | 2 | 2026-03-12T03:27:05Z |
| F-006 | **HIGH** | watchlist_hash | `-` | 1 | 2026-03-12T03:28:14Z |
| F-007 | **HIGH** | watchlist_ip | `192.0.2.200` | 1 | 2026-03-12T03:30:01Z |
| F-008 | **MEDIUM** | scanner_user_agent | `198.51.100.77` | 13 | 2026-03-12T03:20:00Z |
| F-009 | **MEDIUM** | scanner_user_agent | `198.51.100.77` | 1 | 2026-03-12T03:20:56Z |

### F-001 - CRITICAL - SSH brute force succeeded for user 'deploy' from 203.0.113.45

- **Rule:** `brute_force`
- **Confidence:** high
- **Source:** `203.0.113.45`
- **Count:** 9
- **First / last seen (UTC):** 2026-03-12T03:10:00Z / 2026-03-12T03:12:24Z
- **MITRE ATT&CK:** T1110, T1110.001, T1110.003

9 failed SSH authentications from 203.0.113.45 between 2026-03-12T03:10:00Z and 2026-03-12T03:12:24Z were followed by a successful login as 'deploy' at 2026-03-12T03:13:40Z. This is consistent with a successful password-guessing or password-spraying attack.

**Recommendation:** Treat the account and host as potentially compromised: terminate sessions, rotate credentials and keys, review post-login commands, and block the source address.

**Evidence:**

```text
line 27: Mar 12 03:10:00 lab-ubuntu sshd[2400]: Failed password for invalid user root from 203.0.113.45 port 45001 ssh2
line 29: Mar 12 03:10:18 lab-ubuntu sshd[2401]: Failed password for invalid user admin from 203.0.113.45 port 45002 ssh2
line 30: Mar 12 03:10:36 lab-ubuntu sshd[2402]: Failed password for invalid user oracle from 203.0.113.45 port 45003 ssh2
line 32: Mar 12 03:10:54 lab-ubuntu sshd[2403]: Failed password for invalid user postgres from 203.0.113.45 port 45004 ssh2
```

### F-002 - CRITICAL - Sensitive path returned HTTP 2xx to 198.51.100.77

- **Rule:** `sensitive_file_exposure`
- **Confidence:** medium
- **Source:** `198.51.100.77`
- **Count:** 1
- **First / last seen (UTC):** 2026-03-12T03:20:16Z / 2026-03-12T03:20:16Z
- **MITRE ATT&CK:** T1552.001, T1190

1 successful HTTP response returned for sensitive paths requested from 198.51.100.77: /backup.sql. A 2xx status does not prove that useful content was served (for example, an SPA fallback can return 200), so response bodies should be checked immediately.

**Recommendation:** Verify the response body and access logs, remove or restrict the exposed files, rotate any credentials they contained, and block the source address.

**Evidence:**

```text
line 50: 198.51.100.77 - - [12/Mar/2026:03:20:16 +0000] "GET /backup.sql HTTP/1.1" 200 18432 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)"
```

### F-003 - HIGH - Web scanning from 198.51.100.77 (13 paths, 13 errors)

- **Rule:** `http_scanning`
- **Confidence:** high
- **Source:** `198.51.100.77`
- **Count:** 13
- **First / last seen (UTC):** 2026-03-12T03:20:00Z / 2026-03-12T03:21:44Z
- **MITRE ATT&CK:** T1595, T1595.002, T1190

13 HTTP 4xx/5xx responses were returned to 198.51.100.77 between 2026-03-12T03:20:00Z and 2026-03-12T03:21:44Z across 13 distinct paths. Sensitive targets requested: admin_panel, aws_credentials, cgi_bin, env_file, git_metadata, path_traversal, phpunit_rce, server_status, ssh_private_key. The pattern is consistent with automated content discovery or vulnerability scanning.

**Recommendation:** Block the source at the edge, review web logs for successful responses on the same paths, remove exposed files, and keep the web server and plugins patched.

**Evidence:**

```text
line 48: 198.51.100.77 - - [12/Mar/2026:03:20:00 +0000] "GET /.env HTTP/1.1" 403 233 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)"
line 49: 198.51.100.77 - - [12/Mar/2026:03:20:08 +0000] "GET /.git/config HTTP/1.1" 404 233 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)"
line 51: 198.51.100.77 - - [12/Mar/2026:03:20:24 +0000] "GET /wp-login.php HTTP/1.1" 404 233 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)"
line 52: 198.51.100.77 - - [12/Mar/2026:03:20:32 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 233 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)"
```

### F-004 - HIGH - Port scan from 192.0.2.88 (12 destination ports)

- **Rule:** `port_scanning`
- **Confidence:** high
- **Source:** `192.0.2.88`
- **Count:** 12
- **First / last seen (UTC):** 2026-03-12T03:25:00Z / 2026-03-12T03:25:44Z
- **MITRE ATT&CK:** T1046, T1595.001

12 firewall blocks for 192.0.2.88 between 2026-03-12T03:25:00Z and 2026-03-12T03:25:44Z touched 12 distinct destination ports (21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080). Multiple blocked connection attempts across services indicate network reconnaissance.

**Recommendation:** Keep the default-deny policy, block the source, and confirm that no internal service is reachable from untrusted networks.

**Evidence:**

```text
line 62: Mar 12 03:25:00 lab-gw kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=02:00:00:00:00:01 SRC=192.0.2.88 DST=10.0.0.5 LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID=54321 PROTO=TCP SPT=41000 DPT=21 WINDOW=1024 RES=0x00 SYN URGP=0
line 63: Mar 12 03:25:04 lab-gw kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=02:00:00:00:00:01 SRC=192.0.2.88 DST=10.0.0.5 LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID=54321 PROTO=TCP SPT=41001 DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0
line 64: Mar 12 03:25:08 lab-gw kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=02:00:00:00:00:01 SRC=192.0.2.88 DST=10.0.0.5 LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID=54321 PROTO=TCP SPT=41002 DPT=23 WINDOW=1024 RES=0x00 SYN URGP=0
line 65: Mar 12 03:25:12 lab-gw kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=02:00:00:00:00:01 SRC=192.0.2.88 DST=10.0.0.5 LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID=54321 PROTO=TCP SPT=41003 DPT=25 WINDOW=1024 RES=0x00 SYN URGP=0
```

### F-005 - HIGH - Watchlisted domain observed: update-check.example

- **Rule:** `watchlist_domain`
- **Confidence:** high
- **Source:** `10.0.0.23`
- **Count:** 2
- **First / last seen (UTC):** 2026-03-12T03:27:05Z / 2026-03-12T03:27:08Z
- **MITRE ATT&CK:** T1071.004, T1568

The domain update-check.example matched the local watchlist (Synthetic malware update domain (demo)) across 2 log lines.

**Recommendation:** Correlate the indicator with endpoint and network telemetry, contain affected hosts, and update blocking controls. Treat the match as a lead until independently validated.

**Evidence:**

```text
line 74: Mar 12 03:27:05 lab-dns dnsmasq[811]: query[A] update-check.example from 10.0.0.23
line 75: Mar 12 03:27:08 lab-dns dnsmasq[811]: query[A] update-check.example from 10.0.0.23
```

### F-006 - HIGH - Watchlisted file hash observed: d235842f1fa6b2bf...

- **Rule:** `watchlist_hash`
- **Confidence:** high
- **Source:** `not applicable`
- **Count:** 1
- **First / last seen (UTC):** 2026-03-12T03:28:14Z / 2026-03-12T03:28:14Z
- **MITRE ATT&CK:** T1204.002, T1105

The file hash d235842f1fa6b2bf5afef3c941af2bf777ea0ddd6a2d7370db75563248d729f3 matched the local watchlist (SHA-256 of a fixed demo string (not malware)) across 1 log line.

**Recommendation:** Correlate the indicator with endpoint and network telemetry, contain affected hosts, and update blocking controls. Treat the match as a lead until independently validated.

**Evidence:**

```text
line 79: 2026-03-12T03:28:14Z lab-edr1 edr-agent[221]: ALERT verdict=malicious action=quarantined file="/tmp/invoice_scan.pdf" sha256=d235842f1fa6b2bf5afef3c941af2bf777ea0ddd6a2d7370db75563248d729f3
```

### F-007 - HIGH - Watchlisted IP observed: 192.0.2.200

- **Rule:** `watchlist_ip`
- **Confidence:** high
- **Source:** `192.0.2.200`
- **Count:** 1
- **First / last seen (UTC):** 2026-03-12T03:30:01Z / 2026-03-12T03:30:01Z
- **MITRE ATT&CK:** T1071

The IPv4 address 192.0.2.200 matched the local watchlist (Synthetic known-bad C2 endpoint (demo)) across 1 log line.

**Recommendation:** Correlate the indicator with endpoint and network telemetry, contain affected hosts, and update blocking controls. Treat the match as a lead until independently validated.

**Evidence:**

```text
line 81: Mar 12 03:30:01 lab-gw kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=02:00:00:00:00:01 SRC=192.0.2.200 DST=10.0.0.5 LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID=54321 PROTO=TCP SPT=55555 DPT=4444 WINDOW=1024 RES=0x00 SYN URGP=0
```

### F-008 - MEDIUM - Offensive scanner user-agent ('nikto') from 198.51.100.77

- **Rule:** `scanner_user_agent`
- **Confidence:** high
- **Source:** `198.51.100.77`
- **Count:** 13
- **First / last seen (UTC):** 2026-03-12T03:20:00Z / 2026-03-12T03:21:44Z
- **MITRE ATT&CK:** T1595, T1595.002

13 requests used a user-agent associated with the offensive tool 'nikto'. This is a direct signature of automated scanning or exploitation attempts.

**Recommendation:** Block or challenge the source, inspect the requested paths for successful exploitation, and consider filtering known scanner user-agents at the reverse proxy.

**Evidence:**

```text
line 48: 198.51.100.77 - - [12/Mar/2026:03:20:00 +0000] "GET /.env HTTP/1.1" 403 233 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)"
line 49: 198.51.100.77 - - [12/Mar/2026:03:20:08 +0000] "GET /.git/config HTTP/1.1" 404 233 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)"
line 50: 198.51.100.77 - - [12/Mar/2026:03:20:16 +0000] "GET /backup.sql HTTP/1.1" 200 18432 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)"
line 51: 198.51.100.77 - - [12/Mar/2026:03:20:24 +0000] "GET /wp-login.php HTTP/1.1" 404 233 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)"
```

### F-009 - MEDIUM - Offensive scanner user-agent ('sqlmap') from 198.51.100.77

- **Rule:** `scanner_user_agent`
- **Confidence:** high
- **Source:** `198.51.100.77`
- **Count:** 1
- **First / last seen (UTC):** 2026-03-12T03:20:56Z / 2026-03-12T03:20:56Z
- **MITRE ATT&CK:** T1595, T1595.002

1 request used a user-agent associated with the offensive tool 'sqlmap'. This is a direct signature of automated scanning or exploitation attempts.

**Recommendation:** Block or challenge the source, inspect the requested paths for successful exploitation, and consider filtering known scanner user-agents at the reverse proxy.

**Evidence:**

```text
line 55: 198.51.100.77 - - [12/Mar/2026:03:20:56 +0000] "GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1" 404 233 "-" "sqlmap/1.8.3#stable"
```

## Indicators of Compromise

Indicators are extracted from every line, including lines that could not be parsed behaviourally. Internal addresses are shown for context and are not automatically malicious.

### External IPv4

| Value | Hits | First seen (UTC) | Last seen (UTC) | Contexts | Note | Watchlist |
|---|---:|---|---|---|---|---|
| `192.0.2.200` | 1 | 2026-03-12T03:30:01Z | 2026-03-12T03:30:01Z | firewall_block | RFC 5737 documentation range (synthetic sample) | hit: Synthetic known-bad C2 endpoint (demo) |
| `198.51.100.77` | 14 | 2026-03-12T03:20:00Z | 2026-03-12T03:21:44Z | http_request | RFC 5737 documentation range (synthetic sample) | - |
| `192.0.2.88` | 12 | 2026-03-12T03:25:00Z | 2026-03-12T03:25:44Z | firewall_block | RFC 5737 documentation range (synthetic sample) | - |
| `203.0.113.45` | 10 | 2026-03-12T03:10:00Z | 2026-03-12T03:13:40Z | ssh_failed_login, ssh_success_login | RFC 5737 documentation range (synthetic sample) | - |
| `198.51.100.10` | 7 | 2026-03-12T03:01:44Z | 2026-03-12T03:32:00Z | http_request | RFC 5737 documentation range (synthetic sample) | - |
| `198.51.100.11` | 2 | 2026-03-12T03:14:00Z | 2026-03-12T03:14:20Z | http_request | RFC 5737 documentation range (synthetic sample) | - |
| `198.51.100.12` | 2 | 2026-03-12T03:14:40Z | 2026-03-12T03:15:00Z | http_request | RFC 5737 documentation range (synthetic sample) | - |

### Internal IPv4 (context only)

| Value | Hits | First seen (UTC) | Last seen (UTC) | Contexts | Note | Watchlist |
|---|---:|---|---|---|---|---|
| `10.0.0.5` | 13 | 2026-03-12T03:25:00Z | 2026-03-12T03:30:01Z | firewall_block | Private or non-routable address | - |
| `10.0.0.31` | 7 | 2026-03-12T03:00:20Z | 2026-03-12T03:12:56Z | http_request | Private or non-routable address | - |
| `10.0.0.32` | 7 | 2026-03-12T03:01:02Z | 2026-03-12T03:13:38Z | http_request | Private or non-routable address | - |
| `10.0.0.15` | 4 | 2026-03-12T03:00:10Z | 2026-03-12T03:31:20Z | ssh_success_login | Private or non-routable address | - |
| `10.0.0.23` | 4 | 2026-03-12T03:27:05Z | 2026-03-12T03:27:45Z | dns_query | Private or non-routable address | - |
| `10.0.0.18` | 3 | 2026-03-12T03:01:25Z | 2026-03-12T03:09:05Z | ssh_success_login | Private or non-routable address | - |
| `10.0.0.21` | 2 | 2026-03-12T03:04:05Z | 2026-03-12T03:07:50Z | ssh_success_login | Private or non-routable address | - |
| `10.0.0.44` | 1 | 2026-03-12T03:28:00Z | 2026-03-12T03:28:00Z | dns_query | Private or non-routable address | - |
| `10.0.0.77` | 1 | 2026-03-12T03:19:00Z | 2026-03-12T03:19:00Z | ssh_failed_login | Private or non-routable address | - |

### Domains

| Value | Hits | First seen (UTC) | Last seen (UTC) | Contexts | Watchlist |
|---|---:|---|---|---|---|
| `update-check.example` | 2 | 2026-03-12T03:27:05Z | 2026-03-12T03:27:08Z | dns_query | hit: Synthetic malware update domain (demo) |
| `deb.debian.org` | 1 | 2026-03-12T03:27:30Z | 2026-03-12T03:27:30Z | dns_query | - |
| `github.com` | 1 | 2026-03-12T03:27:45Z | 2026-03-12T03:27:45Z | dns_query | - |
| `telemetry.example` | 1 | 2026-03-12T03:28:00Z | 2026-03-12T03:28:00Z | dns_query | - |

### File Hashes

| Value | Hits | First seen (UTC) | Last seen (UTC) | Contexts | Watchlist |
|---|---:|---|---|---|---|
| `d235842f1fa6b2bf5afef3c941af2bf777ea0ddd6a2d7370db75563248d729f3` | 1 | 2026-03-12T03:28:14Z | 2026-03-12T03:28:14Z | malware_alert | hit: SHA-256 of a fixed demo string (not malware) |
| `90fe540a068e4954aca2a7f6969e0f65` | 1 | 2026-03-12T03:29:02Z | 2026-03-12T03:29:02Z | endpoint_scan | - |
| `b0c98431229bdb155964ce2609b9f0e102c1672300069f10beee4f4f2ce93277` | 1 | 2026-03-12T03:29:02Z | 2026-03-12T03:29:02Z | endpoint_scan | - |

### URLs

None observed.

## Suspicious Event Timeline

| Time (UTC) | Line | Finding | Event | Summary |
|---|---:|---|---|---|
| 2026-03-12T03:10:00Z | 27 | F-001 | ssh_failed_login | Mar 12 03:10:00 lab-ubuntu sshd[2400]: Failed password for invalid user root from 203.0.113.45 port 45001 ssh2 |
| 2026-03-12T03:10:18Z | 29 | F-001 | ssh_failed_login | Mar 12 03:10:18 lab-ubuntu sshd[2401]: Failed password for invalid user admin from 203.0.113.45 port 45002 ssh2 |
| 2026-03-12T03:10:36Z | 30 | F-001 | ssh_failed_login | Mar 12 03:10:36 lab-ubuntu sshd[2402]: Failed password for invalid user oracle from 203.0.113.45 port 45003 ssh2 |
| 2026-03-12T03:20:00Z | 48 | F-003 | http_request | 198.51.100.77 - - [12/Mar/2026:03:20:00 +0000] "GET /.env HTTP/1.1" 403 233 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)" |
| 2026-03-12T03:20:00Z | 48 | F-008 | http_request | 198.51.100.77 - - [12/Mar/2026:03:20:00 +0000] "GET /.env HTTP/1.1" 403 233 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)" |
| 2026-03-12T03:20:08Z | 49 | F-003 | http_request | 198.51.100.77 - - [12/Mar/2026:03:20:08 +0000] "GET /.git/config HTTP/1.1" 404 233 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000 |
| 2026-03-12T03:20:08Z | 49 | F-008 | http_request | 198.51.100.77 - - [12/Mar/2026:03:20:08 +0000] "GET /.git/config HTTP/1.1" 404 233 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000 |
| 2026-03-12T03:20:16Z | 50 | F-002 | http_request | 198.51.100.77 - - [12/Mar/2026:03:20:16 +0000] "GET /backup.sql HTTP/1.1" 200 18432 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:00 |
| 2026-03-12T03:20:16Z | 50 | F-008 | http_request | 198.51.100.77 - - [12/Mar/2026:03:20:16 +0000] "GET /backup.sql HTTP/1.1" 200 18432 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:00 |
| 2026-03-12T03:20:24Z | 51 | F-003 | http_request | 198.51.100.77 - - [12/Mar/2026:03:20:24 +0000] "GET /wp-login.php HTTP/1.1" 404 233 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:00 |
| 2026-03-12T03:20:56Z | 55 | F-009 | http_request | 198.51.100.77 - - [12/Mar/2026:03:20:56 +0000] "GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1" 404 233 "-" "sqlmap/1.8.3# |
| 2026-03-12T03:25:00Z | 62 | F-004 | firewall_block | Mar 12 03:25:00 lab-gw kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=02:00:00:00:00:01 SRC=192.0.2.88 DST=10.0.0.5 LEN=44 TOS=0x00 PRE |
| 2026-03-12T03:25:04Z | 63 | F-004 | firewall_block | Mar 12 03:25:04 lab-gw kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=02:00:00:00:00:01 SRC=192.0.2.88 DST=10.0.0.5 LEN=44 TOS=0x00 PRE |
| 2026-03-12T03:25:08Z | 64 | F-004 | firewall_block | Mar 12 03:25:08 lab-gw kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=02:00:00:00:00:01 SRC=192.0.2.88 DST=10.0.0.5 LEN=44 TOS=0x00 PRE |
| 2026-03-12T03:27:05Z | 74 | F-005 | dns_query | Mar 12 03:27:05 lab-dns dnsmasq[811]: query[A] update-check.example from 10.0.0.23 |
| 2026-03-12T03:27:08Z | 75 | F-005 | dns_query | Mar 12 03:27:08 lab-dns dnsmasq[811]: query[A] update-check.example from 10.0.0.23 |
| 2026-03-12T03:28:14Z | 79 | F-006 | malware_alert | 2026-03-12T03:28:14Z lab-edr1 edr-agent[221]: ALERT verdict=malicious action=quarantined file="/tmp/invoice_scan.pdf" sha256=d235842f1fa6b2b |
| 2026-03-12T03:30:01Z | 81 | F-007 | firewall_block | Mar 12 03:30:01 lab-gw kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=02:00:00:00:00:01 SRC=192.0.2.200 DST=10.0.0.5 LEN=44 TOS=0x00 PR |

## Event Breakdown

| Source type | Events |
|---|---:|
| http | 39 |
| ssh | 20 |
| firewall | 13 |
| dns | 5 |
| sudo | 2 |
| syslog | 2 |
| edr | 2 |

| Event type | Events |
|---|---:|
| http_request | 39 |
| firewall_block | 13 |
| ssh_success_login | 10 |
| ssh_failed_login | 10 |
| dns_query | 5 |
| sudo_command | 2 |
| syslog | 2 |
| malware_alert | 1 |
| endpoint_scan | 1 |

## Detection Method and Tuning

| Rule | Logic | Default threshold |
|---|---|---|
| `brute_force` | Failed SSH logins clustered per source IP; optional successful login after the burst | 5 failures / 20s |
| `http_scanning` | HTTP 4xx/5xx clustered per source IP, distinct paths and sensitive targets | 10 errors or 8 distinct paths / 20s |
| `sensitive_file_exposure` | HTTP 2xx response for a sensitive path | any match |
| `port_scanning` | Firewall blocks clustered per source IP by distinct destination port | 8 ports / 20s |
| `scanner_user_agent` | User-agent matches a known offensive tool | any match |
| `watchlist_*` | Extracted IOC matches the local JSON watchlist | any match |

## Assumptions and Limitations

- Timestamps without an explicit zone are treated as UTC; syslog lines use the year supplied with --assume-year.
- Detection is behavioural and threshold-based, so tuning is required for each environment; the defaults target small lab logs.
- Only IPv4 addresses are inventoried as IOCs; IPv6 source addresses are parsed where the log format exposes them but are not aggregated.
- No packet payload, HTTP body, or file content is inspected. A 2xx response for a sensitive path is a lead that requires manual validation.
- Watchlist matching is local and static; the included watchlist is synthetic and is not a threat-intelligence feed.
- The tool is read-only and makes no network calls. It does not block, quarantine, or modify any system.
- Mixed log formats are supported on a best-effort basis; unknown lines are still scanned for indicators but are not correlated behaviourally.
- The input size is capped (default 50 MiB) because events are held in memory.

## Safety

LogTriage is a defensive, read-only tool. It does not execute log content, make network requests, modify the input, or interact with any target. All sample indicators are synthetic or use reserved address space and the `.example` domain.

---

Generated by LogTriage v1.0.0. Defensive log triage; validate findings before acting.

