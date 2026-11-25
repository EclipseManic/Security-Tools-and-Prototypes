# Sample Input

`triage_sample.log` is a **synthetic** mixed log written to exercise every
detector in the tool. `generate_sample.py` regenerates it deterministically
(83 lines, 2026-03-12, 03:00-03:32 UTC).

## Safety

- All public IPs are from RFC 5737 documentation ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- Internal IPs use RFC 1918 `10.0.0.0/8`.
- All domains are under the reserved `.example` TLD (plus benign references to
  `deb.debian.org` and `github.com`).
- Users, hosts, file names, and hashes are invented or derived from fixed demo
  strings. No real users, companies, malware, credentials, or PII are present.

## Injected scenarios

| Time (UTC) | Scenario | Indicator |
|---|---|---|
| 03:00-03:09 | Benign lab SSH, cron, sudo, and web traffic | - |
| 03:10-03:13 | SSH brute force/password spraying, then successful login | `203.0.113.45` |
| 03:20-03:22 | Web content discovery; `/backup.sql` returns 200 | `198.51.100.77` |
| 03:25 | 12-port firewall scan | `192.0.2.88` |
| 03:27 | DNS lookup of a watchlisted domain | `update-check.example` |
| 03:28 | EDR malware verdict with a watchlisted SHA-256 | `d23584...29f3` |
| 03:30 | Watchlisted C2 address blocked once | `192.0.2.200` |

There is also normal background traffic after the incidents, a single benign
failed SSH login, and a low-volume 404 pattern to exercise threshold handling.

## Regenerate

```bash
python sample_input/generate_sample.py
```

The generator is deterministic and writes `triage_sample.log` next to itself.
Do not add real data to this directory.
