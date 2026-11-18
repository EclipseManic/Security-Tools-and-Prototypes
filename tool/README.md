# LogTriage

Defensive, read-only log triage in a single CLI. Ingests a mixed text log,
extracts IOCs, detects common attack patterns, and writes Markdown + JSON
reports. **Python 3.10+ standard library only.**

## Safety

- Read-only: never modifies the input.
- No network access, shell execution, or target interaction.
- No offensive capability. This is a Blue-team triage tool.
- Only public/synthetic data is used in the included sample.
- Input is limited to 50 MiB and 10,000 characters per line by default.

## Requirements

- Python 3.10 or newer.
- No third-party packages. `requirements.txt` is intentionally empty apart from
  comments.

```bash
python --version
python -m pip install -r tool/requirements.txt
```

## Quick start

From the repository root:

```bash
python tool/log_triage.py --input sample_input/triage_sample.log --out-dir sample_output
```

Sample console output:

```text
LogTriage v1.0.0 | defensive log triage (read-only)
==================================================================
Input     : sample_input/triage_sample.log (11.7 KiB, 83 lines)
Parsed    : 83 events | ssh=20, http=39, dns=5, firewall=13, edr=2
IOCs      : 7 external IPv4, 9 internal IPv4, 4 domains, 3 hashes, 0 URLs
Watchlist : 3 indicators | 3 matching IOCs
Risk      : CRITICAL (100/100) | 9 findings (2 critical, 5 high, 2 medium)
  [CRITICAL] F-001 SSH brute force succeeded for user 'deploy' from 203.0.113.45
  ...
Outputs
  JSON     : sample_output/triage.json
  Markdown : sample_output/triage.md
```

Outputs are written with UTF-8 and LF line endings. Existing output files are
overwritten; the input is never written to.

## CLI options

| Option | Default | Purpose |
|---|---|---|
| `-i, --input PATH` | required | Text log to triage |
| `-o, --out-dir PATH` | `sample_output` | Output directory (created if needed) |
| `--output-prefix NAME` | `triage` | Output basename (`triage.json`, `triage.md`) |
| `--format {both,json,md}` | `both` | Select output formats |
| `--watchlist PATH` | `tool/watchlist.json` if present | Local JSON watchlist |
| `--no-watchlist` | off | Disable watchlist matching |
| `--window SECONDS` | `600` | Correlation window |
| `--brute-threshold N` | `5` | SSH failures per window |
| `--scan-threshold N` | `10` | HTTP errors per window |
| `--port-scan-threshold N` | `8` | Distinct blocked ports per window |
| `--success-window SECONDS` | `1800` | Look-back for success after an SSH burst |
| `--assume-year YYYY` | current year | Year for year-less syslog timestamps |
| `--max-bytes N` | 52,428,800 | Input size cap |
| `--fail-on LEVEL` | off | Exit 1 if overall risk reaches low/medium/high/critical |
| `--quiet` | off | Suppress the console summary |
| `--no-color` | off | Disable ANSI colour |
| `--version` | - | Print version |

Exit codes: `0` success, `1` `--fail-on` threshold reached, `2` input/config
error. Reports are still written before the `--fail-on` exit.

## Supported input formats

The parser is tolerant and falls back to generic IOC scanning:

1. **OpenSSH auth logs** (syslog): `Failed password`, `Accepted`, `Invalid
   user`, pre-auth disconnects, and PAM authentication failures.
2. **Apache/Nginx combined access logs**: client IP, timestamp, request, status,
   referer, and user-agent.
3. **dnsmasq query logs**: `query[A] host from 10.0.0.x`.
4. **UFW/iptables block lines**: `SRC=`, `DPT=`, and action.
5. **ISO-8601 endpoint/EDR lines**: `verdict=`, quarantine actions, hashes.
6. **Generic lines**: still scanned for IPv4, domains, URLs, and hashes.

Unknown non-blank lines are retained as `unparsed`/`generic` events so IOC
extraction does not silently lose indicators.

## Detection rules

| Rule | Logic | MITRE ATT&CK |
|---|---|---|
| `brute_force` | Failed SSH logins clustered per source IP by gap <= window; flags a successful login after the burst as critical | T1110, T1110.001, T1110.003 |
| `http_scanning` | HTTP 4xx/5xx clustered per source; distinct and sensitive paths raise severity | T1595.002, T1190 |
| `sensitive_file_exposure` | HTTP 2xx on a sensitive path (`.env`, `.git`, backups, `.aws`, `.ssh`, admin panels, traversal) | T1552.001 |
| `port_scanning` | Firewall blocks clustered per source by distinct destination ports | T1046, T1595.001 |
| `scanner_user_agent` | User-agent matches sqlmap, Nikto, nmap, masscan, zgrab, Nuclei, etc. | T1595 |
| `watchlist_*` | Extracted IP/domain/hash matches the local JSON watchlist | Rule-dependent |

Risk score = sum of severity weights (critical 40, high 25, medium 10, low 3),
capped at 100. Levels: clean (0), low (<20), medium (<45), high (<70), critical
(>=70). These weights are intentionally simple and documented so analysts can
re-tune them.

## Output

### JSON

Top-level keys:

```text
schema_version, tool, generated_at, input, config, watchlist, summary,
findings, iocs, timeline, stats, limitations
```

- `summary.risk_score` / `risk_level` / `severity_counts` / `ioc_counts`
- `findings[]`: id, rule, title, severity, confidence, source_ip, timestamps,
  count, description, recommendation, MITRE IDs, evidence line numbers, details
- `iocs`: `ipv4_external`, `ipv4_internal`, `ipv4_reserved`, `domains`,
  `hashes`, `urls` (each with hits, contexts, source IPs, hosts, watchlist match)
- `timeline`: up to 40 de-duplicated suspicious events with finding IDs

### Markdown

Sections: Risk Summary, Findings (table + detail + evidence), Indicators of
Compromise, Suspicious Event Timeline, Event Breakdown, Detection Method and
Tuning, Assumptions and Limitations, Safety.

Evidence lines are truncated, table pipes are escaped, and no raw ANSI codes are
emitted. The Markdown is deterministic apart from `Generated (UTC)` and input
hash.

## Watchlist format

```json
{
  "ips": {
    "192.0.2.200": {
      "label": "Synthetic known-bad C2 endpoint (demo)",
      "confidence": "high"
    }
  },
  "domains": {
    "update-check.example": {
      "label": "Synthetic malware update domain (demo)",
      "confidence": "high"
    }
  },
  "hashes": {
    "d235842f1fa6b2bf5afef3c941af2bf777ea0ddd6a2d7370db75563248d729f3": {
      "label": "SHA-256 of a fixed demo string (not malware)",
      "confidence": "high",
      "hash_type": "sha256"
    }
  }
}
```

Categories may be objects or simple lists. Invalid entries are skipped with a
warning. `confidence` maps to finding severity (`high` -> high, `medium` ->
medium, `low` -> low). The included file is synthetic and not a real feed.

## Testing

```bash
python -m unittest discover -s tool -p "test_*.py" -v
```

The suite covers IOC extraction, timestamp/SSH/HTTP/firewall parsing, detection
thresholds, watchlist loading, JSON serialisation, Markdown rendering, and a
full CLI run on the committed sample.

## Assumptions and limitations

- Naive timestamps are treated as UTC; syslog lines use `--assume-year`.
- IPv4 is the only aggregated address family.
- Detection is threshold-based; baseline before production use.
- No payload/body inspection; 2xx sensitive-path hits need manual validation.
- Watchlist matching is static and local.
- Input is held in memory and capped at 50 MiB.
- The tool does not block, quarantine, or remediate; it produces triage leads.

## Repository layout

```text
tool/
  log_triage.py       CLI entry point
  triage_types.py     dataclasses and constants
  triage_parse.py     ingestion, parsing, IOC extraction
  triage_detect.py    watchlist, detectors, scoring
  triage_report.py    JSON + Markdown rendering
  watchlist.json      synthetic demo indicators
  requirements.txt    no third-party dependencies
  test_log_triage.py  unit + end-to-end tests
```
