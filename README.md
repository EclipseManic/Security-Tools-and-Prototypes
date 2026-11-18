# Day 2 Mission - Manichand Gupta - Blue - Working Tool

- **Tool name:** LogTriage
- **Time spent:** 3h 00m
- **Language/dependencies:** Python 3.10+; standard library only (no third-party packages)
- **Run command:** `python tool/log_triage.py --input sample_input/triage_sample.log --out-dir sample_output`
- **Repo map:**
  - [Report](report.md)
  - [Tool](tool/)
  - [Config](tool/tool.config)
  - [Sample input](sample_input/)
  - [Sample output](sample_output/)
  - [Evidence](evidence/)
  - [Sources](sources/links.md)

Full usage, formats, and detection rules are documented in
[tool/README.md](tool/README.md). This page is the submission-facing overview.

## What the Tool Does

LogTriage is a defensive, read-only log triage CLI. It ingests a mixed text log,
extracts IPv4 addresses, domains, URLs, and MD5/SHA-1/SHA-256 hashes, detects
SSH brute-force/password spraying, web scanning, sensitive-file exposure, port
scanning, offensive scanner user-agents, and local watchlist matches, then
writes a structured Markdown report and a machine-readable JSON summary.

The included sample log is synthetic and contains several deliberately injected
incidents so the tool can be evaluated end-to-end without downloading data.

Capabilities at a glance:

- Tolerant ingestion of OpenSSH auth logs, Apache/Nginx combined logs, dnsmasq
  queries, UFW/iptables blocks, ISO-8601 EDR lines, and generic lines.
- IOC extraction with internal/external classification, per-indicator hit
  counts, first/last seen timestamps, source IPs, and evidence line numbers.
- Behavioural detections with configurable thresholds and a single 0-100 risk
  score.
- Deterministic Markdown + JSON artifacts, suitable for committing or attaching
  to a ticket.
- No network access, no shell execution, no writes to the input file.

## Key Results

1. Detected **SSH brute force / password spraying** from `203.0.113.45`: 9
   failures across 7 usernames, followed by a successful login as `deploy`
   (critical).
2. Detected **web scanning** from `198.51.100.77`: 13 error responses across 13
   paths, including a `200 OK` on `/backup.sql` (critical exposure lead).
3. Detected a **12-port firewall scan** from `192.0.2.88`, plus three matches
   against the local watchlist (C2 IP, malware domain, file hash).
4. Produced a **CRITICAL (100/100)** risk summary with 9 findings from 83
   parsed events; JSON and Markdown outputs are committed in `sample_output/`.

## Quick Start

From the repository root:

```bash
python --version
python -m pip install -r tool/requirements.txt
python tool/log_triage.py --input sample_input/triage_sample.log --out-dir sample_output
```

Expected console summary:

```text
LogTriage v1.0.0 | defensive log triage (read-only)
==================================================================
Input     : sample_input/triage_sample.log (11.7 KiB, 83 lines)
Parsed    : 83 events | ssh=20, http=39, dns=5, firewall=13, edr=2
IOCs      : 7 external IPv4, 9 internal IPv4, 4 domains, 3 hashes, 0 URLs
Watchlist : 3 indicators | 3 matching IOCs
Risk      : CRITICAL (100/100) | 9 findings (2 critical, 5 high, 2 medium)
Outputs
  JSON     : sample_output/triage.json
  Markdown : sample_output/triage.md
```

Defaults come from `tool/tool.config`. Edit that file to change thresholds,
output paths, or run defaults; CLI flags still override the file.

Run the tests:

```bash
python -m unittest discover -s tool -p "test_*.py" -v
```

Expected result: `Ran 18 tests ... OK`.

Useful variants:

```bash
# JSON only
python tool/log_triage.py -i sample_input/triage_sample.log --format json

# Fail a CI job when high risk or worse is detected
python tool/log_triage.py -i sample_input/triage_sample.log --fail-on high

# Lower the brute-force threshold and broaden the correlation window
python tool/log_triage.py -i auth.log --brute-threshold 4 --window 60

# Custom watchlist, or disable watchlist matching entirely
python tool/log_triage.py -i auth.log --watchlist my_watchlist.json
python tool/log_triage.py -i auth.log --no-watchlist
```

## Inputs

Supported log shapes (all are best-effort; unknown lines still get IOC-scanned):

| Format | Example signal | Parsed fields |
|---|---|---|
| OpenSSH (syslog) | `Failed password`, `Accepted`, `Invalid user` | timestamp, host, user, source IP, outcome |
| Apache/Nginx combined | `IP - - [time] "GET /path HTTP/1.1" 404 233 "-" "UA"` | client IP, method, path, status, user-agent |
| dnsmasq | `query[A] host.example from 10.0.0.23` | query name, query type, client IP |
| UFW/iptables | `[UFW BLOCK] ... SRC=192.0.2.88 ... DPT=22` | source IP, destination port, action |
| Endpoint/EDR | `verdict=malicious action=quarantined sha256=...` | host, verdict, action, hashes |
| Generic | any line containing an IP/domain/hash/URL | indicators only |

Input rules:

- Input must be a text file, UTF-8 (a BOM is tolerated), maximum 50 MiB.
- Lines longer than 10,000 characters are truncated before parsing.
- ANSI escape sequences and control characters are stripped.
- Blank lines are skipped; non-blank unparseable lines are retained as
  `unparsed` events so indicators are not silently lost.
- Compressed, binary, and JSON-lines logs are not supported directly.

## Outputs

Two artifacts are written, plus a console summary:

| File | Contents |
|---|---|
| `sample_output/triage.md` | Human-readable report: risk summary, findings with evidence, IOC tables, timeline, event breakdown, detection logic, assumptions, safety |
| `sample_output/triage.json` | Machine-readable report: metadata, config, watchlist status, summary, findings, grouped IOCs, timeline, stats, limitations |

JSON top-level keys:

```text
schema_version, tool, generated_at, input, config, watchlist, summary,
findings, iocs, timeline, stats, limitations
```

- `input` includes the input path, SHA-256, byte size, line count, and parsed
  event count, so a run can be tied back to an exact file.
- `summary` includes the risk score/level, severity counts, and IOC counts.
- `findings[]` includes id, rule, title, severity, confidence, source IP,
  first/last seen, count, description, recommendation, MITRE IDs, evidence line
  numbers, and rule-specific details.
- `iocs` is grouped into `ipv4_external`, `ipv4_internal`, `ipv4_reserved`,
  `domains`, `hashes`, and `urls`. Each entry lists hits, contexts, timestamps,
  source IPs, hosts, and any watchlist match.
- `timeline` contains up to 40 de-duplicated suspicious events linked to
  finding IDs.

Output behaviour:

- Files are UTF-8 with LF line endings.
- Existing output files are overwritten; the input file is never written to.
- `--format both|md|json` selects artifacts; `--output-prefix` changes the
  basename.
- Exit codes: `0` success, `1` `--fail-on` threshold reached, `2` input or
  configuration error.

Console output is a compact summary only; the full detail is in the two files.
Colour is used only when stdout is a TTY and `--no-color`/`NO_COLOR` are absent.

## Detection Rules

| Rule | Logic | Default threshold | MITRE ATT&CK |
|---|---|---|---|
| `brute_force` | Failed SSH logins clustered per source IP by inter-event gap; flags a successful login within 300s after the burst as critical | 5 failures / 20s | T1110, T1110.001, T1110.003 |
| `http_scanning` | HTTP 4xx/5xx clustered per source IP; distinct paths and sensitive targets raise severity | 10 errors or 8 distinct paths / 20s | T1595, T1595.002, T1190 |
| `sensitive_file_exposure` | HTTP 2xx returned for a sensitive path (`.env`, `.git`, backups, `.aws`, `.ssh`, admin panels, traversal) | any match | T1552.001, T1190 |
| `port_scanning` | Firewall blocks clustered per source IP by distinct destination ports | 8 ports / 20s | T1046, T1595.001 |
| `scanner_user_agent` | User-agent matches sqlmap, Nikto, nmap, masscan, zgrab, Nuclei, gobuster, ffuf, etc. | any match | T1595, T1595.002 |
| `watchlist_ip`, `watchlist_domain`, `watchlist_hash` | Extracted indicator matches the local JSON watchlist | any match | Rule-dependent |

Risk scoring is intentionally simple and documented:

- Severity weights: critical 40, high 25, medium 10, low 3, info 0.
- Score = sum of finding weights, capped at 100.
- Levels: clean 0, low <20, medium <45, high <70, critical >=70.

Findings are sorted by severity, then first-seen time, and assigned stable IDs
(`F-001`, `F-002`, ...) for the run.

## CLI Options

| Option | Default | Purpose |
|---|---|---|
| `-i, --input PATH` | required (or `input` in config) | Text log to triage |
| `--config PATH` | `tool/tool.config` if present | INI configuration file |
| `-o, --out-dir PATH` | `sample_output` | Output directory (created if needed) |
| `--output-prefix NAME` | `triage` | Output basename (`triage.json`, `triage.md`) |
| `--format {both,json,md}` | `both` | Select output artifacts |
| `--watchlist PATH` | `tool/watchlist.json` if present | Local JSON watchlist |
| `--no-watchlist` | off | Disable watchlist matching |
| `--window SECONDS` | `20` | Correlation window for clustering |
| `--brute-threshold N` | `5` | SSH failures per window |
| `--scan-threshold N` | `10` | HTTP errors per window |
| `--port-scan-threshold N` | `8` | Distinct blocked ports per window |
| `--success-window SECONDS` | `300` | Look-back for success after an SSH burst |
| `--assume-year YYYY` | current year | Year for year-less syslog timestamps |
| `--max-bytes N` | `52,428,800` | Input size cap |
| `--fail-on LEVEL` | off | Exit 1 at low/medium/high/critical overall risk |
| `--quiet` | off | Suppress the console summary |
| `--no-color` | off | Disable ANSI colour |
| `--version` | - | Print version |

Run `python tool/log_triage.py --help` for the full, current list.

## Configuration

Runtime defaults live in **`tool/tool.config`**, an INI file loaded
automatically when it sits next to `log_triage.py`. Edit it to tune detection,
output, and run behaviour without changing code or passing flags every time.

Precedence: **command-line flags > `tool.config` > built-in defaults**.
Use `--config PATH` to load a different file. Relative paths in the file are
resolved from the directory you run the tool in. Unknown sections, unknown
keys, and invalid values are rejected with exit code 2, so a typo cannot
silently weaken detection.

| Section | Key | Maps to flag | Built-in default |
|---|---|---|---|
| `[detection]` | `window_seconds` | `--window` | `20` |
| `[detection]` | `brute_threshold` | `--brute-threshold` | `5` |
| `[detection]` | `scan_threshold` | `--scan-threshold` | `10` |
| `[detection]` | `port_scan_threshold` | `--port-scan-threshold` | `8` |
| `[detection]` | `success_window_seconds` | `--success-window` | `300` |
| `[limits]` | `assume_year` | `--assume-year` | current year |
| `[limits]` | `max_bytes` | `--max-bytes` | `52428800` |
| `[output]` | `out_dir` | `--out-dir` | `sample_output` |
| `[output]` | `output_prefix` | `--output-prefix` | `triage` |
| `[output]` | `format` | `--format` | `both` |
| `[run]` | `input` | `--input` | none (CLI required) |
| `[run]` | `watchlist` | `--watchlist` | auto-detect |
| `[run]` | `no_watchlist` | `--no-watchlist` | `false` |
| `[run]` | `fail_on` | `--fail-on` | none |
| `[run]` | `quiet` | `--quiet` | `false` |
| `[run]` | `no_color` | `--no-color` | `false` |

Example file:

```ini
[detection]
window_seconds = 20
brute_threshold = 5

[output]
out_dir = sample_output
format = both

[run]
quiet = false
no_color = false
```

The committed `tool/tool.config` documents every key with comments. Optional
entries (`input`, `watchlist`, `assume_year`, `fail_on`) are commented out by
default so the tool does not silently reuse a stale target file.

## Watchlist

Watchlist matching is optional and local. The default file is
`tool/watchlist.json`, loaded automatically when present.

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

- Categories may be objects or plain lists.
- Invalid entries are skipped with a warning rather than aborting the run.
- `confidence` maps to finding severity: high -> high, medium -> medium,
  low -> low.
- The included list is synthetic demo data, not a threat-intelligence feed.

## Limitations

- Behavioural detections are threshold-based; defaults are tuned for a small
  lab log and would need baselining in production.
- Timestamps without a zone are treated as UTC; syslog lines use
  `--assume-year` (default: current year).
- Only IPv4 indicators are aggregated; IPv6 source addresses are parsed where
  the log format exposes them but are not inventoried.
- No packet payloads, HTTP bodies, or file contents are inspected. A 2xx
  response for a sensitive path is a lead, not proof of compromise.
- The watchlist is a local synthetic demo list, not a threat-intelligence feed.
- Input is capped at 50 MiB because events are held in memory.
- Correlation is limited to a single file and a single process run.
- Mixed formats are supported best-effort; unknown lines are IOC-scanned but not
  correlated behaviourally.
- The JSON report is a triage artifact, not a STIX/TAXII export.

## Assumptions

- Log timestamps are parsed as UTC when no offset is present.
- Syslog timestamps have no year, so `--assume-year` supplies it.
- Source addresses are treated as untrusted unless inside RFC 1918, loopback,
  link-local, CGNAT, multicast, or reserved space.
- A blocked connection is evidence of attempted reconnaissance, not of success.
- A 4xx/5xx response is treated as a failed probe; a 2xx on a sensitive path is
  escalated for manual validation.
- Sample data uses only documentation/private address space and `.example`
  domains; no real users, hosts, or malware are represented.

## Reproduce

```bash
python --version
python -m pip install -r tool/requirements.txt
python tool/log_triage.py --input sample_input/triage_sample.log --out-dir sample_output
python -m unittest discover -s tool -p "test_*.py" -v
```

The command is read-only with respect to the input and makes no network calls.
The committed `sample_output/triage.md` and `sample_output/triage.json` were
generated by this exact command. Re-running the tool refreshes `generated_at`;
findings and IOC counts stay stable because the sample input is committed and
deterministic.

To regenerate the synthetic input itself:

```bash
python sample_input/generate_sample.py
```

## Testing

The suite runs with the standard library only:

```bash
python -m unittest discover -s tool -p "test_*.py" -v
```

Coverage includes:

- IPv4 validation and de-duplication, domain/file-extension filtering, hash
  length classification, and sensitive-path labelling.
- SSH, HTTP, and UFW line parsing, plus ANSI/control-character stripping.
- End-to-end detection on a generated log: brute force, web scanning,
  sensitive-path exposure, and scanner user-agent findings.
- Threshold behaviour (4 failures do not trigger a 5-failure rule).
- Watchlist loading, normalization, and lookup.
- JSON serialization and Markdown rendering, including HTML escaping.
- A full CLI run against the committed sample, asserting both output files.
- Configuration loading, CLI-over-config precedence, config-supplied input and
  output, and rejection of unknown keys.

## Repository Layout

```text
.
|-- README.md                  Submission-facing overview (this file)
|-- report.md                  1-page mission report with evidence links
|-- tool/
|   |-- log_triage.py          CLI entry point and output writing
|   |-- triage_config.py       INI config loading and validation
|   |-- tool.config            Editable runtime configuration
|   |-- triage_types.py        Dataclasses, constants, risk scoring
|   |-- triage_parse.py        Ingestion, parsing, IOC extraction
|   |-- triage_detect.py       Watchlist, detectors, orchestration
|   |-- triage_report.py       JSON and Markdown rendering
|   |-- watchlist.json         Synthetic demo indicators
|   |-- requirements.txt       No third-party dependencies
|   |-- test_log_triage.py     Unit and end-to-end tests
|   `-- README.md              Detailed tool documentation
|-- sample_input/
|   |-- triage_sample.log      Committed synthetic log (83 lines)
|   |-- generate_sample.py     Deterministic generator
|   `-- README.md              Scenarios and safety notes
|-- sample_output/
|   |-- triage.md              Committed Markdown report
|   `-- triage.json            Committed JSON report
|-- evidence/                  Run/output screenshots and notes
`-- sources/links.md           Public references
```

## Safety

This is a **Blue** defensive tool. It has no offensive capability, no target
selection, no network access, and no destructive actions. The sample data uses
only RFC 5737 documentation addresses, RFC 1918 private addresses, and reserved
`.example` domains. There are no real credentials, secrets, or PII in the repo.

Safety guards in the code:

- Read-only input handling; output paths are validated and the input path is
  refused as an output target.
- No `eval`, `exec`, subprocess calls, or outbound requests.
- 50 MiB input cap, 10,000-character line cap, and bounded in-memory events.
- Markdown/HTML escaping of log-derived text and truncation of evidence lines.
- Local, static watchlist; no external enrichment or telemetry.

## Self-Attestation

I self-sourced all materials, used only public/synthetic/self-owned resources,
built a working tool, and performed non-destructive work.
