# Security Tools and Prototypes

Defensive tools I built, each answering one question that came up during lab work
or an investigation. They live in one repository because they share the same shape:
one input, one answer, and an honest statement of what the answer cannot tell you.

**The rule:** investigations, labs and the workbench get their own repositories.
Everything else I build — the tools — is indexed here.

None of these is a product. There is no server to deploy, no tenant model, no
telemetry and no claim of production readiness. Most are Python standard library
only, and the ones that are not say so in their own README.

## Tools

Every row links to something you can open without installing anything: a committed
sample report, a sample log, or a screenshot of a real run.

| Tool | What it does | Runs on | Evidence |
|---|---|---|---|
| [ServiceSentinel](tools/service-sentinel/) | Windows service and SCM triage for DFIR: inventory, explainable scoring, SCM timeline, trusted baselines, and evidence exports | Windows, Python 3.10+ | [overview screenshot](tools/service-sentinel/docs/screenshots/overview.png) |
| [SOC IR Trainer](tools/soc-ir-trainer/) | Browser-based incident-response trainer: 133 scenarios across seven domains, four roles, and a scored debrief | Python 3.11+, Node 18+ to build the UI | [scenario library screenshot](tools/soc-ir-trainer/docs/screenshots/library.png) |
| [FwScan](tools/fwscan/) | Reads a firewall deny log and separates sweep, subnet-wide and distributed port scans, with the reasoning for each source | Python 3.10+, no dependencies | [sample report](tools/fwscan/examples/report.txt) |
| [LogTriage](tools/log-triage/) | Ranked findings, indicator inventory with first and last seen times, Markdown and JSON report | Python 3.10+, standard library only | [sample Markdown + JSON](tools/log-triage/sample_output/) |
| [Endpoint Behavior Monitor](tools/endpoint-monitor/) | Windows keystroke and active-window logger, kept to study how that telemetry is produced | pynput, pygetwindow; authorised hosts only | [sample log (synthetic)](tools/endpoint-monitor/samples/key_log_sample.txt) |
| [Malware Analyzer CLI](tools/malware-analyzer/) | File triage: hashes, YARA rules, PE metadata, optional VirusTotal lookups | Python 3.8+; the offline path needs no keys | [sample report (txt + json)](tools/malware-analyzer/samples/) |
| [Phishing Mail Detector](tools/phishing-mail-detector/) | `.eml` header and content analysis with a SAFE / CAUTIOUS / UNSAFE verdict | Python 3.8+; `--no-vt` runs offline | [sample verdict + JSON](tools/phishing-mail-detector/samples/) |
| [File Intelligence Platform](tools/file-intelligence/) | Local-first file inventory and sensitive-data discovery with a small web UI | Python 3.12+, Node 20+ to build the UI | [dashboard screenshot](tools/file-intelligence/docs/screenshots/dashboard.png) · [sample data](tools/file-intelligence/examples/sample-data/) |
| [ThreatSentry AI](tools/threat-sentry/) | Shodan and NVD prototype that scores exposed hosts and drafts alerts | see its README; a Shodan key is needed for live data | [dashboard screenshot](tools/threat-sentry/assets/screenshots/Screenshot%202026-01-10%20153154.png) |

The malware and phishing samples are committed next to the exact commands that
produced them, so the output can be reproduced. The endpoint log is synthetic on
purpose: recording real keystrokes is not something to demonstrate. SOC IR Trainer
is a practice resource rather than an analyser — it is here so everything I build is
found in one place.

## Screenshots

Real output from real runs on this machine, not mockups.

| ServiceSentinel | SOC IR Trainer |
|---|---|
| ![ServiceSentinel overview](tools/service-sentinel/docs/screenshots/overview.png) | ![SOC IR Trainer scenario library](tools/soc-ir-trainer/docs/screenshots/library.png) |

| FwScan | LogTriage |
|---|---|
| ![FwScan demo output](docs/screenshots/fwscan-demo.png) | ![LogTriage findings](docs/screenshots/logtriage-triage.png) |

| Malware Analyzer CLI | Phishing Mail Detector |
|---|---|
| ![Malware Analyzer offline triage](docs/screenshots/malware-analyzer-report.png) | ![Phishing Mail Detector verdict](docs/screenshots/phishing-detector-verdict.png) |

| Endpoint Behavior Monitor | File Intelligence Platform |
|---|---|
| ![Endpoint Behavior Monitor sample log](docs/screenshots/endpoint-monitor-log.png) | ![File Intelligence dashboard](tools/file-intelligence/docs/screenshots/dashboard.png) |

**ThreatSentry AI** - main hunting interface:

![ThreatSentry AI dashboard](tools/threat-sentry/assets/screenshots/Screenshot%202026-01-10%20153154.png)

## Why one repository

Each of these started as its own repository. Nine repositories read as noise on a
profile and made every tool harder to find, so they were merged here with their
commit history intact:

```text
git merge -s ours --no-commit --allow-unrelated-histories <tool>/main
git read-tree --prefix=tools/<slug>/ -u <tool>/main
```

Every original commit is reachable in `git log`, and the nine standalone
repositories have been retired in favour of this one. The history is the part
worth keeping, and it is here.

If you followed an old link, the mapping is: `FwScan` → [`tools/fwscan/`](tools/fwscan/),
`LogTriage` → [`tools/log-triage/`](tools/log-triage/),
`Endpoint-Behavior-Monitor` → [`tools/endpoint-monitor/`](tools/endpoint-monitor/),
`Malware_Analyzer_CLI` → [`tools/malware-analyzer/`](tools/malware-analyzer/),
`Advance_Phishing_Mail_Detector_CLI` → [`tools/phishing-mail-detector/`](tools/phishing-mail-detector/),
`File-Intelligence-Platform` → [`tools/file-intelligence/`](tools/file-intelligence/),
`ThreatSentry-AI` → [`tools/threat-sentry/`](tools/threat-sentry/),
`ServiceSentinel` → [`tools/service-sentinel/`](tools/service-sentinel/),
`SOC-IR-Trainer` → [`tools/soc-ir-trainer/`](tools/soc-ir-trainer/).

## What is deliberately not here

The five analyst engines folded into the SecLyst workbench live there and only
there: IOC lookup, malware analysis, phishing analysis, EVTX event analysis and
detection-rule translation. SecLyst is in development and private until that work
settles. RuleForge, the detection-rule workbench from that set, also remains as a
standalone archived repository so its eight-dialect translation stays directly
reachable.

## Limits that apply to all of them

- Each tool answers a narrow question about one input. None of them detects "an
  incident", and none replaces reading the evidence.
- No CI runs at this root. The per-tool workflow files came along in the merge but
  only execute from a repository root, so treat the test claims in each tool's
  README as something to run yourself.
- A few tools call external services (VirusTotal, Shodan). Without keys they fall
  back to offline checks, and the verdicts are weaker for it.
- Quality varies with age. The 2025 scripts were learning work; the newer tools
  have tests.
- The problem definitions, detection logic and every limitation written above are mine.

## Licence

MIT. See `LICENSE`.

Part of my [SOC and detection portfolio](https://github.com/EclipseManic).
