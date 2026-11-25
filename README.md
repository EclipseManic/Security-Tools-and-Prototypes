# Security Tools and Prototypes

Small defensive tools, each built to answer one question that came up during lab
work or an investigation. They live in one repository because they share the same
shape: one command, one input, one answer, and an honest statement of what the
answer cannot tell you.

None of these is a product. There is no server to deploy, no tenant model, no
telemetry and no claim of production readiness. Most are Python standard library
only, and the ones that are not say so in their own README.

## Tools

| Tool | What it does | Runs on | Tests |
|---|---|---|---|
| [FwScan](tools/fwscan/) | Reads a firewall deny log and separates sweep, subnet-wide and distributed port scans, with the reasoning for each source | Python 3.10+, no dependencies | 2 test files |
| [LogTriage](tools/log-triage/) | Ranked findings, indicator inventory with first and last seen times, Markdown and JSON report | Python 3.10+, standard library only | yes |
| [Endpoint Behavior Monitor](tools/endpoint-monitor/) | Windows keystroke and active-window logger, kept to study how that telemetry is produced | pynput, pygetwindow. Authorised hosts only | none |
| [Malware Analyzer CLI](tools/malware-analyzer/) | File triage: hashes, YARA rules, PE metadata, optional VirusTotal lookups | see its README; API key optional | none |
| [Phishing Mail Detector](tools/phishing-mail-detector/) | `.eml` header and content analysis with a SAFE / CAUTIOUS / UNSAFE verdict | see its README; API key optional | none |
| [File Intelligence Platform](tools/file-intelligence/) | Local-first file inventory and sensitive-data discovery with a small web UI | see its README | 8 test files |
| [ThreatSentry AI](tools/threat-sentry/) | Shodan and NVD prototype that scores exposed hosts and drafts alerts | see its README | none |

"Tests: yes" means the test files are present and run; it is not a coverage claim.

## Screenshots

Real output from a real run on this machine, not mockups.

**FwScan** - `python fwscan.py demo`, 2812 synthetic deny records, four scan
patterns found:

![FwScan demo output](docs/screenshots/fwscan-demo.png)

**LogTriage** - `python tool/log_triage.py --input sample_input/triage_sample.log`:

![LogTriage findings](docs/screenshots/logtriage-triage.png)

## Why one repository

Each of these started as its own repository. Seven small repositories with one
commit or two each read as noise on a profile and made every tool harder to find,
so they were merged here with their commit history intact:

```text
git merge -s ours --no-commit --allow-unrelated-histories <tool>/main
git read-tree --prefix=tools/<slug>/ -u <tool>/main
```

Every original commit is reachable in `git log`, and the standalone repositories
are being retired in favour of this one. The history is the part worth keeping,
and it is here.

## What is deliberately not here

The five analyst tools that were folded into one workbench live there and only
there: IOC lookup, malware analysis, phishing analysis, EVTX event analysis and
detection-rule translation are all in SecLyst, which is still in development and
private until that work settles. Nothing is duplicated between the two.

RuleForge, ServiceSentinel and SOC IR Trainer are large enough to stand on their
own and stay as separate repositories.

## Limits that apply to all of them

- Each tool answers a narrow question about one input. None of them detects "an
  incident", and none replaces reading the evidence.
- No CI runs at this root. The per-tool workflow files came along in the merge but
  only execute from a repository root, so treat the test claims in each tool's
  README as something to run yourself: `python run.py verify` for RuleForge,
  `pytest` for ServiceSentinel.
- Two tools call external services (VirusTotal, Shodan). Without keys they fall
  back to offline checks, and the verdicts are weaker for it.
- Quality varies with age. The 2025 scripts were learning work; the newer tools
  have tests.
- AI coding assistants were used for scaffolding and boilerplate. The problem
  definition, the detection logic and the limits written here are mine.

## Licence

MIT. See `LICENSE`.
