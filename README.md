# Security-Tools-and-Prototypes

Defensive security utilities and prototypes, consolidated from earlier standalone repositories. Each tool here was built to solve one specific problem that came up during lab work or an investigation. None of them is a product, and none is described as production-ready.

## Utilities

| Tool | What it does |
| --- | --- |
| [ThreatSentry-AI](https://github.com/EclipseManic/ThreatSentry-AI) | Experimental Shodan + NVD prototype that scores exposed hosts by risk |
| [FwScan](https://github.com/EclipseManic/FwScan) | Firewall-log port-scan analysis CLI: classifies sweep, subnet-wide and distributed scans |
| [File-Intelligence-Platform](https://github.com/EclipseManic/File-Intelligence-Platform) | Local-first file intelligence and sensitive-data discovery |
| [Advance_Phishing_Mail_Detector_CLI](https://github.com/EclipseManic/Advance_Phishing_Mail_Detector_CLI) | Inspects `.eml` files for phishing indicators |
| [Malware_Analyzer_CLI](https://github.com/EclipseManic/Malware_Analyzer_CLI) | Offline and online malware triage |
| [LogTriage](https://github.com/EclipseManic/LogTriage) | Defensive log triage CLI: IOC extraction, brute-force and scanning detection |

These are being moved in from their standalone repositories, so for now each link points at the original.

## What is deliberately not here

The five analyst tools that were folded into a single workbench live there and only there: IOC lookup, malware analysis, phishing analysis, EVTX event analysis and detection-rule translation are all in SecLyst (in development; public once the integration work settles). Nothing is duplicated between the two repositories.

## Notes

- Every tool carries its own README with its real scope and known gaps. Read that before assuming a capability.
- Quality varies with age. The 2025 scripts were learning exercises; some of the newer tools have tests.
- AI coding assistants were used for boilerplate and scaffolding. The problem definition, and the logic that actually matters, are mine.
