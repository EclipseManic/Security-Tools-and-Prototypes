# Changelog

All notable changes to ServiceSentinel are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## [3.0.0] - 2026-11-19

Initial public release of the web console.

### Added

- Local web console for Windows service inventory, hunting, timelines, baselines,
  triage, reports, and guarded management.
- Explainable threat and reliability scoring with explicit data gaps instead of
  guessed values.
- Service Control Manager timeline with daily and weekly summaries and localised
  state-word learning.
- Trusted baselines with change, rotation, and unverifiable-value reporting.
- Append-only analyst triage with live evidence snapshots.
- CSV, JSON, and HTML exports with formula-injection protection.
- Optional password authentication, per-session CSRF tokens, strict security
  headers, request-size limits, and a health endpoint.
- Guarded management with elevation checks, core-service refusal, configuration
  backups, rollback, and delete verification.
- 70 unit and API tests covering scoring, baselines, exports, retention,
  authentication, CSRF, and management safety.

### Notes

The original PowerShell prototype is not included in this repository. The
defects it exposed, and the design decisions that replaced them, are recorded in
[`docs/DESIGN-NOTES.md`](docs/DESIGN-NOTES.md).
