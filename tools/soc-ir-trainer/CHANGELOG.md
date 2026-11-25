# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-11-20

Initial public release.

### Added

- Browser GUI (React + Vite) served by the FastAPI application: dashboard,
  scenario library, run workspace, debrief, progress, onboarding, and settings.
- 133 YAML scenarios across Endpoint, Identity & Access, Web App, Cloud,
  Advanced Threats, Network, and AI & ML, including 51 Easy scenarios.
- Role-aware evaluation for SOC Analyst, Incident Manager, CISO, and Executive.
- Per-phase free-text answers scored against reference concepts, replacing the
  legacy multiple-choice content format.
- Hints, reference reveals, and draft persistence with usage recorded in the
  debrief.
- Background evaluation jobs with resumable runs and a polling debrief.
- Offline debrief fallback when no API key is configured or the AI call fails.
- HTML, PDF, and JSON report downloads from the GUI.
- Settings for the OpenRouter key, live model catalog, profile updates, history
  clearing, and profile deletion.
- Signed-cookie profile sessions, a CSRF header for mutating requests, CSP and
  security headers, and loopback-only binding by default.
- 72-test pytest suite and cross-platform CI.

### Changed

- Scenarios are now loaded from YAML data files instead of Python classes.
- The terminal trainer shares the run state machine with the API.
- `start.py` handles dependency installation, frontend builds, and serving.

### Removed

- The legacy Python scenario modules and the obsolete scenario archive are no
  longer part of the repository.

[3.0.0]: https://github.com/EclipseManic/soc-ir-trainer/releases/tag/v3.0.0
