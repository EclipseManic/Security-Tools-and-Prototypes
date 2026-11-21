# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-11-21

### Fixed

- Dashboard category totals now cover every indexed file, including files
  whose analyzer returned no content (for example, SVG images). The category
  card and chart share one distribution, so they always add up to the file
  total.
- Known-safe AI insights use a neutral green `safe` badge instead of the
  severity colour reserved for threat findings, and recommendations show
  their priority explicitly.
- A scan now backfills a category for any file that has none, which also
  repairs databases created before this release.

## [1.0.0] - 2026-11-21

Initial public release.

### Added

- Recursive filesystem scans with pause, resume, cancel, progress, and
  per-file error reporting.
- Metadata indexing: size, timestamps, owner, permissions, MIME type, magic
  bytes, SHA-256, MD5, entropy, and duplicate groups.
- Content analyzers for PDF, Office documents, Outlook `.msg`, text and source
  code, archives, executables, images, and media.
- Sensitive-data detection with 40+ patterns across PII, financial data,
  credentials, cloud credentials, private keys, infrastructure, and network
  artifacts, plus an explainable 0–100 risk score.
- Dashboard, search and filters, category views, file detail pages, and scan
  management in a React GUI.
- Executive summary, full inventory, sensitivity audit, duplicate, largest
  file, and category reports in CSV, HTML, and JSON.
- Optional AI enrichment through Gemini, OpenRouter, OpenAI, or BazaarLink,
  with one anonymized batch request per scan and complete offline operation
  when no key is configured.
- Single-command launcher (`run.py`) that builds the frontend and serves the
  API and GUI from one process.
- Docker Compose deployment with a non-root backend, nginx frontend, loopback
  port bindings, a read-only host mount, and health checks.
- Security headers, loopback-only defaults, and a documented threat model.
- Hermetic 21-test pytest suite and cross-platform CI, plus a frontend
  type-check and production build.
- Synthetic `examples/sample-data` corpus for a first run.

### Changed

- `DATABASE_URL` is now honoured for SQLite, with relative paths resolved
  against `backend/` instead of the current working directory.
- The default bind address changed from `0.0.0.0` to `127.0.0.1`.
- The backend image installs dependencies directly instead of building wheels
  with `--no-deps`, and uses platform markers for `python-magic`.
- The frontend image copies the lockfile before `npm ci`, fixing the Docker
  build.

### Removed

- Unused OCR dependency and the obsolete root-level batch test scripts.
- Generated report artifacts and caches from the repository.

[1.0.0]: https://github.com/EclipseManic/file-intelligence-platform/releases/tag/v1.0.0
