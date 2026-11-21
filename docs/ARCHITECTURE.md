# Architecture

File Intelligence Platform is one local application with two halves: a FastAPI
backend that owns scanning, analysis, storage, and reporting, and a React
single-page app that reads the API.

## Request path

```
Browser (React) ──▶ FastAPI (/api/v1) ──▶ services ──▶ SQLAlchemy ──▶ SQLite
                          │
                          └──▶ report generation (CSV / HTML / JSON)
```

`run.py` builds `frontend/dist` when needed and starts uvicorn with
`backend/` as the working directory. `backend/app/main.py` mounts the built
assets and serves `index.html` for client-side routes, so local mode needs one
process and one port. In Docker, nginx serves `dist` and proxies `/api` to the
backend container.

## Modules

| Path | Responsibility |
|---|---|
| `backend/app/main.py` | App factory, security headers, SPA fallback |
| `backend/app/core/config.py` | Pydantic settings, paths, provider config |
| `backend/app/core/database.py` | Async engine, SQLite pragmas, session factory |
| `backend/app/core/logging.py` | Text/JSON logging setup |
| `backend/app/api/v1/scans.py` | Create, list, start, pause, resume, cancel, delete scans |
| `backend/app/api/v1/files.py` | File list, detail, and per-file artifacts |
| `backend/app/api/v1/search.py` | Filtered, paginated search |
| `backend/app/api/v1/stats.py` | Dashboard summary and distributions |
| `backend/app/api/v1/reports.py` | Report listing and downloads |
| `backend/app/api/v1/ai.py` | On-demand text analysis (optional provider) |
| `backend/app/services/scanner/` | Directory walk, progress, scan lifecycle |
| `backend/app/services/analyzer/` | Per-format extractors and orchestrator |
| `backend/app/services/detector/` | Sensitive patterns and risk scoring |
| `backend/app/services/ai/` | Provider adapters and anonymized batch insights |
| `backend/app/services/report/` | CSV/HTML/JSON report builders |

## Scan lifecycle

1. `POST /api/v1/scans` creates a `ScanJob` in `pending`.
2. `POST /api/v1/scans/{id}/start` launches the scan in a background task.
3. The directory scanner walks the path, applying exclusion rules and
   recording metadata, hashes, entropy, and duplicate groups in batches.
4. The orchestrator extracts text and metadata from each supported file.
5. The detector scores extracted text and writes findings and a sensitivity
   level.
6. If a provider is available, one anonymized batch request adds insights.
7. The job moves to `completed`, `failed`, or `cancelled`.

Pause, resume, and cancel are cooperative: the scanner checks its control flags
between files and batches.

## Data model

| Table | Contents |
|---|---|
| `scan_jobs` | Path, status, progress, counts, timestamps |
| `file_records` | Path, metadata, hashes, entropy, duplicate group |
| `file_contents` | Extracted text, OCR text, summaries, raw metadata |
| `file_categories` | Category, subcategory, confidence, explanation |
| `file_sensitivity` | Sensitivity level, risk score, explanation |
| `sensitive_findings` | Finding type, value, context, severity, count |
| `file_entities` | Extracted entities |
| `technical_artifacts` | Extracted technical indicators |
| `file_analyses` | Analyzer status and raw results |
| `file_timelines` | Observed file timeline events |
| `scan_insights` | Optional AI batch insights |

## Sensitive-data scoring

Each match contributes a severity weight (`critical` 25, `high` 15,
`medium` 8), capped per severity band. Additional weight is added for unique
finding types and for categories such as credentials, cloud, financial, PII,
and infrastructure. The total is clamped to 100 and mapped to:

| Score | Level |
|---:|---|
| 70–100 | Critical |
| 45–69.9 | Highly Confidential |
| 25–44.9 | Confidential |
| 10–24.9 | Internal |
| 0–9.9 | Public |

The explanation records which categories drove the score, so a finding can be
reviewed rather than trusted blindly.

## AI boundary

AI is optional and off by default. The scan path only calls it when
`AI_PROVIDER` resolves to an available provider (or a Gemini key is present).
The batch analyzer sends anonymized summaries — category, type, size band,
sensitivity, and counts — not file contents, full paths, or the database. A
failed or rate-limited call is logged and the scan still completes.

## Portability notes

- `DATABASE_URL` is honoured. Relative SQLite paths resolve against
  `backend/`, so the database lands in the same place whether the app starts
  from the repository root, `backend/`, or `/app` in Docker.
- `python-magic-bin` is installed on Windows and `python-magic` elsewhere.
  Without libmagic, the scanner falls back to extension and magic-byte
  signatures.
- The default exclusion list targets Windows system directories; adjust it for
  macOS and Linux deployments.
