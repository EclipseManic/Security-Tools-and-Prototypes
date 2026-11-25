# Architecture

SOC IR Trainer is a single-process, local web application. A FastAPI service
serves both the JSON API and the built React single-page app, backed by SQLite.
There is no external database, queue, cache, or worker service.

```
Browser (React SPA)
   |  /api/v1/*  (JSON, X-Requested-With)
   v
FastAPI app  ──>  RunService  ──>  SQLite (sessions.db)
   |                  |
   |                  ├── offline concept scorer (in-process)
   |                  ├── background evaluation job (thread pool)
   |                  └── OpenRouter chat completion (optional)
   |
   └── static hosting for web/dist
```

## Components

| Path | Responsibility |
|---|---|
| `start.py` | Installs dependencies, builds the frontend when stale, binds the port, starts `uvicorn` |
| `api/app.py` | App factory, security headers, CSRF guard, exception envelope, SPA fallback |
| `api/routes.py` | `/api/v1` endpoints and response models |
| `api/auth.py` | Signed-cookie profile session and CSRF constants |
| `api/jobs.py` | In-process evaluation thread pool and job registry |
| `core/run_service.py` | Run state machine shared by the API and terminal trainer |
| `core/session_db.py` | Schema, migrations, profiles, runs, actions, metrics |
| `core/response_scorer.py` | Offline concept-coverage scoring |
| `core/ai_evaluator.py` | Prompt construction, OpenRouter call, JSON repair, fallback |
| `core/reporter.py` | HTML, PDF, and JSON rendering |
| `scenarios/loader.py` | YAML discovery, validation, and indexing |
| `web/src/` | React dashboard, library, workspace, debrief, progress, settings |

## Request flow

1. `start.py` resolves the database path, imports `create_app()`, and runs
   `uvicorn`. The frontend is built by Vite into `web/dist/` before startup when
   sources are newer than the build.
2. FastAPI serves `/api/v1/*` for JSON and falls back to `web/dist/index.html`
   for client-side routes.
3. A profile is created with `POST /api/v1/session`. The server signs a cookie
   containing only the profile name. Every later request resolves the profile
   from that cookie.
4. Mutating API requests must include `X-Requested-With: SOC-Trainer`. The
   browser app sets it centrally, so a cross-site form post cannot drive the
   API.
5. API responses use a consistent envelope. Expected failures raise `ApiError`
   and are converted to a stable `{error: {code, message, detail}}` shape.

## Data model

SQLite runs in WAL mode with a busy timeout. Each request opens a short-lived
connection; writes are serialized by SQLite.

| Table | Contents |
|---|---|
| `users` | Profile name, role, selected domains, timestamps |
| `runs` | Scenario id, role, status, score, grade, timestamps, evaluation JSON |
| `actions` | One row per answered phase: choice or free text, concept score, parts, hint and reveal usage, technique |
| `domain_metrics` | Aggregated per-domain performance |
| `mastery` | Per-technique exposure and success |

The database is the durable source of truth. The in-memory job registry only
tracks evaluation progress; after a restart, a completed run is read back from
`runs`.

## Run lifecycle

```
created ──answer──> in_progress ──finish──> evaluating ──> completed
   │                    │                        │
   │                    └──abandon──> abandoned  └──failure──> completed (fallback)
   └──abandon──> abandoned
```

- **Start** validates the scenario id, resolves the role, and stores the run.
- **Answer** validates the phase index, stores the response, runs the offline
  scorer, and advances the cursor. It returns the next public phase only; it
  never returns correctness, reference answers, or the ideal choice.
- **Hint/reveal** records usage on the action and returns the hint or reference
  text. Both are counted in the debrief and apply a small capped assist penalty.
- **Draft** stores unfinished text so a refresh does not lose work.
- **Finish** marks the run evaluating and submits a background job.
- **Evaluation** is polled by the SPA. The job writes the evaluation JSON and
  final score to the run, then marks it completed.

Free-text answers are scored twice: once offline, at answer time, against the
scenario's reference concepts; and once by the AI at finish time, which receives
the offline scores as evidence and may agree, correct, or explain them.

## Evaluation pipeline

```
answers + offline scores
        |
        ├── AI enabled ──> prompt builder ──> OpenRouter ──> lenient JSON parse
        |                                        |                 |
        |                                        └── error ──> offline fallback
        |
        └── AI disabled ──> offline fallback
                                |
                                v
                    normalised evaluation object
                                |
                                v
                    runs.evaluation + runs.score + grade
```

The AI request is a single chat completion containing the incident briefing,
phase prompts, the analyst's responses, role, hint/reveal usage, and offline
scores. The parser strips code fences, repairs common JSON mistakes, normalises
keys, and fills required fields so the UI always receives a complete object.

The fallback derives a 0–100 score from the recorded offline phase scores,
applies the assist penalty, assigns a grade, and writes its own per-phase
feedback. It is deterministic and requires no network. Every evaluation carries
`fallback: true|false`, which the debrief displays.

## Security boundaries

- **Network:** loopback only by default; a non-loopback bind requires
  `--allow-lan`. TLS is not terminated by the app; put it behind a reverse proxy
  if you ever serve it remotely.
- **Identity:** single-user signed cookie, no password. This is deliberate: the
  loopback bind is the access control, and multi-user auth would add complexity
  without changing the local threat model.
- **CSRF:** header requirement on POST/PUT/PATCH/DELETE under `/api/v1`.
- **Content:** strict CSP, `X-Frame-Options: DENY`, `nosniff`, and
  `no-referrer`.
- **Secrets:** the OpenRouter key is stored in `.env`, loaded into process
  memory, and never serialized to a response. The UI only sees
  `api_key_configured`.
- **Files:** report downloads are generated from the run's own evaluation and
  written to `reports/`; the API does not accept arbitrary paths.
- **Input limits:** free-text answers and drafts are capped at 8,000 characters.

## Trade-offs

- **Process-local jobs** keep the app dependency-free. Evaluation survives a
  page refresh, but not a server restart; on restart the run stays `evaluating`
  until it is finished again or abandoned.
- **SQLite over a service** keeps the install to one command and makes the data
  easy to inspect, back up, and delete.
- **YAML scenarios** make content reviewable in a pull request without touching
  Python. The loader validates required fields and fails loudly on bad content.
- **Offline scoring** gives every answer a score even without a key, at the cost
  of being a concept-coverage heuristic rather than a semantic judge.
- **A single AI call at the end** keeps cost and latency predictable and avoids
  leaking phase-by-phase correctness during the run.
