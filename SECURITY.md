# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 3.x | Yes |
| 2.x and older | No |

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub's private vulnerability reporting:
<https://github.com/EclipseManic/soc-ir-trainer/security/advisories/new>

Include the version, operating system, reproduction steps, and the impact you
believe is possible. You will get an acknowledgement, a triage decision, and a
coordinated disclosure timeline.

## Threat model

SOC IR Trainer is a **local, single-user training application**. It is not a
multi-tenant service and it is not designed to be exposed to the internet.

In scope:

- the local web console and its HTTP API;
- the signed session cookie, CSRF guard, CSP, and security headers;
- path handling for reports and the SQLite session database;
- handling of the OpenRouter API key, including whether it can be read back
  through the API or the browser;
- leakage of local profile names, typed answers, or API keys through logs,
  reports, or repository files.

Out of scope:

- an attacker who already has the user's OS account or administrator rights;
- a compromised Python installation, browser, or OpenRouter account;
- denial of service caused by exhausting the host's own resources;
- content that the user deliberately exports, screenshots, or shares.

## Security controls

- **Loopback by default.** `start.py` binds `127.0.0.1` and refuses a
  non-loopback host unless `--allow-lan` is supplied.
- **Signed session cookie.** The cookie carries only the chosen profile name
  and is signed with a local secret stored in `.session_secret` (gitignored) or
  `SOC_SESSION_SECRET`. It is `HttpOnly`, `SameSite=Lax`, and expires after 30
  days. There is no password: this is a single-user local tool, so the loopback
  bind is the access control.
- **CSRF guard.** Mutating `/api/v1` requests must carry
  `X-Requested-With: SOC-Trainer`.
- **Strict response headers:** CSP (`default-src 'self'`),
  `X-Frame-Options: DENY`, `nosniff`, and `no-referrer`.
- **Answer limits.** Free-text answers and drafts are capped at 8,000
  characters by the API.
- **API key handling.** The OpenRouter key is persisted in `.env`
  (gitignored) and is never returned to the browser. The API exposes only
  `api_key_configured: true|false`.
- **No telemetry.** The only outbound requests go to OpenRouter: a cached model
  catalog fetch when the Settings page asks for it, and the evaluation request
  when a run is finished with AI enabled.

## Safe deployment checklist

1. Run the trainer on a workstation you control.
2. Keep the default loopback bind. Do not expose the port to a LAN or the
   internet unless every user is trusted and the host is otherwise isolated.
3. Treat `.env`, `sessions.db`, `sessions.bak-*.db`, `.session_secret`, and
   `reports/` as sensitive. They contain profile names, typed answers, and
   possibly an API key. All are excluded by `.gitignore`.
4. Do not commit chat transcripts, screenshots with hostnames, or exported
   reports to a public repository.
5. Use a dedicated OpenRouter key with a spending limit. Revoke it from the
   OpenRouter dashboard if it is exposed.

## Data handling

Profiles, run history, drafts, and evaluations live in `sessions.db` beside the
project, or at the path given with `--db`. Reports are written to `reports/`.
Both are local-only.

When AI evaluation is enabled, one request is sent to
`https://openrouter.ai/api/v1/chat/completions`. It contains the incident
title, category, summary, phase prompts, the analyst's responses, the role,
hint usage, reference lookups, and the offline concept score. It does not
contain the API key, local file paths, hostnames, or the session database.
Opening the model picker fetches the public OpenRouter model catalog. If
privacy is a concern, leave the API key unset and use the offline debrief.

## Known limitations

The offline debrief is a concept-coverage heuristic, not a human grade. AI
feedback can be wrong or inconsistent between models. Scenario content is
fictional and must not be treated as a real incident-response playbook. See the
Limitations section of the README.
