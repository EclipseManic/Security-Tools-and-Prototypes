# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.x | Yes |

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub's private vulnerability reporting:
<https://github.com/EclipseManic/file-intelligence-platform/security/advisories/new>

Include the version, operating system, reproduction steps, and the impact you
believe is possible. You will get an acknowledgement and a triage decision.

## Threat model

File Intelligence Platform is a **local, single-user application**. It is not a
multi-tenant service and it is not designed to be exposed to the internet.

In scope:

- the local HTTP API and the React GUI;
- path handling during scans and report downloads;
- the SQLite database and its contents;
- handling of AI provider keys;
- leakage of scanned file content, host paths, or findings through logs,
  reports, or repository files.

Out of scope:

- an attacker who already has the user's OS account or administrator rights;
- a compromised Python installation, browser, or AI provider account;
- denial of service caused by exhausting the host's own resources;
- content the user deliberately exports, screenshots, or shares.

## Security controls

- **Loopback by default.** The API and GUI bind `127.0.0.1`. Docker publishes
  ports on `127.0.0.1` only. Changing the bind address is an explicit choice
  that the README warns against.
- **Read-only scanning.** The scanner opens files for reading. It does not
  modify, move, or delete scanned content.
- **Read-only host mount.** The Compose deployment mounts host content at
  `/host-files` with `:ro`.
- **No upload endpoint.** Content enters the index by scanning a local path,
  not by HTTP upload.
- **Response headers.** The API sets CSP, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and a
  restrictive `Permissions-Policy`. nginx adds the same protections in Docker.
- **Non-root container.** The backend image runs as an unprivileged user.
- **Key handling.** Provider keys are read from the environment. They are never
  returned by an API response and never written into reports.
- **No telemetry.** The only outbound request is the optional AI batch call,
  and only when a provider is configured.

## Known limitations

- There is **no authentication**. The loopback bind is the access control. Do
  not expose the port to a LAN or the internet.
- The scanner can read any file the process can read. Run it as a standard
  user and point it only at content you are authorised to inspect.
- Sensitive-data detection is regex-based. It can produce false positives and
  false negatives.
- `backend/data/fip.db`, `.env`, and generated reports contain real paths,
  extracted text, and findings. Treat them as sensitive. They are gitignored.

## Safe deployment checklist

1. Run FIP on a workstation you control.
2. Keep the default loopback bind.
3. Use a standard user account, not an administrator.
4. Scan only directories you are authorised to inspect.
5. Keep `backend/data/`, `.env`, and generated reports out of repositories
   and shared drives.
6. If you enable AI, use a dedicated key with a spending limit.
7. Before publishing screenshots or reports, redact host names and paths.
