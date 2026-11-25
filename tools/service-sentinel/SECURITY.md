# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 3.x | Yes |
| 2.x and older | No |

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub's private vulnerability reporting:
<https://github.com/EclipseManic/servicesentinel/security/advisories/new>

Include the version, Windows build, reproduction steps, and the impact you
believe is possible. You will get an acknowledgement, a triage decision, and a
coordinated disclosure timeline.

## Threat model

ServiceSentinel is a **local, single-host** Windows administration and incident
response console. It is not a multi-tenant service and it is not designed to be
exposed to the internet.

In scope:

- the local web console and its HTTP API;
- authentication, session handling, CSRF protection, and request limits;
- path handling and the guarded service-management workflow;
- export handling and spreadsheet formula injection;
- leakage of host evidence through logs, exports, or repository files.

Out of scope:

- an attacker who already has administrator or SYSTEM rights on the host;
- a compromised Windows installation, PowerShell, or service control manager;
- denial of service caused by exhausting the host's own resources;
- data that the user deliberately exports from the console.

## Security controls

- **Loopback by default.** The server binds `127.0.0.1` unless `--allow-remote`
  is supplied, and a non-loopback bind is refused without a password.
- **Optional password login** with rate limiting (`8` failed attempts, then a
  `60` second lockout).
- **CSRF token.** Every mutating request must carry the per-session
  `X-Sentinel-Token` header.
- **Signed, HttpOnly, SameSite=Strict session cookie** with an 8-hour lifetime.
- **Strict response headers:** CSP (`default-src 'self'`), `X-Frame-Options:
  DENY`, `nosniff`, `no-referrer`, and `Cache-Control: no-store`.
- **Request limit:** 1 MB maximum body size.
- **Guarded management:** elevation check, exact case-sensitive service-name
  confirmation, core-service refusal, configuration backup before disruptive
  actions, per-step results, rollback, and delete verification.
- **No egress.** No telemetry, no reputation lookups, no outbound calls.

## Safe deployment checklist

1. Run it from an account you control, on a host you are authorised to inspect.
2. Keep the default loopback bind unless you have a specific need to go remote.
3. If you must go remote, put it behind a firewall rule for named admin hosts and
   add TLS at a reverse proxy. Use a password, and prefer the
   `SENTINEL_PASSWORD` environment variable over `--password`.
4. Run elevated only when you need complete metadata or service management.
5. Treat `ServiceSentinelData/` as sensitive evidence. It contains hostnames,
   paths, hashes, and analyst notes. Do not commit it or copy it to an untrusted
   share.
6. Create a baseline only when the host is known to be clean.
7. Verify business impact before stopping, containing, or deleting a service.

## Data handling

Everything is stored under `ServiceSentinelData/` beside the project, or under
`%LOCALAPPDATA%\ServiceSentinel` when the project folder is not writable. The
folder is excluded by `.gitignore`. There is no cloud component and no
telemetry.

## Known limitations

Scores are heuristics, not malware verdicts. ServiceDll values and full
executable ACLs are not audited. Event visibility depends on the host's audit
policy and log retention. See the Limitations section of the README.
