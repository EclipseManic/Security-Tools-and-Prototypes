# Design notes

ServiceSentinel started as a terminal PowerShell tool. The maintained
implementation is the Python/Flask web console in this repository. The original
prototype is **not shipped**; this document records the defects it exposed and
the design decisions that replaced them, so the reasoning behind the rewrite is
auditable.

## The evidence model

Windows hides service metadata from non-elevated callers. A tool that scores
missing data will always produce findings it cannot justify. The console
therefore separates three states for every field:

- **checked and clean** — evidence exists and is compared or scored;
- **checked and bad** — evidence exists and contributes points;
- **could not check** — reported as a data gap with zero points, and the UI asks
  you to re-run elevated.

This is the single most important design rule in the project: *unknown is not
suspicious*.

## What the rewrite changed

| Defect in the original PowerShell prototype | Fix in the web console |
|---|---|
| A blank executable path scored `+15 "high-privilege account paired with a nonstandard path"`, so non-elevated runs invented risk for `LSM`, `McmSvc`, `NetSetupSvc`, `PlutonQcService` | Unknown path, signature and account contribute **zero** points and surface as explicit *data gaps* |
| A blank `StartName` was rewritten to `LocalSystem`, producing false "account changed" baseline hits | Blanks stay `Unknown`; accounts that are unreadable are never compared or scored |
| `sc.exe delete` never throws on failure, so deletion always reported success and logged `ACTION completed` | Native exit codes are checked; each step reports its own result; success is only shown when every step passed |
| `Contain` printed "Action completed" even when the stop or disable step failed | Same per-step reporting; failures are visible and logged as errors |
| User-writable detection only matched `C:\Users\...` and `Temp`, so a `Downloads` folder on another drive scored nothing | Path-segment detection covers Downloads, Desktop, AppData, Temp and profiles **on any drive** (this changed three real findings from High to Critical) |
| Triage always stored score 0, no path and no hash | Decisions store the live assessment: scores, levels, category, account, path, signer, signature and SHA-256 |
| Event 7036 state word was parsed in English only, silently degrading timelines elsewhere | The console learns this host's localised wording from current service states and shows unrecognised words verbatim |
| Categories "scored" keywords but every weight was equal, and matched the executable path (`UvxInstaller` filed a monitoring agent under Update and Deployment) | Weighted keywords in name/display name (+3) and description (+1); the path is no longer used for categorisation |
| Baseline comparison read `''` values as changes, and version-stamped service names produced High-severity created+deleted pairs on every app update | Values unknown in both snapshots are skipped, one-sided unknowns are listed as unverifiable, and version name rotation is classified `Low` |
| `$Service.Description`/timeline cache returned a wrapper object when the cached event list was empty | Rewritten in Python with an explicit event cache keyed by window and a correct empty-result path |
| Management had no protection for core services, no rollback path, and no fail-safe on partial containment | Core services (`RpcSs`, `DcomLaunch`, `EventLog`, `LSM`, `SamSs`, `Winmgmt`, …) are refused; containment is reversible from its backup |
| The old repo claimed a `.gitignore` that did not exist, so ~1.5 MB of host evidence was publishable | `.gitignore` excludes `ServiceSentinelData/`, baselines, triage records and caches |
| Version string disagreed with itself (1.1.0 vs 2.0.0); docs referenced a removed management unlock | One version constant, one documented behaviour, no unlock flow |
| No authentication, no CSRF-safe management path, Flask development server | Optional password login with rate limiting, per-session request token, strict CSP, waitress |
| Collector caches were not thread-safe and were keyed only on `evidence`, so a 24-hour inventory could be served to a 7-day hunt | One re-entrant lock around collection; cache keyed by evidence mode **and** event window |
| Scoring re-interpreted every event once per service (O(services x events)) | Events interpreted once and indexed by service name |
| Evidence, exports, logs and baseline history grew without limit | Retention pass prunes expired artifacts, caps exports and the evidence cache, never touching the baseline or triage log |
| CSV exports were open to spreadsheet formula injection via service names and analyst notes | Dangerous leading characters are quoted |
| Containment could leave a half-contained service with no recovery; deletion was never verified | Automatic rollback to the captured startup state, then delete verification with a recovery pointer |
| Management attempted actions without checking elevation | Actions refuse with an explicit message unless the console is elevated |
| No health endpoint, no request-size limit | `/api/health`, 1 MB body cap, security headers on every response |

## Consequences for users

- Findings are deliberately conservative. A clean score does not prove a service
  is benign; it means the checks that could run found nothing.
- The console asks for elevation when metadata is unreadable instead of inventing
  a value.
- Destructive actions are slower on purpose: exact name confirmation, a saved
  configuration backup, per-step results, and a rollback path.
- There is no cloud component. Evidence stays on the host unless the analyst
  exports it.
