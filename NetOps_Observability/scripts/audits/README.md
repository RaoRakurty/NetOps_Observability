# Audit suite

Re-runnable, stdlib-only black-box audits that exercise each module of the
running stack through its live API and assert it behaves as expected. Use them as
a regression gate after changes, or to spot-check a deployment.

## Run

```bash
# whole suite (logs in once per module; needs the admin password)
python3 scripts/audits/run.py --password '<admin pw>'

# a subset
python3 scripts/audits/run.py iam platform --password '<admin pw>'

# a single module, standalone
python3 scripts/audits/platform.py --password '<admin pw>'

# env instead of flags
IAM_AUDIT_BASE_URL=http://localhost:8000 IAM_AUDIT_USER=admin \
IAM_AUDIT_PASSWORD='<admin pw>' python3 scripts/audits/run.py

# treat known gaps (WARN) as failures
python3 scripts/audits/run.py --password '<pw>' --strict
```

Exit code: `0` if no module reports a FAIL, `1` otherwise (`--strict` also fails on WARN).

## Modules

| Module | Path | Covers |
|--------|------|--------|
| `iam` | `scripts/iam_audit.py` | Region→Org→Tenant→User tree, bindings, disable/delete + instant revocation, cross-tenant leak, password policy (length/complexity/reuse/lockout/idle) |
| `platform` | `audits/platform.py` | Breadth smoke across every backend module's API surface + unauthenticated rejection |
| `alerts` | `audits/alerts.py` | Alert rules (shape), active alerts, incidents (read-only) |
| `telemetry` | `audits/telemetry.py` | Data flow: logs / metrics / flows / findings reachable; WARN (not FAIL) on a dry pipe |
| `collectors` | `audits/collectors.py` | Collector status, SNMP credential CRUD + secret hygiene (v3 keys masked) |
| `notify` | `audits/notify.py` | Notification channel config + contact-point CRUD (never triggers real `/test` sends) |
| `reports` | `audits/reports.py` | Report channels, schedules/runs, execution history (never calls run/preview) |
| `integrations` | `audits/integrations.py` | ITSM/integration config + connector status + signed-webhook gate (config-only) |

## Severities

- **PASS** — a control that should hold, holds.
- **FAIL** — something implemented regressed → exit 1.
- **WARN** — a known gap / inherent trade-off (e.g. JWT cached until expiry, a
  policy knob stored but not yet enforced, v2c community shown by design).
- **INFO** — context only.

## Safety

The audits are safe to run against a live stack: they create only
`audit_<pid>_`-prefixed resources and tear them down in a `finally` block, and
they never call destructive endpoints (no notification test-sends, no report
runs, no discovery refresh).

## Adding a module

Drop `audits/<name>.py` defining `class Audit` with `NAME`, `TITLE`, and
`run(self)` using `self.api` / `self.rep`, ending with
`if __name__ == "__main__": sys.exit(run_audit(Audit))`. `run.py` auto-discovers it.
