# First-customer acceptance checklist — correlation data reliability (#101)

Run this per customer deployment BEFORE go-live. Every item is a hard gate;
each has a one-command verification. (Broader product gates — security
defaults, licensing, backup drill — live in their own tracks; this checklist
covers the data-reliability contract.)

## 1. Retention is explicit and matches the contract

- [ ] `.env` has the intended `CORR_RETENTION_PROFILE` (installer flag
      `--retention-profile`; enterprise contracts: `extended` or explicit
      `CORR_RETENTION_*_DAYS` overrides, `0` = keep forever, documented in the
      deployment record).
- [ ] TTLs are live on all corr tables:
      `scripts/ch-retention-dry-run.sh` → every table shows a TTL, no
      "NO TTL configured" lines.

## 2. Cold tier leads the TTL horizon

- [ ] Cold-export cron installed (monthly beats the ≤1-partition-month TTL lag):
      `17 2 3 * * .../scripts/ch-cold-export.sh --quiet >> .../ch-cold-export.log 2>&1`
- [ ] First export ran: `data/clickhouse-cold/<table>/*.parquet` exist for
      every closed month (`ch-retention-dry-run.sh` coverage section).
- [ ] Restore path proven once on this deployment:
      `scripts/ch-cold-restore.sh --table corr_objects --tenant <a-tenant>`
      reports rows into `netops_restore` (then DROP it).

## 3. Read budgets are enforced and clean

- [ ] Budget-check cron installed (hourly):
      `42 * * * * .../scripts/ch-query-budget-check.sh --quiet >> .../ch-query-budget-check.log 2>&1`
- [ ] `scripts/ch-query-budget-check.sh` exits 0 under normal load
      (mem < 100 MiB, p95 < 1 s, zero memory kills).
- [ ] Workload profiles active: `system.settings_profiles` lists
      `hot_ui` + `background`; a Command Center poll in `system.query_log`
      shows `Settings['max_memory_usage'] = 1073741824`.

## 4. Alerts exist AND route somewhere a human sees

- [ ] The four contract alerts parse and load (CI:
      `go test ./alerts/ -run TestShippedRulesFileParses`):
      `CHQueryMemoryKilled`, `CorrVersionChurnUndamped`,
      `CorrCurrentProjectionFailing`, `CorrTenantWriteAmpOverBudget`.
- [ ] Metric inputs are scraped: query VictoriaMetrics for
      `corr_current_projection_write_failures_total` and
      `ClickHouseProfileEvents_QueryMemoryLimitExceeded` (1+ series each).
- [ ] **A push channel is enabled** (Admin → Notifications: ntfy/Slack/
      PagerDuty, min severity critical) and its test button delivered.
      In-app-only alerting is NOT acceptance-complete — a projection failure
      at 02:00 must reach a phone. Keep the external stack-watchdog on its
      OWN topic (it must be able to report the stack's death).

## 5. Chaos fixture policy is explicit

- [ ] `CORR_CHAOS_FIXTURES` is EMPTY unless a drill is officially scheduled
      for this deployment (policy: fixtures only for planned drills; an
      entry suppresses auto-ticketing for matching objects).
- [ ] If set: the drill is documented, Command Center shows the "planned
      drill" badge on its objects, and `/healthz` `chaos_fixtures` lists it.

## 6. Release gate passes on the deployed build

- [ ] `make release-gate` green (offline storm SLOs + SQL-shape guardrails).
- [ ] `make release-gate-live` green against the running stack (adds live
      budgets + retention preview). Re-run after ANY install/deploy/packaging
      change, not just code changes.

## 7. Projection reliability is demonstrably healthy

- [ ] `corr_current_projection_write_failures_total` is 0 (or explained).
- [ ] The reconciler drift count is 0: api log line
      `corr-current-reconcile` shows no repairs, or the drift SQL in
      `docs/runbooks/clickhouse-query-budget.md` §4 returns 0.

Sign-off: date, deployment, profile chosen, alert channel chosen, drill
policy — one line each, into the customer's deployment record.
