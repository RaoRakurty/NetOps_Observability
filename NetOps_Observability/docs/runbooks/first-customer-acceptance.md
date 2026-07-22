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

## 4. Alerts exist AND leave the app (HARD GATE — automated)

**In-app alert visibility is not sufficient for customer operations. Critical
alerts must leave the app through an external notification channel before
first customer.** A projection failure at 02:00 must reach a phone/pager.

- [ ] Run the gate: `scripts/verify-critical-alert-channel.sh --send`
      (or `make first-customer-check SEND=1`). It FAILS unless:
      an external channel is enabled and fully configured; its min_severity
      admits criticals; the ntfy topic is NOT the watchdog's; the contract
      alerts are shipped; and a live test alert delivers.
- [ ] The delivered test alert was SEEN on the subscribed device (subscribe
      the on-call phone/desktop to the dedicated topic first — delivery to
      the server is not receipt).
- [ ] **Dedicated channel/topic**: product/platform alerting uses its OWN
      topic. The external stack-watchdog stays on its separate topic —
      watchdog independence is intentional (it must be able to report the
      stack's own death). Export `WATCHDOG_NTFY_TOPIC` in `.env` so the API
      refuses it server-side.
      Recommended setup: Admin → Notifications → ntfy, new dedicated topic,
      min severity critical — or seed at install via
      `FEATURE_NTFY_NOTIFICATIONS=true` + `NTFY_ALERT_TOPIC=...` in `.env`.
- [ ] The contract alerts parse to their real queries (CI:
      `go test ./alerts/ -run 'TestShippedRulesFileParses|TestParseRulesYAMLScalarStyles'`):
      `CHMemoryLimitExceeded`, `CHFailedQueriesRising`,
      `CorrVersionChurnUndamped`, `CorrCurrentProjectionFailing`,
      `CorrTenantWriteAmpOverBudget`.
- [ ] Metric inputs are scraped: query VictoriaMetrics for
      `corr_current_projection_write_failures_total` and
      `ClickHouseProfileEvents_QueryMemoryLimitExceeded` (1+ series each).

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
- [ ] `make first-customer-check SEND=1` green — the single command that
      chains release-gate-live + the §4 alert-delivery gate.

## 7. Projection reliability is demonstrably healthy

- [ ] `corr_current_projection_write_failures_total` is 0 (or explained).
- [ ] The reconciler drift count is 0: api log line
      `corr-current-reconcile` shows no repairs, or the drift SQL in
      `docs/runbooks/clickhouse-query-budget.md` §4 returns 0.

## 8. Backups exist, run on a schedule, and have been RESTORED once (F-59)

The 2026-07-21 audit found `GET _snapshot` = `{}` (no OpenSearch snapshot
repository had ever been registered), a "ClickHouse dump" that was
`SHOW CREATE TABLE` for 2 of 16 tables, every dump command ending in `|| true`
so a total failure still exited 0, and `scripts/backup.sh` in no crontab at
all. The dangerous part is not the absence of backups — it is that the system
reported having them. Each gate below tests the failure path, not the presence
of a script.

- [ ] **Snapshot repository is registered and healthy** (not just configured):
      `docker compose exec -T opensearch curl -s localhost:9200/_snapshot/netops-fs/_verify`
      returns nodes, not `repository_missing_exception`.
- [ ] **The daily snapshot policy is enabled and has actually run:**
      `curl -s 'localhost:9200/_cat/snapshots/netops-fs?v'` lists at least one
      snapshot in state `SUCCESS`. `PARTIAL` is a FAILED gate — it means some
      shards were not captured.
- [ ] **Backup cron installed** (daily, ahead of the ISM delete horizon):
      `30 3 * * * .../scripts/backup.sh /backups/netops-$(date +\%F).tar.zst >> .../backup.log 2>&1`
      Note `backup.sh` now EXITS NON-ZERO when any component fails, so cron
      MAILTO / the log is a real signal rather than decoration.
- [ ] **The last archive verifies:** `scripts/backup.sh --verify <file>` exits 0
      and its MANIFEST shows no `FAIL` lines.
- [ ] **A restore has been performed once on this deployment** — into a scratch
      copy, not production. `scripts/restore.sh` refuses an archive whose
      manifest records a failure; the OpenSearch half is restored from a
      SNAPSHOT (see the commands it prints), never from the copied data dir: a
      file-level copy of a live Lucene directory can be torn and may not open.
- [ ] **Off-host copy exists.** `data/opensearch-snapshots` and the tarballs
      live on the same disk as the stack until someone moves them. A backup
      that dies with the host is not a backup.
- [ ] **Replica posture recorded**: `OPENSEARCH_REPLICAS` in `.env` (0 is
      correct ONLY on a single-node appliance — see F-07; on a multi-node
      cluster 0 replicas plus a lost snapshot is unrecoverable loss).

Sign-off: date, deployment, profile chosen, alert channel chosen, drill
policy, backup schedule + last verified restore — one line each, into the
customer's deployment record.
