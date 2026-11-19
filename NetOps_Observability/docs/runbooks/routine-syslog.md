# Routine management-session syslog: split, retention and roll-ups

Tracker 410, owner decision 2026-11-19.

## What it is

On a managed estate most stored syslog (92 % on the lab, 2026-11-12) is
*routine management sessions*: the SD-WAN controller and the monitoring
platform opening, using and closing a NETCONF or SNMP session per request. The
records are kept, but not for as long as the rest of syslog:

| Family | Holds | Kept for |
|---|---|---|
| `netops-syslog-<tenant>-<date>` | every other device syslog record | the log window (`OPENSEARCH_LOG_RETENTION_DAYS`, 14 d by default) |
| `netops-syslogroutine-<tenant>-<date>` | routine originals, same fields as syslog | `OPENSEARCH_ROUTINE_SYSLOG_RETENTION_HOURS` (96 h by default, so every record lives at least 72 h) |
| `netops-syslogrollup-<tenant>-<date>` | one document per tenant, device, source, user and minute: `first_seen`, `last_seen`, `occurrence_count` and the identity | the log window |

So the raw lines are readable for about three days, and their counts and
usernames (D2, D7) for the full window.

## How a record is classified

- **At write time** the router (`deployment/docker/vector-router/vector.yaml`,
  `syslog_store_route.routine`) applies the address-free rules of
  `internal/logroutine`: SNMP polls and in-session steps (NETCONF RPCs,
  session-group lines, SSH session open/close), inside `management_audit`,
  never with a failure word. `SYSLOG_ROUTINE_SPLIT=off` sends everything to the
  main family.
- **At read time** the Logs page, export, the severity tiles and Iris hide the
  full routine class (including the address rules) over both families, and
  count it. The read rule is the only one that decides what is hidden; the
  write rule only decides retention.

## The roll-up job

The api's `routine-syslog-rollup` worker folds closed minutes of
`netops-syslogroutine-*` into `netops-syslogrollup-*` every minute, re-rolling
the last 15 minutes for late arrivals, and recounts each closed hour of the last
48 h once an hour, re-rolling any hour whose roll-up sum differs from its
originals. Each roll-up document's id is the hash of its key, so a re-run
upserts. `ROUTINE_SYSLOG_ROLLUP=off` stops it (a D2 gap: originals then expire
with no count kept).

Metrics: `netops_routine_rollup_runs_total{result}`,
`netops_routine_rollup_documents_written_total`,
`netops_routine_rollup_tenant_mismatch_records_total`,
`netops_routine_rollup_deferrals_total`, `netops_routine_rollup_mismatch_hours`,
`netops_routine_rollup_last_success_timestamp_seconds`.

## RoutineSyslogRollupStale

The roll-up has not completed a tick for over an hour, or every tick in the
last 30 minutes failed. Nothing is lost yet: the originals live at least 72 h
and the job repairs any gap shorter than that by itself. After about 48 h the
oldest originals start expiring uncounted.

1. Read the api log for `routine-syslog roll-up`.
2. A 403 on `netops-syslogrollup-*` means the security configuration was not
   re-applied after the upgrade: re-run the `opensearch-security-init` one-shot
   (securityadmin).
3. OpenSearch unavailable or read-only (flood stage) stops the job with every
   other writer: see `storage-and-volume-operations.md`.
4. `netops_routine_rollup_tenant_mismatch_records_total` rising means routine
   originals whose `tenant_id` disagrees with the index they sit in. They are
   never rolled into the wrong tenant's roll-ups; find the sender and its
   ownership in the inventory.

## Deploy order

The router's split needs the templates, the ISM policy and the writer role in
the cluster first: run `opensearch-init` and `opensearch-security-init` (both
run by `scripts/deploy.sh`/`deploy-qualify.sh`) before the new vector-router.
`scripts/bootstrap-opensearch.sh --verify` reports an uncovered sink lane.
