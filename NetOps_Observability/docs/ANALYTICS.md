# Analytics layer (ClickHouse)

> Reviewed against the code 2026-11-19. Schema of record:
> `deployment/docker/clickhouse/init.sql` (fresh installs) plus the
> converge-on-boot statements in `src/backend/internal/chschema` (existing
> installs pick up new tables when the api starts — no manual DDL). Retention
> knobs: `internal/chschema/ch_retention.go`; the full map is
> `docs/design/data-retention-map.md`.

ClickHouse is the OLAP store: raw flows and their per-interface roll-up, the
correlation engine's tables, and the path, application, wireless, experience,
cloud-cost and seasonal-baseline tables. It sits next to OpenSearch, which
holds the searchable flow documents; ClickHouse answers the aggregate
questions ("busiest links", "top talkers over a day").

## Tenant isolation

Every tenant-scoped table carries `tenant_id` and a row policy. A read sets the
caller's `tenant_scope` (`__all__` only for a cross-tenant principal or a
background job); the policy, not the caller's SQL, decides what is visible.
STRICT tables (for example `series_hourly`) show a row only to its own tenant.

## Key tables

| Table | What | Retention |
|---|---|---|
| `netops.flows` | One row per NetFlow / IPFIX / sFlow record, written by vector-router. Partitioned by `(tenant_id, day)`, ordered by `(ts, sampler_address, src_addr, dst_addr)`; carries ODID and flow start/end (tracker 401) | 7 days (`CH_FLOWS_RETENTION_DAYS`) |
| `netops.flow_iface_1m` | Per-interface one-minute roll-up of flows, written by the api's flowquery Roller (it reconciles the last 6 h). Read by `/api/flows/links` and `/api/flows/links/series` | follows flows |
| `netops.findings` | Legacy correlation findings (`/api/findings`) | see the retention map |
| `netops.corr_*` | The correlation engine's signals, objects and current state (`/api/correlations`) | see the retention map |
| `netops.series_hourly` | Hourly p10/p50/p90 of the baseline-eligible metric series, behind Iris's seasonal answers (`FEATURE_SEASONAL_ROLLUP`) | 63 days |

`SHOW TABLES FROM netops` lists the rest (paths, applications, wireless,
experience, cloud costs, …).

**No materialized view may read `netops.flows`.** The tenant row policy is
evaluated on every insert into an MV source, in the inserting connection's
context, where `tenant_scope` is unset — the insert errors and ingestion
breaks. Roll-ups are written by the api instead (`flow_iface_1m`, the service
roll-up), never by an MV (`init.sql`, the removed `flows_hourly`).

## API endpoints

The SPA never issues raw SQL: the api runs fixed, parameterised statements.

* Link views (`internal/flowquery`): `/api/flows/links`, `/api/flows/links/series`,
  `/api/flows/links/movers`, `/api/flows/apps`, `/api/flows/services`,
  `/api/flows/capacity` (capacity reads VictoriaMetrics interface counters, not
  ClickHouse), `/api/flows/sampling`.
* Older routes (`flows.go`): `/api/flows/top`, `topn`, `timeseries`, `by-proto`,
  `by-type`, `flags`, `geo`, `coverage`, `fanout`. They take `since` (a Go
  duration or seconds, 5 min – 30 days) and answer **400** for a malformed or
  out-of-range window rather than substituting a default (tracker 405).
* `/api/findings`.

## Querying directly

```
docker compose exec clickhouse clickhouse-client \
  --query "SELECT count() FROM netops.flows SETTINGS tenant_scope='__all__'"
```

Without `tenant_scope` the row policies show nothing. The self-monitoring
console (Stack → Self-Monitoring) has a provisioned ClickHouse datasource.

## Operational notes

* **Retention.** Daily partitions with `ttl_only_drop_parts = 1`: expiry drops
  whole parts. Change retention with the knobs in `ch_retention.go` (applied on
  api boot), not with a hand `ALTER TABLE … MODIFY TTL`.
* **Partitioning.** Filter on `ts` (and `tenant_id`) first.
* **Backups.** See `docs/runbooks/storage-and-volume-operations.md`.
