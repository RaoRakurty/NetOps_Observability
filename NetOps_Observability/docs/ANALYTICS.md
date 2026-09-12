# Analytics layer (ClickHouse)

ClickHouse is the OLAP store for flow analytics, long-term trend
analysis, capacity planning, and correlation-engine findings. It sits
next to OpenSearch — they overlap on flow data on purpose: OpenSearch
is the right tool for "show me flows touching 10.0.0.5 in the last
hour" (ad-hoc, hit-by-hit), ClickHouse is the right tool for "what's
the daily aggregate egress per BGP AS over the last quarter".

## Schema

`deployment/docker/clickhouse/init.sql` creates three tables on first
container start.

### `netops.flows` — raw flow stream

One row per NetFlow / IPFIX / sFlow record. Partitioned by day, ordered
by `(ts, sampler_address, src_addr, dst_addr)`, TTL 90 days.

```sql
-- Top 10 src/dst pairs by bytes in the last hour
SELECT src_addr, dst_addr,
       sum(bytes * sampling_rate) AS bytes_total
  FROM netops.flows
 WHERE ts >= now() - INTERVAL 1 HOUR
 GROUP BY src_addr, dst_addr
 ORDER BY bytes_total DESC
 LIMIT 10;
```

### `netops.flows_hourly` — materialized rollup

Populated automatically by ClickHouse as new rows land in `flows`.
Powers the "Top Talkers (last 24h)" dashboard widget without scanning
the raw table.

### `netops.findings` — correlation engine output

One row per anomaly / correlation / RCA finding emitted by the Python
service. The Findings tab in the dashboard reads from here.

## API endpoints

The Go API surfaces a small set of fixed queries so the SPA never
issues raw SQL. Add new endpoints in `src/backend/flows.go`.

| Endpoint                       | Returns                                     |
|--------------------------------|---------------------------------------------|
| `/api/flows/top`               | Top talker pairs (src, dst, bytes, packets) |
| `/api/flows/by-proto`          | Bytes/packets/flows grouped by IP proto     |
| `/api/flows/timeseries`        | Time-bucketed bytes/packets                 |
| `/api/findings`                | Correlation findings (filterable severity)  |

All accept `?since=1h` / `?since=24h` / `?limit=N`.

## Querying directly

ClickHouse's HTTP interface is reachable from inside the network:

```
docker compose exec clickhouse clickhouse-client --query "SELECT count() FROM netops.flows"
docker compose exec clickhouse clickhouse-client --query "SHOW TABLES FROM netops"
```

The self-monitoring add-on's console (Stack → Self-Monitoring in the UI)
has a provisioned ClickHouse datasource — `Explore` → pick ClickHouse →
write SQL.

## Operational notes

* **TTL.** The TTL clauses delete rows older than 90 days automatically.
  Adjust per data class (`ALTER TABLE netops.flows MODIFY TTL ts +
  INTERVAL 180 DAY`) if you need longer retention.
* **Partitioning.** Daily partitions on `flows` mean a single partition
  is the unit of TTL drop and the smallest unit of efficient query
  filter. Don't `WHERE` on `bytes` if you can `WHERE` on `ts`.
* **Backups.** Use `clickhouse-backup` (third-party but well-supported)
  or just snapshot `data/clickhouse/` while the service is stopped.
