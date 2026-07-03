# DB & Storage Optimization — Best Practices, Applied State, and Decisions

Reconciles the owner's optimization research (2026-07-03: columnar engines,
codecs, rollups, approximation, isolation) with what is **actually applied and
validated** on the stack, what was assessed and deliberately deferred, and what
does not fit Correlix. Companion to the operational runbook
(`docs/runbooks/storage-and-volume-operations.md`) and TRACKER §G (#96).

Golden rule used throughout: **an optimization ships only when (a) it cannot
change query results or wire contracts, (b) it was verified against live
ingest after apply, and (c) it solves a measured problem — not a hypothetical
one.** Everything below is tagged accordingly.

---

## 1. Applied & validated (2026-07-03)

| Change | Value delivered | Break-safety analysis |
|---|---|---|
| CH `system.*` log bounding (config.d drop-in) | 5.84 GiB → 316 KiB disk; CH RSS 1.34 → 0.67 GiB | Lossless to the product: grep-verified **no code reads** `system.query_log/text_log/metric_log`; kept query_log 7d for slow-query debugging; re-enable path documented |
| CH `ttl_only_drop_parts=1` (6 TTL'd tables) | TTL expiry = free part drops, no rewrite merges | Retention semantics ±1 day max (daily partitions); query results unchanged |
| CH flow codecs (DoubleDelta ts / T64 counters / ZSTD ip-strings) | 361 → 291 MiB (−19%) on 16.6 M rows; less scan I/O | All codecs **lossless**; insert path (JSONEachRow) codec-transparent; ingest + queries verified post-`OPTIMIZE FINAL`; init.sql carries codecs for fresh installs |
| OpenSearch `index.codec: best_compression` (templates) | ~20-30% smaller new daily indices | Static setting on **new** indices only; existing dailies age out via ISM 14d; search behavior identical |
| VictoriaMetrics `--dedup.minScrapeInterval=30s` | Removes duplicate samples; smaller TSDB | **Cadence audit before apply**: every producer ≥30s (SNMP 30-60s, gNMI sample-interval 30s, STAMP_INTERVAL 30s, synthetics 60s, Prometheus scrape 30s) → drops only duplicates, never signal |
| Prometheus scrape/eval 15s→30s + cadvisor housekeeping 30s | Halves self-monitoring churn | Every alert rule window ≥5m → ≥10 samples/window; `for:` durations unaffected |
| Redpanda cluster retention defaults 72h/512MB + `redpanda-init` | Stalled consumer can't fill the disk | Bus is transit-only; CH/OS/VM are the durable stores; per-topic overrides still win; corr replay reads the CH archive, not the bus |
| Memory caps bound on all 20+ containers; redis `--maxmemory 96mb` **noeviction** | No un-capped container; clean errors instead of OOM-kills | Redis holds app state → eviction policies (allkeys-lru) were considered and **rejected** as semantics-changing |

**Post-change regression sweep:** syslog live, SNMP polling live (conntrack),
controller mock lane live, CH/VM/OS queries verified. One anomaly found and
root-caused as **pre-existing**: NetFlow/IPFIX ingest has been dry ~48 h —
zero packets reaching the host on 2055/4739 (sFlow on 6343 still arrives,
counter-only). Predates all changes; consistent with the lab NetFlow exporter
(c8000v cold-boot issue) or tgen being off. **Owner action: check tgen +
wan-r1/c8000v on 10.70.245.120.**

## 2. Assessed, deliberately NOT applied (and the trigger that revisits each)

| Practice (from research) | Why not now | Revisit when |
|---|---|---|
| Materialized views / rollups (`AggregatingMergeTree`) | Flows = 291 MiB; every dashboard query is sub-second. An MV re-evaluates the tenant row-policy question on every insert path — the removed `flows_hourly` MV was deleted for exactly that (#20) | p95 panel latency > ~2s, or flows > ~50 GB. Design must answer tenancy at write time |
| Skip indexes (bloom/ngram/minmax) | Primary key + partition pruning already serve every current query shape; skip indexes tax every insert/merge | A measured slow query filtering a non-key column (e.g. log free-text search moves from OS to CH) |
| Query result cache / uncompressed cache tuning | Dashboards hit VM (metrics) or small CH aggregates; no repeated-identical heavy queries measured | Repeated multi-second identical queries appear in query_log |
| `SAMPLE` / approximate everything | Product contract: RCA evidence must be exact. `uniqHLL12`-class functions are fine for *panels* — several already use approximations where display-only | New top-N panels over >100M-row windows |
| PREWHERE rewrites | ClickHouse moves filters to PREWHERE automatically in the versions we run; hand-tuning is noise | EXPLAIN shows a mis-planned heavy query |
| `async_insert` | All writers already batch (Vector batches; Go workers batch via jsonEachRow) | A new many-small-writers producer appears |
| LowCardinality on `src_addr`/`dst_addr` | Cardinality risk: internet-facing flow addresses can exceed the dictionary sweet spot and *degrade*; ZSTD(1) captured most of the win safely | Never for addresses; fine for genuinely enum-like new columns (already the schema convention) |
| Sharding / `Distributed` engine / replicas | Single-node CH at <1 GB data; a well-tuned single node goes very far vertically | See packaging design — CH growth options are a **deployment** question (§ analytics tiering in `docs/design/packaging-strategy.md`) |
| Gorilla codec on floats | flows has no float metric columns; VM already Gorilla-encodes its own storage | A float-heavy CH table appears |
| Storage tiering (`TTL ... TO VOLUME`, S3 cold) | No second storage tier exists on the lab host; biggest cost lever **at customer scale** | First deployment where retention × ingest exceeds local NVMe economics |

## 3. Research corrections (where the generic advice doesn't fit Correlix)

- **TimescaleDB / Druid comparisons — N/A.** The stack is CH + VM + OS by
  design; no migration is on the table. Kept in the research doc for context
  only.
- **"Add a `drop_after` column for TTL" — anti-pattern here.** Our TTLs are
  expression-based on the event time and partition-aligned (`toDateTime(ts) +
  INTERVAL n DAY` with daily partitions + `ttl_only_drop_parts`), which is
  strictly better: no extra column, expiry = whole-part drop.
- **"VM has no dedup/limited controls" — outdated.** VM supports
  `--dedup.minScrapeInterval` (now set) and `-retentionPeriod` (set, 30d).
- **Broadcast/co-located join guidance** applies to clustered CH; single-node
  Correlix joins are local by construction. The app-layer rule that matters
  more here: **denormalize into wide tables and never join across tenant
  scopes** (§3a) — which the schema already follows.
- **Bitnami subchart references** (packaging research): the Bitnami public
  catalog was gated/relocated in Aug 2025 — do not build on it; see the
  packaging design doc.

## 4. Standing method (how future optimizations get applied)

1. Measure first; name the number you expect to move.
2. Prove result-invariance (lossless codec / setting / cadence audit).
3. Apply live behind verification (ingest still flowing, queries identical).
4. Mirror in init.sql / compose so **fresh installs equal the tuned stack**.
5. Record in TRACKER §G with before/after; preflight must PASS.
