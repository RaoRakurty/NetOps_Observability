# P2 — ClickHouse s06 memory peak (14:35–14:50, 2026-08-29) — decomposition

CH 24.8.14.39, container `netops-clickhouse-1`. All queries read-only; nothing changed.

## 0. Signals that exist (and the two that do not)

| Signal | Status |
|---|---|
| `system.metric_log` | present, 1 s resolution, 997 columns, 2026-08-28 00:00 → now |
| `system.part_log` | present — **`netops` only. Zero rows for `database='system'`, ever.** |
| `system.query_log`, `system.errors`, **`system.error_log`** | present (error_log from 2026-08-16) |
| `system.asynchronous_metric_log` | **DOES NOT EXIST** — no historical jemalloc.*, MemoryResident, MarkCacheBytes, PrimaryKeyBytes, TotalParts* |
| `system.trace_log` | **DOES NOT EXIST** — memory profiler output is not persisted. `memory_profiler_step=4 MiB` and `total_memory_profiler_step=4 MiB` are set but `*_sample_probability=0` and there is no sink. Memory profiling is effectively OFF. |
| `CurrentMetric_MemoryTrackingInBackgroundProcessingPool` | not a column in 24.8 (removed upstream). Only `MergesMutationsMemoryTracking`. |

Present and used below: `CurrentMetric_{MemoryTracking, MergesMutationsMemoryTracking, Merge, PartMutation, BackgroundMergesAndMutationsPoolTask, BackgroundCommonPoolTask, BackgroundSchedulePoolTask, Query, QueryThread, HTTPConnection, TCPConnection, MMappedFileBytes, PartsActive, PartsOutdated, PartsTemporary, FilesystemCacheSize}`, `ProfileEvent_{Merge, MergedRows, MergedColumns, MergedUncompressedBytes, MergeTotalMilliseconds, LoadedMarksMemoryBytes, MemoryAllocatorPurge, QueryMemoryLimitExceeded}`.

## 1. What `MemoryTracking` actually is — this reframes everything

Live, right now, on the idle-ish server:

```
system.metrics   MemoryTracking  = 692.12 MiB
async_metrics    MemoryResident  = 692.10 MiB      <-- identical to 2 dp
```

`CurrentMetric_MemoryTracking` in 24.8 is the **global tracker hard-set to process RSS once per second** by `AsynchronousMetrics` (`MemoryTracker::setRSS`). It is *not* the sum of per-query/per-merge allocations. Consequences:

* It can and does exceed the sum of its children, and a child tracker can read above it. `MergesMutationsMemoryTracking > MemoryTracking` in **34 of hour-14's 3,600 samples** and **50 of hour-11's** (11:40–11:45: merges tracker 4,084 MiB while total was 1,347 MiB, for 48 consecutive seconds). The two are not commensurable.
* **The harness's "drop samples where merge > total" filter is built on a false premise** and silently discards the most diagnostic samples.
* `part_log.peak_memory_usage` (tracked bytes for one merge) can never sum to `MemoryTracking` (RSS). The "contradiction" in the brief is not a contradiction.

## 2. Decomposition of the peak

The peak is **not a plateau — it is 13 one-to-three-second RSS transients.** Per-minute max vs median, 14:35–14:50: max 3,265–4,406 MiB, **median 1.28–1.40 GiB**. s05's median over 12:10–12:40 was 1.25–1.36 GiB. *The baseline is identical in both runs.* Only the transients differ.

Every accountable component, measured over 14:10–15:00:

| Component | Measured max | Evidence |
|---|---|---|
| Sum of **all in-flight query memory**, per second | **826.2 MiB** (14:49:19, 61 concurrent queries) | query_log start/end expansion |
| Largest single query | 546.6 MiB (`WITH picked AS…`, 2 calls, `log_comment='worker:cross-tenant'`) | query_log |
| Largest single **merge** (`peak_memory_usage`) | **169.6 MiB** (corr_objects, 9,518 rows, 236 MiB read) | part_log |
| Concurrent merge tasks | ≤ 7 (pool 6×2 = 12) | `BackgroundMergesAndMutationsPoolTask` |
| Failed / aborted merges | **zero** (`part_log WHERE error!=0` → 0 rows) | part_log |
| Mutations | zero (`PartMutation`=0, no MutatePart, `system.mutations` empty) | |
| `MMappedFileBytes` | flat 487 MiB all window | metric_log |
| Mark cache / uncompressed cache | 3.6 MiB / 0 B | async_metrics |

**Queries + merges + mmap ≈ 1.5 GiB. The peak is 4.41 GiB. ~2.9 GiB is unattributed to any query or any `netops` merge.**

## 3. Where the missing ~2.4–2.9 GiB goes: `system.metric_log` merges

`system.metric_log` has **exactly 997 columns**. `ProfileEvent_MergedColumns` reads exactly `997` on a ~38–46 s cadence all day — that is the metric_log merge finishing.

* **10 of the 13 seconds with `MemoryTracking > 3 GiB` land 1–4 s *before* a 997-column merge completion.** (14:37:20/22, 14:38:07, 14:38:52, 14:40:27/28, 14:42:46, 14:43:32, **14:46:30 = the 4,406 MiB peak**, 14:54:15.) 36 of the 81 `MergesMutationsMemoryTracking > 3 GiB` samples likewise.
* Second-by-second at the peak: `mm` = 96 → 1,726 → 3,410 → 3,895 MiB, then **0**, with the 997-column merge completing in the very second it drops. `ProfileEvent_MemoryAllocatorPurge`=2 and `QueryMemoryLimitExceeded`=1 fire at 14:46:30.
* **This is invisible in `part_log` because part_log has never logged a single `database='system'` row.** That, precisely, is why part_log "contradicts" the metric.
* All 17 MEMORY_LIMIT_EXCEEDED (14:36:34 → 14:54:16, from `system.error_log`) sit on the same ~46 s cadence.

### The mechanism, and why s05 was clean

metric_log is 1,015 B/row uncompressed. Two thresholds bracket a danger band:

* `min_bytes_for_wide_part = 10 MiB` → output becomes **Wide** (997 separate column streams) above ~10,330 rows.
* `vertical_merge_algorithm_min_rows_to_activate = 131,072` → below that the merge is **Horizontal**: all 997 streams open simultaneously.

Between ~10.3k and 131k rows a metric_log merge is Wide **and** Horizontal. Buffer arithmetic with the stock global settings (`max_compress_block_size=1 MiB`, `min_compress_block_size=64 KiB`, `max_read_buffer_size=1 MiB`):

```
writer   997 cols x (1 MiB + 64 KiB)                 ~= 1.06 GiB
readers  997 cols x 1 MiB x N source parts           ~= 0.97 GiB per source part
total with 2-3 source parts                          ~= 3.0 - 4.1 GiB   (observed 3.4 - 3.9)
```

Confirmed in `system.parts`: the active level-258 part is **Wide, 13,693 rows, 13.31 MiB uncompressed** — squarely in the band. And the row counts at the spike completions (`MergedRows` 0–11,004) confirm small merges, not big ones.

Why s05 (11:55–13:10) never saw it: its metric_log merges were either **below** the band (14:15–14:21, `MergedRows` 6.5k–9.5k → Compact part → one stream → `mm` ≈ 0) or **above** it (12:00–13:00, `MergedRows` 200k–500k → Vertical algorithm → one column at a time → `mm` 21–248 MiB). s06's landed inside it. **This is an artefact of how much metric_log had accumulated since the 11:33 server start — not of the 2.5K workload.**

## 4. The killed repartition statement — refuted as a cause

`query_id b63fcc83-7e5b-4688-a5b8-3607d24f40db`:

```
QueryStart  14:19:09.903   QueryFinish 14:19:23.270   duration 13,366 ms
memory_usage 69 MiB   read 19,086,599 rows / 4,266.8 MiB   written 121,495 rows
exception_code 0
```

* It **was not killed** — the client gave up at 12 s, the server finished successfully 1.4 s later. There is no KILL in query_log and no leaked tracker: the statement had already terminated. Nothing survives a completed query's tracker.
* **It used 69 MiB.** Streaming worked exactly as intended. It cannot account for any part of the peak, and the 14:20–14:25 "plateau" is in fact two isolated 1-second spikes (14:24:16, 14:26:46) that occur **1–7 minutes after it finished.**
* It did read the **whole** monthly partition: `PARTITION BY (tenant_id, toYYYYMM(created_at))` vs `WHERE … toYYYYMMDD(created_at)=20260821` — **not prunable**, 19.1 M rows / 4.27 GiB uncompressed off disk in 13 s. Real cost = page-cache eviction and I/O, not memory.

## 5. Ranked verdict on the extra ~2.4 GiB vs s05

1. **`system.metric_log` Wide+Horizontal 997-column merges — MOST LIKELY (high confidence).** *For:* exact 997 column-count match; 10/13 total-memory spikes and 36/81 merge-tracker spikes within 1–4 s of a completion; `mm` ramps and collapses exactly on merge completion; part_log's blindness to `database='system'` explains the whole "contradiction"; buffer arithmetic reproduces 3.0–4.1 GiB; the band argument explains why s05 and 14:15–14:21 were clean. *Against:* not directly measurable — part_log excludes it and trace_log is absent, so the attribution is by correlation and arithmetic, not by a profiler sample. It **cannot be closed from the logs alone**; §7 says how to close it.
2. **jemalloc dirty-page retention amplifying transients — CONTRIBUTING (medium).** *For:* `MemoryTracking` is RSS, so freed-but-unreturned arena pages count; `MemoryAllocatorPurge` fires exactly at the limit breach; `jemalloc.retained` is 21.65 GiB now. *Against:* no historical jemalloc series exists (no asynchronous_metric_log), so the magnitude is unquantifiable.
3. **The 3 unexplained spikes at 14:24:16 / 14:26:46 / 14:27:31 — UNSETTLED.** No query was in flight (`CurrentMetric_Query`=0, in-flight query memory ~0); nearest 997-merge is 9–22 s away. They coincide with `PartsOutdated` exploding 166 → 14,553 after the `corr_edges__daily` backfill and the api-boot DDL wave. Plausibly outdated-part object churn; **cannot be settled from the logs.**
4. **The api/reconciler query mix — REFUTED.** s05's window contained *larger* queries (894 MiB, 610 MiB, 526 MiB) than s06's (547 MiB max) and peaked at 1,950 MiB. Peak in-flight total never exceeded 826 MiB.
5. **The repartition INSERT…SELECT — REFUTED.** 69 MiB, completed, see §4.
6. **`hypotheses String CODEC(ZSTD(3))` (14:19) — REFUTED as the driver.** corr_objects merges are the largest `netops` merges but cap at 169.6 MiB; their read_bytes/row is unchanged across the boundary.
7. **`netops` merges generally — REFUTED.** ~5,700 merges/5 min on *both* runs, max 169.6 MiB, zero failures, ≤7 concurrent.

**Customer-visible fact:** 17 MEMORY_LIMIT_EXCEEDED, 14:36:34–14:54:16. Only **2** of them surfaced in `query_log` (two `INSERT INTO netops.findings`, 4.05 and 4.16 GiB against the 4.00 GiB cap). The other 15 were raised in background threads and are recorded **only** in `system.error_log` / `system.errors`. The victims are tiny inserts because the overcommit tracker picks whoever allocates next after RSS crosses the cap — they are collateral, not cause.

## 6. Recommendations — fix the cause first

**(a) Bound `system.metric_log`, in `deployment/docker/clickhouse/`.** This is the highest-leverage change and it costs nothing operationally. Force Compact parts so a merge opens one stream instead of 997:

```xml
<metric_log>
  <database>system</database><table>metric_log</table>
  <flush_interval_milliseconds>7500</flush_interval_milliseconds>
  <collect_interval_milliseconds>1000</collect_interval_milliseconds>   <!-- keep 1 s resolution -->
  <engine>ENGINE = MergeTree PARTITION BY toYYYYMM(event_date) ORDER BY (event_time)
          TTL event_date + INTERVAL 7 DAY DELETE
          SETTINGS min_bytes_for_wide_part = '1G',
                   vertical_merge_algorithm_min_rows_to_activate = 1024,
                   max_compress_block_size = 65536</engine>
</metric_log>
```
Caveat: changing `<engine>` makes CH rename the existing table to `metric_log_1` on restart and create a fresh one — history is preserved but moves. Deploy at a run boundary, never mid-run. If a rename is unacceptable, the one-line variant is `vertical_merge_algorithm_min_rows_to_activate = 1024` alone (forces vertical merges, one column at a time) — smaller win, no rename. Same treatment applies to any other wide log table if one is added.

**(b) Per-query `max_memory_usage`.** Currently 2 GiB (default profile) — the api/reconciler never exceeded 547 MiB, so tighten to **1 GiB** for the `netops` user profile as a blast-radius guard. **Be clear this would not have prevented these errors**: the limit that fired was `max_server_memory_usage` (total), not a per-query one. Per-query caps buy containment, not immunity.

**(c) The repartition copy.** Memory was never the problem (69 MiB) — prunability is. `PARTITION BY (tenant_id, toYYYYMM(created_at))` means **no day filter can prune**; measured 19.1 M rows read for 121 k written. Options: (i) copy a whole month per statement (`WHERE toYYYYMM(created_at)=202608`) and let the daily target partition on write — same I/O, one pass instead of 31; (ii) `INSERT INTO … SELECT … FROM netops.corr_edges` restricted with `IN PARTITION`-style pruning only if the source is repartitioned daily first. Streaming settings to set explicitly, because the current pair is inconsistent: they set `max_insert_block_size=100000` but `min_insert_block_size_rows` is still the default **1,048,449** and `min_insert_block_size_bytes` **256 MiB** — the squashing transform will re-buffer up to 1 M rows regardless. Set all three together (`max_block_size=65536`, `max_insert_block_size=100000`, `min_insert_block_size_rows=100000`, `min_insert_block_size_bytes=0`) plus `max_memory_usage=536870912` and a client timeout above 20 s (the server needed 13.4 s; the client quit at 12 s and produced a false "hung/killed" reading in the incident record).

**(d) Turn the profiler on for the next run** so this is measured, not inferred. Both sinks are missing today:
```xml
<trace_log><database>system</database><table>trace_log</table>
  <flush_interval_milliseconds>7500</flush_interval_milliseconds></trace_log>
<asynchronous_metric_log><database>system</database><table>asynchronous_metric_log</table>
  <flush_interval_milliseconds>7500</flush_interval_milliseconds></asynchronous_metric_log>
```
plus `total_memory_tracker_sample_probability = 0.01` (server) and `memory_profiler_sample_probability = 0.01` (profile), keeping `total_memory_profiler_step = 4194304`. Then `SELECT arrayStringConcat(arrayMap(x -> demangle(addressToSymbol(x)), trace), '\n'), sum(size) FROM system.trace_log WHERE trace_type='MemorySample' GROUP BY 1` names the allocator directly and closes candidate 1 and candidate 3 in one run. Cost: trace_log volume; enable for the diagnostic run, not permanently.

**(e) Harness clause — yes, read the `MEMORY_LIMIT_EXCEEDED` delta.** Two changes:
* **Add** `system.error_log` (code 241) summed over the run window, or a before/after delta of `system.errors`. Proof it is necessary: `query_log` reported **2** of the **17**; error_log reported all 17. The error count is the customer-visible fact, `MemoryTracking` is a proxy for it.
* **Remove** the "drop samples where merge > total" filter and stop asserting on `MergesMutationsMemoryTracking` as a fraction of `MemoryTracking`. §1 shows the two are measured differently (tracker sum vs RSS snapshot); the filter discards 34–50 samples per hour, all of them diagnostic. If a merge-memory assertion is wanted, assert on `part_log` `peak_memory_usage` — but note it will never see `system`-database merges, so pair it with the error-count clause.
* Consider asserting on **p99 rather than max** of `MemoryTracking`: the s05/s06 medians are identical (1.25–1.40 GiB); only 13 one-second RSS transients separate a "clean" run from a "failed" one, and a max-based gate cannot tell a sustained regression from a transient.
