# memflat re-score — p2-s05-08291138

Re-scored 2026-08-29T13:24:04Z by scale-miniladder.py --rescore-memflat.
READ-ONLY: the run's own report files are untouched; this is what the
corrected clauses (2026-08-29) say about the evidence that run left.

* original memflat verdict: FAIL — netops-correlation-3: LEAK SLOPE (docker_stats) 470 -> 647 MiB (x1.37 > x1.3) after input stopped; clickhouse: peak MERGE memory 4084 MiB is 99.7% of the 4096 MiB server cap (> 50.0%) — background merges alone can starve the query/insert path | clickhouse anon 881 MiB (x0.811 vs anchor); peak MemoryTracking 2952 MiB = 72.1% of cap 4096 MiB (merges 4084 MiB = 99.7%); MaxPartCountForPartition 15 (preflight 15, envelope 23, delay at 1000)
* re-scored verdict: **FAIL/UNKNOWN**

## clause (2) — ClickHouse's own memory accounting

* window: `2026-08-29 11:39:00` -> `2026-08-29 12:37:00` (ClickHouse's clock)
* cap: 4096 MiB (server_settings.max_server_memory_usage)
* samples: 3481 in the window, 50 rejected as physically impossible (merge memory above the tracked total)
* peak MemoryTracking: **1950 MiB** = 47.6% of cap (limit 85.0%)
* peak MERGE memory: **421 MiB** = 10.3% of cap (limit 50.0%)
* what the UNFILTERED `max()` would have printed — the defect: MemoryTracking 2952 MiB, merges 4084 MiB

clause (2): PASS

## clause (1) — correlation, anchored at corr_engine_pending == 0

* source: none

correlation: UNKNOWN: this run predates the per-replica {pending, rss} curve (added 2026-08-29), so the first sample at which each replica reported corr_engine_pending == 0 — and its RSS there — was never recorded. The input-stop anchor in the run's own report cannot separate a leak from a backlog drain, which is exactly why it is not reused here. Re-run to get a judged correlation slope
