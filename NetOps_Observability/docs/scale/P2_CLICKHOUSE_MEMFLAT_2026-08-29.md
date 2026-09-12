# P2 — ClickHouse `memflat` failure, run `p2-s04b-08290858`: investigation + design

**Verdict up front.** The gate failed on a number that is **not ClickHouse memory**, and the
underlying cost it half-detected is **not new in P2 step 4**. Two separate findings:

1. `docker stats` MemUsage = cgroup `memory.current − inactive_file` — **page cache + dentry slab
   included**. Measured now: `anon` **984 MiB**, `active_file` **1,516 MiB**, `slab_reclaimable`
   **621 MiB** → docker stats **3.14 GiB** vs ClickHouse's own `MemoryResident` **994 MiB**.
   **~68 % of what memflat calls ClickHouse "RSS" is reclaimable kernel cache.**
2. The real, pre-existing cost is **merge write amplification of ~241×** on `corr_objects`,
   driven by one-row inserts of a **26.9 KiB/row** row into a single month partition.

## 1. Is it merges, a cache, or a leak?  → merges (and page cache), no leak

`system.part_log` is disabled (`system-logs.xml`), so this is reconstructed from
`system.metric_log` + `system.query_log`. Window totals:

| leg (persist mode) | window | insert stmts | merges | merged rows | merged uncompressed | merge CPU | OS write | peak `MemoryTracking` | peak `MergesMutationsMemoryTracking` | peak PartsActive / Outdated |
|---|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| `s012d` 04:14–05:50 **inline** | 96 m | 190,249 | **87,818** | 1,467 M | **563.1 GiB** | 4,921 s | 68.4 GiB | 4,222 MiB | **3,976 MiB** | 641 / 32,422 |
| `s04` 07:00–08:10 **async** | 70 m | 172,370 | 60,417 | 788 M | 333.0 GiB | 3,755 s | 49.0 GiB | 4,626 MiB | 3,964 MiB | 210 / 37,207 |
| `s04b` 08:58–10:15 **async** | 75 m | 179,149 | **69,201** | 825 M | **337.6 GiB** | 3,874 s | 50.4 GiB | **4,566 MiB** | **3,978 MiB** | 927 / 36,338 |

- **Not a leak.** `MemoryTracking` returns to 1,056 MiB by 10:10 and is 994 MiB now; jemalloc
  `allocated` 877 MiB, `retained` 22.3 GiB (returned to the OS, not resident).
- **Not a cache.** `MarkCacheBytes` 2.01 MiB, `UncompressedCacheBytes` 0 B — though both
  *ceilings* are wrong (5.37 GiB / 8.59 GiB against a 5.20 GiB cgroup; see §3b).
- **It is merge work.** Level distribution of active parts shows the pathology directly:
  `corr_objects` has a **1.86 GiB part at level 1,568**; `corr_current` a 37.8 MiB part at level
  **33,082**; `corr_edges` 29.8 MiB at **11,848**. Level = number of merges that part has been
  through: the trickle of tiny parts is being folded into the accumulated part over and over.
- **Row shape is the multiplier.** `corr_objects` = **26,878 B/row uncompressed** (1,923 B on
  disk); the single `hypotheses` String column is **45.01 GiB of the table's 48.01 GiB (94 %)** —
  every re-merge of the big part rewrites it.
- **Amplification.** Uncompressed bytes *inserted* in the s04b window ≈ **1.40 GiB**
  (corr_objects 1.20 GiB + edges 71 MiB + evidence 86 MiB + archive 30 MiB + current 29 MiB)
  against **337.6 GiB merged** → **≈ 241× merge write amplification**.
- **The real risk the gate should have caught:** peak `MemoryTracking` **4,566 MiB = 95.2 % of
  `max_server_memory_usage` (5,026,244,198 B = 4,794 MiB)**, and merges alone peaked at
  **3,978 MiB**. `merges_mutations_memory_usage_soft_limit`=0 with ratio 0.5 derives the limit
  from **OSMemoryTotal 15.61 GiB → ~7.8 GiB**, i.e. it is *inert* inside a 5.2 GiB cgroup.
- `system.errors`: `MEMORY_LIMIT_EXCEEDED` ×30 (last 08:50, a 2.01 GiB *query* limit, pre-run
  cleanup), `TIMEOUT_EXCEEDED` ×164, `NETWORK_ERROR` ×652. No insert-side `TOO_MANY_PARTS`
  (`parts_to_delay_insert`=1000, `parts_to_throw_insert`=3000; peak PartsActive 927).

## 2. Did the async Evidence plane change the part count? → **No. Only the timing.**

Insert statements per table are within ±13 % across the three legs and the shape is unchanged:

| table | `s012d` inline | `s04` async | `s04b` async | rows/insert (s04b) |
|---|--:|--:|--:|--:|
| `corr_objects` | 53,040 | 42,163 | 47,899 | **1.0** |
| `corr_current` | 53,036 | 42,163 | 47,894 | **1.0** |
| `corr_signals_archive` | 25,843 | 23,977 | 23,513 | **4.8** |
| `corr_edges` | 17,491 | 24,202 | 20,094 | 16.9 |
| `corr_evidence` | 17,490 | 24,200 | 20,094 | 16.9 |
| `corr_signals` (batched today) | 2,511 | 713 | 2,593 | 17.2 |

The async leg did **less** merge work than the inline leg (69,201 vs 87,818 merges; 338 vs
563 GiB) and hit the **same** peak merge memory (3,978 vs 3,976 MiB). P2 step 4 moved *when* the
Evidence writes are issued, not how many parts they create.

**Why s04b failed and s04 passed on identical code**: `s04` sampled warm **4,314 MiB** → end
**3,281** = ×0.761 **PASS**; `s04b` warm **2,246** → end **3,854** = ×1.72 **FAIL**. s04b's warm
sample landed right after the previous run's cleanup dropped the page cache. The verdict is
decided by where the page cache happens to sit at the warm sample.

## 3. Recommendations

### (a) Evidence-plane write batching — cross-version, per table

Today `_emit_child_rows` batches *within* one object version only (`CORR_ROW_BATCH_ROWS`), so a
version with 7.5 edges is still one insert. Add a cross-version accumulator in the Evidence
consumer (`_write_evidence` → per-table buffer, one flusher task), flushing on
**200 items OR 8 MiB of row bytes OR 2,000 ms**, whichever first.

At the measured drain rate (**45,356 versions / ~3,900 s ≈ 11.6 versions/s**) the 2 s clause
binds first → ~23 versions per flush:

| table | inserts s04b | after batching | rows/insert | bytes/insert |
|---|--:|--:|--:|--:|
| `corr_edges` | 20,094 | **~1,970** | ~172 | ~36 KiB |
| `corr_evidence` | 20,094 | **~1,970** | ~172 | ~43 KiB |
| `corr_signals_archive` | 23,513 | **~1,970** | ~58 | ~15 KiB |
| Evidence-plane subtotal | 63,701 | **~5,900** | — | **≈ 11× fewer parts** |

**Decision plane is the bigger prize but costs TTUR.** `corr_objects` + `corr_current` are
**95,793 of the 162,087 corr_* inserts (59 %)** and `corr_objects` alone is **86 % of the
uncompressed bytes** — it is where essentially all the merge cost lives. They are written
*synchronously* in `_persist_snapshot` before the Evidence item is queued, so batching them
delays the operator-visible verdict. Recommended split:
- `corr_objects` (history, nothing reads it on the TTUR path): batch at **200 / 8 MiB / 1,000 ms**
  → ~12 rows/insert, **47,899 → ~3,900 inserts (12×)**, ~310 KiB/insert.
- `corr_current` (Command Center reads it): keep a tight **250 ms** flush → ~3 rows/insert,
  **47,894 → ~16,000 (3×)**; raise to 1 s only if the TTUR budget shows headroom.
- Combined: **162,087 → ~26,000 inserts, ≈ 6× fewer level-0 parts**; Evidence tables 11×,
  `corr_objects` 12×.

**Dedup tokens.** `insert_deduplication_token` is **per block**, so a batch needs exactly one:
`token = "batch:" + sha256("|".join(member_tokens))[:32]`, members in flush order. That preserves
the guarantee that actually exists today — `ch_insert`'s in-process bounded retry resends the
*same* list, hence the same token, hence ClickHouse drops the duplicate. It does not preserve
cross-restart replay dedup (batch composition depends on drain timing), but the async plane
already gave that up: a failed Evidence item is "lost and loud", not replayed. The Decision
tables batch by the same construction — `tok` is content-derived
(`obj:<cid>:v<n>:<state>:<hash16>`), so the batch hash is deterministic for a member set.
**Do not use `async_insert` for dedup**: on 24.8 non-replicated MergeTree the token is not
honoured on the async path, silently dropping the idempotency `ch_insert` relies on.
`non_replicated_deduplication_window`=1000/partition covers ~1.6 min today, ~10 min batched.

### (b) ClickHouse-side settings (no app change; do these first, they are cheap)

| setting | now | recommend | why |
|---|--:|--:|---|
| `max_bytes_to_merge_at_max_space_in_pool` (per-table, `corr_objects`) | 150 GB | **2 GiB** | Caps the accumulated part so the 1.86 GiB / level-1,568 part stops being a merge candidate. This alone should remove most of the 337 GiB. Yields ~24 parts/partition — far under `parts_to_delay_insert`=1000. |
| same, `corr_signals_archive` / `corr_edges` / `corr_evidence` / `corr_current` | 150 GB | **1 GiB** | Same pathology at levels 7,524 / 11,848 / 10,825 / 33,082. |
| `background_pool_size` | 16 (×2 ratio = **32 concurrent merges**) | **6** (×2 = 12) | 4-core box; 32 concurrent merges is what lets `MergesMutationsMemoryTracking` reach 3,978 MiB. |
| `merges_mutations_memory_usage_soft_limit` | 0 → derived from **host** 15.61 GiB ≈ 7.8 GiB | **1.5 GiB** explicit | Today the limit is inert inside a 5.20 GiB cgroup. Set it in `memory.xml` beside `max_server_memory_usage`. |
| `mark_cache_size` | **5.37 GiB** | **512 MiB** | Ceiling exceeds the whole container limit. |
| `uncompressed_cache_size` | 8.59 GiB | **0** | Cache is off (`use_uncompressed_cache=0`); the reservation is a latent trap. |
| `min_age_to_force_merge_seconds` | 0 | **600** + `min_age_to_force_merge_on_partition_only=1` | Converts the constant re-merge trickle into one bounded consolidation pass per idle partition. |
| `async_insert` | 0 | **leave 0** | See dedup note in (a): app-side batching gives the same part cut *and* keeps token dedup. `min_insert_block_size_rows/bytes` (1,048,449 / 256 MiB) and `old_parts_lifetime` (480 s) need no change — neither squashes separate INSERT statements. |
| **structural** (file separately) | `PARTITION BY toYYYYMM`, `hypotheses` plain `String` | daily partitions + `CODEC(ZSTD(3))` or a side table for `hypotheses` | Bounds the accumulated part by construction and shrinks the 45 GiB column that *is* the merge cost. |

### (c) The `memflat` clause for ClickHouse

`docker stats` is the wrong instrument for a store that writes 50 GiB/run. Replace the
ClickHouse clause in `scripts/scale-miniladder.py::_memflat_judge` with three assertions:

1. **Leak slope on anonymous memory only** — `anon` from
   `docker exec <c> cat /sys/fs/cgroup/memory.stat` (fallback: `MemoryResident`), not
   `docker stats`. Keep ×1.3 + the 64 MiB floor. *s04b reads ~1.0 GiB flat → passes correctly.*
2. **OOM path against ClickHouse's own cap** — `max(CurrentMetric_MemoryTracking)` over the run
   (from `system.metric_log`) **< 85 % of `max_server_memory_usage`**.
   *On s04b: 4,566 / 4,794 = **95.2 % → FAIL**, which is the finding worth gating on.*
   Add `max(CurrentMetric_MergesMutationsMemoryTracking) < 50 %` of the same cap
   (s04b: 3,978 / 4,794 = 83 % → FAIL).
3. **Parts return to baseline after input stops** — `MaxPartCountForPartition` back within
   +20 % of the preflight value within `--drain-factor × burst`, and
   `< parts_to_delay_insert / 2`. This is the honest "the store settled" assertion; it is what
   a stateful store legitimately owes after a burst, where an RSS ratio is not.

Keep `pct_of_limit` on `docker stats` for the *stateless* services; for the stateful three
(clickhouse, opensearch, kafka) page cache makes the ratio non-deterministic — s04 vs s04b,
same code, ×0.761 PASS vs ×1.72 FAIL, is the proof.

**Re-enable `system.part_log` for the next scale leg** (delete its `<remove/>` line in
`deployment/docker/clickhouse/system-logs.xml`, restart, add a TTL) so the part/merge counts
above become measured rather than reconstructed, and so the batching win can be verified
directly instead of estimated.
