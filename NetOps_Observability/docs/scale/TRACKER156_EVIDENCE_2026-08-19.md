# Tracker 156 — what was fixed, what was measured, and what is still open

Status after 2026-08-19: **the defect named in tracker 156 is fixed and proven.
The PASS criteria for the sustained load test are NOT met**, because the
symptoms 156 was filed to explain turn out to have a different cause. Both
halves are recorded here; the second half is the more important finding.

---

## 1. What 156 said, and what profiling actually found

The row named `_archive_slice` + `slice_hash` as work "sized by the whole
50k-floor WINDOW rather than by the object". Directionally right, wrong cost
centre. One profiled `engine_cycle` (3,000-signal window, 120 open objects,
**49.66s**):

| calls | site | cumulative |
|---|---|---|
| 1,086,000 | `uuid5` via `Signal.signal_id` | 22.1s |
| 360,000 | `Signal.to_ch_row` | 25.4s |
| 361,200 | `json.dumps` (attrs) | 6.3s |
| 120 | `_archive_slice` | 10.2s |

`signal_id` was a `@property` recomputing a SHA-1 on **every access**, and the
archive converts every window signal to a row **once per open object**. The real
shape was O(objects x window) with pure results recomputed N times.

## 2. The fix, and why it is per-cycle rather than per-signal

`_window_index` builds the node grouping, the canonical `(ts, signal_id)`
ordinal and `str(signal_id)` once per cycle; `_CYCLE_ROW_CACHE` holds each
signal's base archive row for one cycle; archive rows are built per chunk rather
than materialising the whole slice.

Measured at a 20,000-signal window:

| variant | RSS | live objects | cycle CPU |
|---|---|---|---|
| baseline | 157.0 MB | 35.4 MB | 49.66s |
| memoised **on the Signal** | 228.0 MB | 84.8 MB | 7.34s |
| attrs-json memo on the Signal | 185.3 MB | 59.2 MB | 10.52s |
| **per-cycle caches (shipped)** | **156.7 MB** | **35.3 MB** | **7.82s** |

Caching on the Signal looked free and was not. `Signal` is a ~25-field
dataclass, so instances use a key-sharing dict; writing a second non-field key
into `__dict__` converts it to a standalone dict — **measured at +944 bytes per
signal**, ~47 MB across the 50k window. Pinned by
`test_signal_instances_are_never_memoised_in_place`.

**Net: 6.4x less engine-cycle CPU at identical memory.** Output is byte-identical
— `test_archive_index_156.py` compares `_archive_slice` against a verbatim copy
of the pre-156 implementation. 7/7 mutants killed; two of them survived the first
version of the test, which mutated the build result instead of a cache hit.

## 3. The sustained load test: FAIL. The criteria are not met.

Mini-ladder `08191628yka8`, 1000 devices, 5-minute burst, on the fixed build:

| phase | verdict |
|---|---|
| preflight | PASS (ClickHouse healthy again after the PID fix) |
| onboard | PASS |
| burst | PASS — 600,001 events at ~1,898/s |
| drain | **FAIL** — final lag 391,142 after 948s |
| accounting | **FAIL** |
| memflat | **FAIL** — correlation-1 at 762 MiB, 96.5% of its 789 MiB cap |

Against the required gates: memory did **not** plateau below the cap, and the
backlog did **not** drain. Drain improved only from ~115/s to **132/s** (+15%),
nowhere near the 6.4x the isolated profile shows.

**Why the isolated win did not transfer:** the engine cycle was never the
throughput limit. It runs periodically and blocks the loop; fixing it removes
stalls, but consumption rate is set by the per-event `handle()` path, which this
change does not touch.

## 4. The finding that redirects 156: it is not the window

After the run drained and cleanup purged the tenant registry, correlation
reported `window_signals = 0` and `open_objects = 0` — **while still holding
700–774 MiB, 89–98% of its cap.**

An empty window with a full heap disproves the natural hypothesis (a 50k window
at ~14.5 KB/signal). Reproduced in isolation:

```
start                       rss=  65.2 MB
after 30,000 events+cycles  rss= 132.2 MB   window=30000
after clearing EVERYTHING   rss= 131.3 MB   window=0     <-- freed 0.9 MB
after malloc_trim(0)        rss= 122.2 MB                <-- returned 9.1 MB
```

Clearing `WINDOW_BUFFER`, `OPEN_OBJECTS`, `_BUFFERED_IDS`, both per-cycle caches
and the archive-hash map, then collecting three times, released **0.9 MB of
67 MB**. `malloc_trim` returned 9 MB more. The remaining ~57 MB is **allocator
arenas that Python freed and never returned to the OS** — fragmentation from
sustained high-rate small-object churn.

So correlation's RSS is not *held* by any container this codebase can prune. It
is the accumulated high-water mark of allocation churn, and it never comes back
down. That is why every previous memory hypothesis (window size, open objects,
pending batches, replayed state) measured as "bounded" while RSS still climbed to
the cap — all of them were true and none of them were the cause.

**Consequence: the remaining work is to cut ALLOCATION CHURN in the per-event
consume path, or to stop the process retaining freed arenas — not to prune a
container and not to raise the limit.** Candidate levers, none yet measured:
`MALLOC_ARENA_MAX`, periodic `malloc_trim` after a cycle, and reducing per-event
object creation in `handle()`. The consume path is also the drain bottleneck, so
one change may serve both gates.

## 5. Two observations that need follow-up

* **`corr_signals covers 927/1000 burst devices`** on this run, where 2026-08-17
  and 2026-08-18 both covered 1000/1000. Most likely explained by the run ending
  with 391,142 events still unconsumed, so some devices were never reached — but
  it is a difference against the fixed build and deserves confirmation before
  anyone calls it benign. The 156 change cannot plausibly cause it (`corr_signals`
  is written from `handle()`, not the archive, and the archive's output is
  test-pinned byte-identical), but "cannot plausibly" is not "measured".
* **137 DLQ lines with no `reason` field**, surfaced by the new tracker-159 gate
  and correctly failed as an unexpected category. The old count-based gate hid
  them inside a total. The DLQ rotated before a sample could be captured, so the
  writer is not yet identified — capture one on the next run.

## 6. State

`BUS_PARTITIONS` untouched. Tracker 155 not started. **No soak baseline created**
— the required one clean mini-ladder run has not happened, so re-baselining would
repeat exactly the mistake `SOAK_VERDICT_2026-08-19.md` records.
