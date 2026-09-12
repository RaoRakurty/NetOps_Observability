# Tracker 156, second pass — the per-event consume path

Follow-on to `TRACKER156_EVIDENCE_2026-08-19.md`. That pass fixed the
engine-cycle redundancy and found it did not explain the symptoms. This pass
attacked `handle()`, the per-event path, which was the shared suspect behind both
the slow drain and the RSS high-water.

**Result: one acceptance criterion is now met outright and was not before —
consumer expulsions are gone. Memory and drain are still FAIL.**

---

## 1. What the per-event profile found

40,000 mini-ladder-shaped syslog events through `handle()` alone, no
`engine_cycle`. Baseline **1,261 events/s**. Per event:

| count | what |
|---|---|
| 16.5 | regex searches — **12 of them the entire port-event rule chain**, which misses for ordinary traffic |
| 1.2 | log records — a `log.info` per accepted signal, ~4,000 lines/s at burst, each formatted, written to stdout, then shipped through Vector into OpenSearch |
| 1 | `os.path.getmtime` — the device→tenant registry re-stat'ed on **every event** |
| 5 | `datetime.now` |
| 4 | dataclass `__init__` — including a fresh per-device `Observer` every time |

## 2. Fixes and their measured effect

| | throughput | RSS growth | live objects |
|---|---|---|---|
| baseline | 1,261 ev/s | 261 MB | 59.6 MB |
| + prefilter, stat throttle, one clock read, log downgrade | 1,851 ev/s | 261 MB | 59.6 MB |
| + interned Observers | **1,785 ev/s** | **222 MB** | **52.0 MB** |

**+42% throughput, −15% RSS growth, dataclass allocations halved (160,000 →
80,000 objects per 40,000 events).**

The port-event pre-filter is the union of exactly the rules it replaces, so it is
sound by construction — a union matches iff some alternative matches, therefore a
line it rejects cannot match any rule. 16.5 → 4.5 searches per event.

**Measured and rejected: `MALLOC_ARENA_MAX`.** 293.0 MB at default, 293.3 at 2,
293.0 at 1 — no effect at all. The churn is small objects served by pymalloc, not
glibc arenas, so the glibc knob cannot reach it. Recorded so nobody spends
another afternoon on it. `malloc_trim` was measured earlier at 9 MB of 67.

## 3. The live acceptance run

Mini-ladder `08191832j027`, same shape as before.

### The criterion that is now met

| run | commit_failed | unknown_member | consumer_restarts |
|---|---|---|---|
| 2026-08-18 baseline | 7 | **110** | 2 |
| after the engine-cycle fix | 6 | **100** | 2 |
| **after the handle() fix** | **0** | **0** | 1 (the deploy) |

**Consumer expulsions went to zero.** Both containers show `RestartCount=0`, so
the single counted restart is the deploy that started the run, not a mid-run
expulsion.

The progression is the interesting part: the engine-cycle fix barely moved
expulsions (110 → 100), the `handle()` fix eliminated them (→ 0). So the
heartbeat starvation was in the **consume path** all along — `handle()` at 1,261
ev/s was occupying the loop between polls, and 42% more headroom was enough. The
engine cycle was never the cause of the rebalance storm, despite being the thing
tracker 156 named.

### The criteria still failing

| gate | required | actual |
|---|---|---|
| memory plateau below the cap | < 85% | **99.6%** (786 MiB of 789) |
| backlog drains | ~645/s to clear 600k in the budget | **146/s** |
| device coverage | 1000/1000 | **927/1000** |

Drain rate across the three runs: 115 → 132 → **146/s** (+27% cumulative). Real,
and an order of magnitude short of what the gate needs.

## 4. The coverage gap is repeatable and unexplained

`corr_signals covers 927/1000` in **both** runs on the fixed build — the same
number twice, under different run ids. That is not backlog variance, which is
what the first pass assumed. 2026-08-17 and 2026-08-18 both covered 1000/1000.

It could not be diagnosed after the fact because the ladder's cleanup phase
purges the run's rows before anything can query them. **Next step: one run with
cleanup disabled, then query which device indices are absent** — a contiguous
tail means events never consumed, a scattered set means something else.

Neither change plausibly explains it (`corr_signals` is written from `handle()`,
and the archive's output is test-pinned byte-identical), but two identical
numbers deserve a measurement, not an argument.

## 5. The DLQ records with no `reason` — captured, and a real defect

Captured live this run, which the first pass could not do before rotation:

```json
{"ts": "...", "topic": "chbatch:netops.corr_signals",
 "error": "clickhouse rejected the batched insert",
 "payload": "{\"tenant_id\": \"global\", \"signal_id\": \"...\", ...}"}
```

These are **ClickHouse batch-insert rejections**, not tenant refusals. Two
rejected batches — `batched_rows=42` on one replica and `batched_rows=53` on the
other, 95 total, exactly matching the 95 records captured — and one
`ch_code=241` (MEMORY_LIMIT_EXCEEDED) on `netops.findings`.

Two things follow:

1. **This is a real data-loss path that the old gate could not show.** The
   count-based accounting gate folded these into a DLQ total dominated by benign
   `identity_unattributable`, so 95 lost signals looked like more of the same
   background. Tracker 159's reason-aware gate separated them on its first run.
2. **The batch-rejection DLQ writer stamps no `reason` field**, unlike the tenant
   path. That is what makes the records unclassifiable, and it is worth fixing on
   its own — filed as tracker **160**.

## 6. Status

| acceptance criterion | verdict |
|---|---|
| memory reaches a stable plateau below the cgroup ceiling | ❌ 99.6% of cap |
| no unexpected consumer expulsions/restarts | ✅ **110 → 0** |
| no loop-starvation regression | ✅ |
| backlog drains normally | ❌ 146/s |
| RCA coverage correct | ❌ 927/1000, repeatable, unexplained |

Two of five. Tracker 155 not started, `BUS_PARTITIONS` untouched, **no soak
baseline created** — the required clean mini-ladder run has not happened.

Remaining for memory: the earlier finding stands — with `window_signals = 0` the
service still held 700–774 MiB, and neither `MALLOC_ARENA_MAX` nor `malloc_trim`
recovers it. Per-event allocation is now 42% cheaper in CPU but the object COUNT
per event is largely the data itself. The next honest step is to instrument
correlation's own heap in-process (tracemalloc behind a flag) rather than infer
from a harness, because the harness reproduces the churn shape but not the
magnitude.
