# Tracker 165 at 1.25 GiB, and where the drain time actually goes

**Date:** 2026-08-21 · **Base:** `a9e14486` · **Bus:** Apache Kafka 4.1.1 KRaft, mTLS
**Runs:** `08210203s5sp` (Part A, p90, profiler off) · `082103…` (Part B, 790/s, profiler on)

---

## Part A — 1.25 GiB qualification: **PASS**

Candidate limit **1,342,177,280 bytes (exactly 1.25 GiB)**, window cap **150,000**
(a resource ceiling ≈1.6× what the horizon needs at the measured p90 rate, not
the horizon itself). Workload: the measured **p90 active rate of 182 signals/s**
for 12 minutes — 721 s of event time, deliberately longer than the 516.527 s
horizon so it can actually be filled, and deliberately *not* the 10× storm.

### All seven phases PASS — the first fully clean 1K qualification in this programme

| Phase | Verdict |
|---|---|
| preflight | PASS — 29 services |
| onboard | PASS — **1000/1000**, ratio 0.94 |
| burst | PASS — 131,041 events in 721 s (~182/s) |
| **drain** | **PASS — lag back to baseline in 25 s** (budget 2,164 s, peak 152) |
| accounting | PASS — **131,041 == 131,041 + 0 DLQ + 0 rejections; 1000/1000 devices covered** |
| memflat | PASS — all 8 containers within ×1.3 and under 85 % of caps |
| stability | PASS — 0 CommitFailed, 0 UnknownMember, 0 restarts, worst stall **2,158 ms** |
| cleanup | PASS — 1000 devices deleted + verified |

### Retention held at the contract, not at the ceiling

| | replica 1 | replica 2 |
|---|---:|---:|
| required horizon | 516.527 s | 516.527 s |
| **achieved horizon** | **680.0 s** | **640.0 s** |
| retained signals | 64,482 | 57,997 |
| window utilisation | **43.0 %** | **38.7 %** |
| capacity drops | **0** | **0** |
| stream-time evictions | 18,351 | 18,050 |
| idle-tenant evictions | 0 | 0 |
| **`rca_evidence_degraded`** | **0** | **0** |
| `copartition_ok` | true | true |
| entity cache (ids / tuples / evicted) | 7,048 / 6,000 / **0** | 7,049 / 6,001 / **0** |

Evidence left the window **only** by semantic expiry. The cap never bound.

### Memory

| | replica 1 | replica 2 |
|---|---:|---:|
| peak | 668.1 MiB (**52.2 %**) | 774.8 MiB (**60.5 %**) |
| settled | 623.7 MiB | 729.3 MiB |
| +5 min | 625.3 MiB | 730.5 MiB |
| **+15 min** | **628.3 MiB (49.1 %)** | **732.9 MiB (57.3 %)** |
| swap | **0** | **0** |
| `memory.events` max / high / oom / oom_kill | **0 / 0 / 0 / 0** | **0 / 0 / 0 / 0** |
| PSI some / full (whole run) | 0.10 s / 0.06 s | 0.13 s / 0.09 s |
| CPU | 1,963 core-s (1.39 s throttled) | 1,882 core-s (0.17 s throttled) |

**Headroom: 39.5 % at worst-case peak, 42.7 % at +15 min.** The settled slope is
**+4.6 MiB over fifteen minutes (0.7 %)** — flat, not a rising trend. No cap hit
of any kind, zero swap, negligible pressure.

**Verdict: 1.25 GiB is production-viable for the qualified p90 1K workload**, and
not marginally — it passes with ~40 % headroom on the worst replica.

### Tracker 165 = **PASS**

Every semantic gate was proven in prior waves and re-confirmed here; the one
outstanding criterion — production-memory viability — is now met. Per the wave's
own decision rule, 165 is **not** held open by the throughput problem, which it
does not own.

**Caveat, stated rather than buried:** the shipped default is still
`CORRELATION_MEM_LIMIT:-768m`, and that value is also wired into
`scripts/resource_planner.py` (which distributes a *host* budget across all
services) with its own tests. Raising correlation by 512 MiB has to come from
somewhere in that budget, so changing the default is a planner-level decision
and was **not** made unilaterally in a qualification wave. The lab runs the
qualified 1.25 GiB via `compose.mem125.yml`.

---

## Part B — the drain bottleneck

### First, a correction to the premise

The wave describes "the remaining 1K drain failure". At the qualified 1K/p90
workload **drain does not fail** — it completed in 25 s against a 2,164 s budget.
What fails is the 10× synthetic storm, which the harness sets *deliberately*
above the sustainable ceiling so the drain proof is not vacuous.

Rate ladder, measured:

| ingress | drain | notes |
|---:|---|---|
| 182/s (p90) | **PASS in 25 s** | budget 2,164 s — comfortable |
| 790/s | **PASS in 910 s** | budget 1,093 s — **83 % of budget**, peak lag 193,982 |
| 1,651–1,905/s | **FAIL** | never returns to baseline |

**Sustainable ceiling ≈ 800–1,000/s across two replicas** (~400–500/s each), and
790/s is already near it.

### Profiler contamination: **NOT CONTAMINATED**

`stage()` costs **2.20 µs enabled** / 0.69 µs disabled. The profiled run made
78,879 stage calls → **0.173 s of profiler CPU against 275 measured CPU-seconds
= 0.063 % overhead**. Loop stalls (2,290 ms) and memory (736 MiB) are in line
with the unprofiled Part A run. Conclusions are usable.

### Stage breakdown (790/s, full run)

| stage | calls | total | p50 | mean | p99 | max |
|---|---:|---:|---:|---:|---:|---:|
| **`engine.run_window`** | **6** | **611.0 s** | **77,823 ms** | **101,840 ms** | 195,994 ms | **195,994 ms** |
| `handle.syslog` | 145,791 | 1,092.9 s | **0.34 ms** | 7.50 ms | 79.86 ms | 2,498 ms |
| `engine.prune` | 19 | 1.5 s | 0.01 ms | 78.0 ms | 848 ms | 848 ms |
| `engine.partition_by_tenant` | 19 | 0.2 s | 0.01 ms | 8.7 ms | 51 ms | 51 ms |

### The finding

**A single engine cycle takes 78 seconds at p50 and 196 seconds at worst,
against a 30-second interval.** Six calls consumed 611 seconds. `run_window` is
the pure-Python engine core, and it is the bottleneck by a wide margin.

The per-event path is **not** the problem: a typical syslog event costs
**0.34 ms**. Its 7.50 ms *mean* is the tail of events waiting for the
interpreter while `run_window` holds it — p50 to mean is a 22× gap, which is the
signature of starvation rather than of expensive work.

**The process is GIL-bound, not CPU-bound.** CPU sat at **0.69 / 0.66 cores of a
2-core limit with zero throttling**. Adding cores cannot help: `run_window` is
one single-threaded Python computation, and while it runs, the consumer loop can
only make progress at interpreter switch boundaries.

Executor saturation is ruled out and now on complete evidence — `run_window` was
routed through the instrumented path this wave, closing the coverage gap that
made previous offload numbers describe only one caller. **Queue depth 0, peak 1,
wait p99 0.020 s** while a single call executed for 196 s. The queue is empty;
the work is simply slow.

### Scaling dimension, and the uncomfortable interaction

`run_window` cost scales with **window size** (signals → nodes → candidate
pairs), and window size is exactly what tracker 165 corrected upward. The old
broken window held ~50k signals spanning 54.5 s; the corrected one holds the full
516.527 s horizon — ~96k signals in this run, and far more under load.

**Fixing the retention correctness is what made the engine cycle the
bottleneck.** That is not an argument against the fix — the previous behaviour
was producing hollow RCA graphs — but it is the honest causal chain, and it is
why correctness and capacity are separate trackers.

### Top five measured costs

1. **`run_window`** — 611 s / 6 calls, p50 77.8 s, max 196 s. Dominant.
2. **GIL serialisation** — 0.66–0.69 cores used of 2 available.
3. **`handle()` tail from starvation** — p50 0.34 ms, mean 7.50 ms (22×).
4. `engine.prune` — max 848 ms at ~96k signals. Small, but no longer free.
5. `engine.partition_by_tenant` — max 51 ms. Negligible.

### Expected next optimisation target

Reduce `run_window`'s per-cycle cost. The three directions, in the order the
evidence supports them:

* **bound the work per cycle** — it currently rescans the whole window every
  cycle; incremental correlation over just the newly-arrived signals would make
  cost scale with arrivals rather than with retained state;
* **get it off the GIL** — a separate process would let the 2-core limit
  actually be used;
* **reduce candidate-pair generation** — the same territory tracker 162 is in,
  now with a measured reason to care.

**No optimisation was attempted in this wave**, per the instruction not to make
the profiler and the optimiser change the system simultaneously.

---

## Tracker status

| Tracker | Status |
|---|---|
| **165** | ✅ **PASS** — semantics proven, 1.25 GiB qualified with ~40 % headroom |
| 164 | open, **not the bottleneck** — now on complete executor evidence. Unbounded queue remains pre-GA resilience hardening. |
| 163 | deferred — `OPEN_OBJECTS` 7–8 |
| 162 | PARTIAL — and now has a measured reason to matter: candidate-pair cost inside the dominant stage |
| **NEW** | engine-cycle cost: `run_window` at 78–196 s/cycle is the 1K throughput blocker |

**Clean 1K qualification: PASSED at p90.** **Capacity calibration: may begin** —
the ceiling is bracketed at 800–1,000/s and the bottleneck is identified.
**72 h soak: still blocked** — do not soak a system whose dominant cost path is
about to be optimised.
