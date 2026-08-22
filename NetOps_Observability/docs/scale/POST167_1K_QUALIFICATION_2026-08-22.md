# Post-167 clean 1K qualification — the gate told the truth, and the answer is FAIL

**Date:** 2026-08-22 · **Run:** `08212335gjeg` · **Overall: FAIL**
**Base commit:** `5d7d6892`, tree dirty (166/167/168/170 wave), diff fingerprint `534fc6a1c3e2bb96`
**Workload:** `--devices 1000 --burst-minutes 12 --eps 182`, unchanged from the qualified baseline.
Labelled **`CORRELATION_STRESS`** (~100 % promotion, single-kind).

---

## The headline

**Tracker 170 did its job on its first live run.** The previous run returned PASS
on all eight phases with 97 % of the workload unevaluated. This one:

```
drain                    PASS  KAFKA TRANSPORT lag drained in 41s (budget 2160s) —
                               transport only; correlation evaluation is gated separately
correlation_completion   FAIL  correlation engine INCOMPLETE after 2160s:
                               pending=95618 oldest_pending_age=520.0s cohorts_delta=4
Overall                  FAIL
```

The gate caught live exactly the class of failure it was built for. Transport
still drains in 41 seconds; the engine still does not evaluate the workload.

---

## A. Preflight

| | |
|---|---|
| image | `netops-correlation:latest` → `sha256:3c9d78ff553f`, rebuilt this wave |
| containers | `4f0d00c2a24d` (23:29:59Z) · `81f9d874c238` (23:30:02Z), both fresh |
| **167 deployed** | verified inside both containers: `_inapplicable_score` present in `/app/scoring.py` |
| 168 / 166 / 165 | 11 × `tracker 168`, 4 × `_begin_epoch`, 14 × `RETENTION_REQUIRED_S` — all present |
| cgroup limit | 1280 MiB per replica — **unchanged** |
| BUS_PARTITIONS | 4 — unchanged |
| devices at start | **0 live** (API) |
| **170 baseline** | 2 replicas, **both readable**, pending 0, cohorts 0, oldest 0, window 0 |

**Pre-167 steady-state note:** before redeploy, both replicas sat at **92–96 % CPU
with pending = 0** — the cost of re-scoring 1,000 open objects every cycle with
nothing new arriving. That is the baseline 167 was meant to attack.

## B. Workload

131,041 events in 720 s (~182/s, on target). **1000/1000 devices** created
(35.1/s → 38.1/s, ratio 1.08). OpenSearch persisted 131,041 run docs;
`corr_signals` 131,041; run-attributable DLQ **0**; unexplained missing **0**.

## C. Tracker 170 completion — the engine did NOT evaluate the workload

| Replica | pending final | cohorts base → final | oldest pending | same process | readable |
|---|---:|---:|---:|---|---|
| `4f0d00c2a24d` | **47,122** | 0 → **1** | 520.0 s | ✅ | ✅ |
| `81f9d874c238` | **48,496** | 0 → **3** | 510.0 s | ✅ | ✅ |

`pending_sum` **95,618** · worst oldest **520.0 s** · cohorts advanced **4** ·
process identity stable · both replicas readable throughout (127 samples).

> **Did the engine actually evaluate the qualification workload? NO.**
> Four cohorts completed against 131,041 injected signals.

## D. Tracker 167 live selectivity — and why this run cannot answer Phase 4

167 **is** deployed and **did** help materially:

| | pre-167 run (`082120173zup`) | post-167 run (`08212335gjeg`) |
|---|---:|---:|
| **`epoch_seconds_max`** | **3,956 s** | **582 s / 1,334 s** |
| `prep_seconds_max` | 2.45 / 5.30 s | 4.50 / 1.78 s |
| carried-edge peak | 20,806 / 20,917 | 18,767 / 19,481 |
| RSS end | 381.6 MiB | **372 MiB (29.1 %)** |

Live selectivity for this workload's objects: **22 of 100 templates (22 %)** —
identical to offline, and computed the same way the engine computes it.

**That agreement is not validation.** The harness emits 100 %
`%LINK-3-UPDOWN`, so essentially every object has **one** signal kind. Adding a
second kind to the same object still yields 22 candidates. **This run does not
exercise multimodality at all, so Phase 4's real question — does 22 % hold under
a realistic mix — remains unanswered.** It cannot be answered until the
mixed-ingest profile from the GA workload contract exists.

## E. Engine profile — the current dominant cost

| Component | replica 1 | replica 2 |
|---|---:|---:|
| epoch max | 582 s | **1,334 s** |
| epoch cohorts max | 1 | 2 |
| snapshot preparation max | 4.50 s | 1.78 s |
| prune max | **0.02 s** | 0.01 s |
| loop stalls | 711 | 699 |
| **worst loop stall** | 6,513 ms | **17,029 ms** |

Preparation is **0.3 %** of the epoch. Pruning is **negligible**. The cost is
still inside `run_window` — per-object work over ~1,500 objects — and 167 cut it
by roughly 3–7× without closing the gap.

## F. Throughput

Ingress 182/s. Kafka consumption kept up entirely (peak lag 2,821, drained 41 s).
Correlation evaluated **4 cohorts** — at most ~20,000 of 131,041 signals.

`pending` peaked at **61,808 / 65,178**, then settled to 47,122 / 48,496.
**That decline is retention expiry, not evaluation:** 17,899 + 17,523 = **35,422
signals were evicted by stream-time expiry**, and evictions are what removed
them from pending.

**Classification: SATURATED.** The backlog is bounded — but bounded by evidence
expiring, not by the engine catching up. Without expiry it would grow. This is a
stable-but-insufficient engine, not positive feedback, and it must not be
described as healthy.

## G. Tracker 166

1. Did correlation complete? **No** — 4 cohorts, 95,618 pending at budget.
2. Did pending return to zero? **No.**
3. Did oldest pending recover? **No** — 520 s at budget, against a 516.527 s horizon.
4. Did processing meet ingress? **No.**
5. Progressive slowdown? **No** — bounded, not degrading. Saturated.
6. Memory bounded? **Yes** — 372 MiB, 29.1 % of limit.
7. Finished inside budget? **No.**

**Tracker 166 = FAIL — stable but insufficient throughput/capacity.**
Explicitly *not* positive feedback: the earlier collapse dynamic is gone, and
every mechanism 166 built is working (preparation 3 per 17 epochs, cohorts
bounded, frontier and carried edges bounded, memory flat). What remains is a raw
capacity deficit.

## H. Tracker 171 — OPEN, NON-BLOCKING

| Maintenance task | Intended cadence | Max observed gap | State impact |
|---|---:|---:|---|
| `_prune_buffer` | ~180 s | **610 s (r1) / 1,363 s (r2)** | window peaked 62,788 / 66,019, settled 47,122 / 48,496 |

17 prune executions per replica, **35,422 evictions total**, prune duration
**≤ 0.02 s**. Maintenance ran, caught up completely, retained state stayed
bounded, memory plateaued at 29.1 % of the limit, and 165 stayed correct.

Starvation improved with 167 (worst gap 1,363 s vs a 3,956 s epoch before).
**Not GA-blocking on this evidence** — the operational consequences the tracker
warns about (monotonic state growth, memory amplification, failed catch-up) did
not occur. It stays open because the coupling is still structural: prune cadence
is bounded by cohort duration, so it degrades exactly when the engine is most
loaded. Fix it after the capacity deficit, not before.

## I. Tracker 165 — remains PASS

Required retention 516.527 s. `rca_evidence_degraded` **0**, capacity drops
**0**, co-partitioning healthy, evictions all stream-time semantic expiry.

**Separate execution finding, as Phase 10 requires:** 35,422 signals expired
**before the engine evaluated them**. That is not a 165 failure — the contract
guarantees retention, and retention held. It is a capacity consequence, and it
belongs to 166.

## J. Tracker 168 — remains PASS

Carried edges peaked at 18,767 / 19,481 (vs ~384 k pre-168). Open objects
peaked 1,626 / 1,509 against 1,000 devices — device-local shape intact, the
excess being continuation/versioning as the window slides. No weld signature.
Direct object audit was not possible post-run: cleanup purged ClickHouse
telemetry, as designed.

## K. Resources

| Metric | correlation-1 |
|---|---:|
| cgroup limit | 1280 MiB |
| RSS cold → warm → end | 60 → 279 → **372 MiB** |
| % of limit | **29.1 %** |
| ratio vs warm anchor | 1.337 |
| swap / OOM / oom_kill | 0 / 0 / 0 |

`memflat` **FAIL** on ×1.337 > ×1.30. This is growth *after input stopped* — the
engine was still materializing objects from the backlog, which is the known
false-failure shape for this gate under stream-time retention. At 29.1 % of the
limit it is not a resource risk, but the gate cannot distinguish "still working"
from "leaking" and said so.

## L. Kafka / process health

0 CommitFailedError · 0 UnknownMember · 0 rebalances · 0 consumer restarts ·
0 process identity changes · 2/2 replicas readable across 3,324 s.

## New finding — CPU starvation is now causing durability loss

`accounting` **FAIL**: three ClickHouse writes were **LOST**.

```
23:44:01 ERROR clickhouse insert transport failure table=netops.findings err=ReadTimeout
23:44:01 WARN  clickhouse write LOST table=netops.corr_signals_archive reason=rejected row_count=8461
23:48:18 WARN  clickhouse write LOST table=netops.corr_objects reason=rejected version=2
```

All three are `ReadTimeout`, all during peak load, on a process showing
**17-second event-loop stalls**. The durability contract behaved correctly — the
loss was detected, counted and logged, never silent — but this is **real data
loss**: one object version, one findings row, and an archive slice of **8,461
rows**.

**This escalates the severity of the capacity deficit.** It is no longer only
"RCA is late". Engine overload → event-loop starvation → ClickHouse client read
timeouts → lost writes. Any capacity fix must be re-checked against this path.

## M. Status

* **165 = PASS** (frozen)
* **166 = FAIL** — stable but insufficient throughput/capacity
* **167 = PASS OFFLINE; live-deployed and materially effective, but live
  selectivity NOT validated** (single-kind workload)
* **168 = PASS LIVE**
* **169 = OPEN** — merge blocker, untouched
* **170 = PASS** — validated live on its first real run
* **171 = OPEN, NON-BLOCKING**
* 1280 MiB floor = **unchanged**
* mini-ladder = **BLOCKED** · 72h soak = **BLOCKED**

## N. Next action

**Profile and fix the current post-167 bottleneck.** The measurement is
unambiguous: preparation is 0.3 % of an epoch, pruning is 0.02 s, candidate
generation is no longer dominant, and the remaining cost is per-object work
inside `run_window` across ~1,500 objects.

Do not touch 171 or add replicas yet. The next step is a profiler run against
the *current* engine to find what the remaining per-object cost actually is —
the same discipline that turned 167 from a guess into a measurement. The
durability-loss path above makes it more urgent, not less.

---

# Addendum — profiling today's engine, and two cache defects it exposed

Per §N, the current engine was profiled at the live shape rather than optimised
on assumption. 48,000 nodes, 5,000-node cohort, full `run_window` under cProfile.

## The bottleneck was not where anyone would have guessed

**`Catalog.version_hash()` was 241.09 s of a 495.86 s `run_window` — 48.6 % of
the cycle.**

`rank()` stamps `catalog_version` on every `RankingResult`, so `version_hash()`
runs once per RCA object. It re-serialised all 100 templates through pydantic,
re-encoded them to JSON with `sort_keys`, and SHA-256'd the result — **every
time** — to return the same twelve characters. Its own docstring says the value
is a constant that "changes iff an enabled template's content changes".

The visible cost was spread across functions that looked unrelated:

| | |
|---|---:|
| `encoder.py:iterencode` | 100.03 s (43,067 calls) |
| pydantic `to_python` | 91.44 s (**4,306,500** calls = 43,065 × 100 templates) |
| `openssl_sha256` | 24.22 s (43,067 calls) |

None of that is correlation work. It is one memoisation.

The second finding was **my own 167 code**: `_inapplicable_score(template)`
depends on the template alone — no evidence, no object — yet it was recomputed
per object: **3,359,070 calls, 47.31 s**.

## The fix, and the regression it initially caused

Memoising both took `run_window` **495.86 s → 301.42 s (−39.2 %)**.

But the profile then showed **88,240,185 pydantic `hash_func` calls costing
58.75 s** — the new top entry. `lru_cache` keyed on the `Catalog`/`Template`
objects had traded expensive recomputation for expensive **cache-key hashing**:
hashing a frozen pydantic model walks every field of every template, and that
was happening on every lookup.

Replacing the value-keyed caches with **identity-keyed** ones — a bounded dict
holding a strong reference to the cached `Catalog` so its `id()` cannot be
recycled — removed it. Both derived structures (kind index and analytic scores)
are now built together, once per catalog, in `_catalog_plan`.

## Result

| Stage | `run_window` | vs baseline |
|---|---:|---:|
| post-167 baseline | **495.86 s** | — |
| + value-keyed memoisation | 301.42 s | −39.2 % |
| **+ identity-keyed caches** | **186.63 s** | **−62.4 %** |

**2.66× faster, with zero semantic change.** The 25-test equivalence oracle and
the full suite (**1435 passed, 9 skipped**) are green; ruff / mypy / bandit
clean. A mutation re-check on the new seam still kills (dropping optional-clause
kinds → 16 failures).

One test needed updating: it patched `_catalog_kind_index` to force the
exhaustive path, and `rank()` now reads `_catalog_plan`. The test caught the
moved seam immediately, which is what it is for.

## What is dominant NOW

| | cumtime | % wall |
|---|---:|---:|
| `rank()` total | 167.85 s | 89.9 % |
| ↳ `score_template` (947,430 calls = 43,065 objects × 22 candidates) | 151.35 s | — |
| ↳ **`verdicts.assess`** | **81.65 s** | **43.7 %** |
| `build_edges` | 4.65 s | 2.5 % |
| components + seam fold | 0.89 s | 0.5 % |

The remaining cost is **legitimate work**: the 22 candidate templates each
object genuinely has to score, and the verdict gate inside each. There is no
further cache defect here — the next step would be a design change to the
verdict path, which is a different question and needs its own evidence.

## Does this close tracker 166?

**Probably not on its own, and I will not claim it does without a live run.**
The live run evaluated ~4 cohorts in the 2,160 s budget against ~26 needed. A
2.66× improvement takes that to roughly 10–11. Still short by ~2.5×.

That estimate is offline and on a single-kind workload. **166 stays FAIL until a
live run says otherwise.**
