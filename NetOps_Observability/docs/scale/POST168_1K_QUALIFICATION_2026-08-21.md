# Post-168 clean 1K qualification — the harness says PASS, the engine says FAIL

**Date:** 2026-08-21 · **Run:** `082120173zup` · **Branch:** `feat/observability-platform`
**Base commit:** `5d7d6892` · tree **DIRTY** (166 + 168 wave uncommitted; diff sha256 `2437438ac713c5c1`)
**Workload:** `--devices 1000 --burst-minutes 12 --eps 182` — identical to the qualified 165 baseline
and to the failed 166 run. Labelled **`CORRELATION_STRESS`** (~100 % promotion).

---

## The headline

**Tracker 168 is live-qualified on correctness. Tracker 166 is still FAIL.
And the harness returned PASS on all eight phases while the correlation engine
evaluated 3 % of the workload.**

That third clause is the most important finding of the run.

| | harness verdict | engine reality |
|---|---|---|
| drain | **PASS** — lag to baseline+ε in 56 s (budget 2,160 s) | Kafka *consumption* drained. Correlation **evaluation** did not start. |
| accounting | **PASS** — 131,041 == 131,041 persisted + 0 DLQ + 0 rejections, 1000/1000 devices | counts `corr_signals` rows, written by `handle_syslog` on ingest — **before** the engine ever sees them |
| overall | **PASS** | **127,247 signals never evaluated** |

The harness gates on Kafka consumer lag and ClickHouse ingest accounting. Neither
is a statement about RCA. Filed as **tracker 170**.

---

## A. Preflight

| | |
|---|---|
| commit / tree | `5d7d6892`, dirty (166+168 wave), diff fingerprint `2437438ac713c5c1` |
| image | `netops-correlation:latest` → `sha256:281e539fa411`, built this wave |
| containers | `netops-correlation-1` `02f0c701526a` (20:11:53Z) · `netops-correlation-2` `182088270d24` (20:12:48Z) |
| **168 in the running image** | verified **inside the container**: 11 × `tracker 168` in `/app/producers.py`, backstop at `/app/engine.py:346` |
| **166 epoch in the running image** | 4 × `_begin_epoch` in `/app/main.py` |
| 165 retention | untouched — no diff to retention/watermark/co-partitioning lines |
| planner floor | 1280 MiB, unchanged; cgroup `memory.max` = 1,342,177,280 B = **1280 MiB** on both replicas |
| BUS_PARTITIONS | 4, unchanged |
| cohort / drain | 5000 / 20 (defaults, unchanged) |
| devices at start | **0 live** (API `/api/devices` → empty). The 300 `mlx-*` entries in `devices.json` are `deleted_at` **tombstones**, not stale identities |
| ClickHouse | 6 residual `corr_signals` rows; purged by the run |
| **standing background** | syslog-ng reports a sustained **2 EPS** from an external UDP:514 source, all refused `identity_unattributable` (registry empty). Pre-existing, tracker-159 class. It **cannot** contaminate accounting: DLQ is counted by `grep -c <runid>` and refusal records withhold the hostname (F-11). ~1.1 % of ingress at 182 EPS |

## B. Workload result

131,041 events injected in 720 s (~182/s, on target). 1000/1000 devices created
(rate 25.9/s → 31.6/s, ratio 1.22). 0 DLQ attributable to the run, 0 rejections,
0 duplicates, 0 loss. Cleanup deleted and verified all 1000 devices.

## C. Tracker 168 — density and object structure, LIVE

| | PRE-168 (characterization) | POST-168 LIVE |
|---|---:|---:|
| entity_tokens on a link event | `(host, ifname)` | **`['mlx-…-00000']`** — verified in ClickHouse |
| carried edges (plateau) | ~384,000 | **13,076 / 13,699** per replica |
| RCA objects | ~1 (estate-wide weld) | **2,586** |
| **multi-device objects** | 1 spanning **150+** devices | **0 of 2,586** |
| largest object | 1,800+ nodes | **7 nodes** (mode 6) |
| correlation RSS | 750–784 MiB (56–58 %) | **381.6 MiB (29.8 %)** |

Every `affected` set holds interfaces of exactly one device, e.g.
`mlx-082120173zup-00617:GigabitEthernet0/{1,9,17,25,33,41}`. All 2,586 objects
`suspected`, which is correct for containment-only relations on synthetic flaps.

**Tracker 168 = PASS, live-qualified.** No weld, no device-local identifier acting
globally, carried-edge explosion removed, memory nearly halved, tenant isolation
intact, accounting clean.

## D. Tracker 166 — FAIL

| replica | epochs | **preparations** | **cohorts completed** | window | pending | oldest pending |
|---|---:|---:|---:|---:|---:|---:|
| correlation-1 | 17 | **3** | **1** | 67,115 | **66,179** | **700 s** |
| correlation-2 | 15 | **3** | **2** | 63,926 | **61,068** | **680 s** |

In 26 minutes of run plus 25 minutes after it, the two engines completed **one and
two cohorts**. Pending never recovered — it rose monotonically and then froze.
`oldest_pending_event_age` reached **700 s against a 516.527 s horizon**.

**Positive feedback: the answer is NO — and that is not good news.** The old
loop (slow cycle → bigger next cohort → slower cycle) cannot be observed because
the engine never got to a second cohort. The failure changed shape rather than
resolving: from many slow cohorts to **one cohort that will not finish**.

### The epoch machinery itself works

`prep_seconds_max` = **1.78 s / 1.08 s**; `preparations` = 3 against 17 and 15
epochs. The once-per-epoch invariant held in production exactly as designed, and
preparation is now a trivial fraction of the cycle. **The 166 epoch work is
sound; it is not what is failing.**

### Where the time actually goes — offline reproduction of the live shape

6,000 nodes / 125 devices × 48 interfaces / 5,000-node cohort (matching the run's
reported `prep_nodes=6000`), full `run_window` under cProfile:

| | |
|---|---:|
| `prepare_run_window` | 0.29 s |
| **whole `run_window`** | **29.71 s** → **1,111 objects**, 99,091 edges |
| `build_edges` (candidate gen + scoring) | **4.11 s — only 14 %** |
| `scoring.score_template` | **17.98 s cumulative, 111,100 calls** |
| `catalog.kinds` | 2.68 s (2,064,000 calls) |
| `verdicts.coverage` | 2.30 s (111,100 calls) |
| pydantic `to_python` + `json.iterencode` | 4.51 s |

**111,100 = 1,111 objects × ~100 catalog templates.** The cost is now
**per-OBJECT**, not per-candidate.

### The causal chain, corrected by measurement

The proposed chain was: local-token leakage → false candidate groups → weld →
carried-edge explosion → candidate explosion → long cycles → collapse.

**Everything up to and including "candidate explosion" is confirmed and fixed.**
Candidates/signal fell 970.9 → 23.5; carried edges 384 k → 13 k; `build_edges`
is no longer the bottleneck at 14 % of the cycle.

**The final link is refuted.** Removing the weld did not shorten the cycle,
because the weld had been *hiding* a second cost: it collapsed the estate into
**one** object, so per-object work was paid once. Correct behaviour produces
~1,000 objects per replica, and per-object template scoring, verdict assessment
and serialization now dominate. The bottleneck moved from
`O(candidates)` to `O(objects × templates)`.

## E. Epoch performance

Only one/two cohorts completed, so distribution statistics are not meaningful.
What is measured: `epoch_seconds_max` **365.6 s** (replica 1) and **200.0 s**
(replica 2); `epoch_cohorts_max` **1**; `prep_seconds_max` 1.78 s / 1.08 s.
At the time of writing a single cohort has been running **~33 minutes** — still
progressing (open objects rose 739 → 786 during observation), not deadlocked.

## F/G. Throughput

Ingress 182 EPS. Kafka consumption kept up completely (lag peak 4,702, drained in
56 s, final 59). **Correlation evaluation processed ~3,900 of 131,041 signals.**

Classification: **UNSTABLE OVERLOAD** on the correlation axis —
backlog grew continuously and never drained — while the ingest path was
comfortably **SUSTAINABLE**. Those two must be reported separately; conflating
them is exactly what produced the false-green.

## H. Tracker 165 — remains PASS

`stream_time_evictions_total` = **0**, `rca_evidence_degraded` = **0**, no
capacity drops, co-partitioning healthy. **Nothing expired and nothing was
dropped** — the pending evidence is still in the window, merely unevaluated.

One consequence of the 166 epoch design is recorded honestly: `_prune_buffer`
now runs at the **epoch boundary**, so an epoch that runs for 33 minutes defers
retention for 33 minutes. Here that is benign (it retains *more*, and the design
doc flagged it as a new gate). Under a longer run it is a real risk and needs
the epoch bounded in wall time.

## I. Resources

| | correlation-1 |
|---|---:|
| cgroup limit | 1,342,177,280 B (1280 MiB) |
| cold → warm → end | 59.6 → 372.9 → **381.6 MiB** |
| % of limit | **29.8 %** |
| ratio vs warm anchor | 1.023 |
| swap / OOM / oom_kill | 0 / 0 / 0 |

Against the pre-168 run's 750–784 MiB (56–58 %). **Memory halved.** The 1280 MiB
floor is unchanged and is now generously conservative — but it must not be
lowered on one run at 3 % evaluation coverage.

## J. Kafka health

0 CommitFailed · 0 UnknownMember · 0 consumer restarts · 0 rebalances ·
2/2 replicas readable over a 1,156 s window · worst loop stall 5,767 ms ·
245 loop stalls (expected: `run_window` is a long synchronous offload).

## K. Status

* **165 = PASS** (frozen, unchanged)
* **166 = FAIL** — pending never recovers; 1–2 cohorts in 26 min; 127,247 signals unevaluated
* **168 = PASS, live-qualified** — 0/2,586 multi-device objects, tokens verified in ClickHouse
* **167 = READY, and now clearly GA-blocking** — but its **scope must widen from per-pair to per-object cost**
* **169 = OPEN**, merge blocker (unchanged, untouched this wave)
* **170 = NEW** — the harness returns PASS while correlation evaluates 3 % of the workload
* **1280 MiB planner floor = unchanged**
* **72h soak = BLOCKED**

## L. Recommended next action

**Tracker 167, rescoped to per-object cost.** The measurement this wave existed
to produce is unambiguous: `build_edges` is 14 % of a cycle and
`score_template` × object-count is 60 %+. Candidate-level prefilters — 167's
original scope — would optimise the wrong 14 %.

The specific target: **~100 catalog templates are evaluated against every one of
~1,000 objects per cycle.** An index from object signal-kinds to candidate
templates (`Template.applies_when` / `kinds()` is already declared) should cut
that by the selectivity ratio without touching a single verdict.

Fix 170 first, though — it is small, and until it is fixed the qualification
harness cannot tell a good run from a bad one.

---

# Addendum — the engine did finish, and what happened next

**Correction to §D.** "One cohort that will not finish" was too strong. Sampling
the replicas ~50 minutes after the run ended showed `cohorts_total` at **16 and
15** (from 1 and 2), `pending` **0**, `oldest_pending_age` **0**. The backlog
drained; it was roughly an hour late, not never.

The precise shape, from the engine's own counters at rest:

| | correlation-1 | correlation-2 |
|---|---:|---:|
| **`epoch_seconds_max`** | **3,956 s (66 min)** | 3,649 s (61 min) |
| `epoch_cohorts_max` | 10 | 9 |
| `prep_seconds_max` | 2.45 s | 5.30 s |
| preparations / epochs | 7 / 21 | 24 / 36 |
| stream-time evictions | 18,744 | 17,657 |
| open objects (settled) | **1,000** | **1,000** |
| carried-edge peak | 20,806 | 20,917 |

So a **single epoch ran for 66 minutes and drained 10 cohorts inside it**. The
work-conserving drain loop behaved exactly as designed; what was missing is a
wall-time bound on the epoch. Pruning is deferred to the epoch boundary, so
retention was deferred for 66 minutes — which is why evictions read 0 during the
run and 18,744 afterwards. Recorded as **tracker 171**.

`open_objects` settling at exactly **1,000 per replica — one per device** is a
second independent confirmation of tracker 168.

The qualification verdict is unchanged: **166 = FAIL**. Completing an hour
outside the contract is not completion. But the failure is "60× over budget",
not "deadlocked", and that distinction matters for what to fix.
