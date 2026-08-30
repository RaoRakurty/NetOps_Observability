# P4 — Storm-time RCA optimisation programme: consolidated measurement (draft, 2026-08-29)

Owner constraint (2026-08-28): no more hardware; success = engine efficiency +
TTUR SLOs on the existing 4-core box. P5 (scale-out proof) dropped. Authority:
owner memo `/var/tmp/Correlix-Bottleneck-Modified.md`; every number below is
from a dated verdict doc in `docs/scale/` with the SQL/method stated there.
**FINAL — 2026-08-30. Measurement side CLOSED.** The lifecycle fix and the P3
A/B are both measured and recorded below, and the owner has ratified the
storm-time SLO (§8, Option A). What remains is execution work, not measurement
(§7).

## 1. The instrument (what "measured" means here)
- Ratified workload `t-nominal-2.5k`: 2,500 devices, 900,001 events @ 1,000 eps
  (15 min), one tenant → one shard. Gates: completion in 2,700 s, accounting
  exact, memflat, stability. Its noise floor is ±10 % on TTUR (arrival-timing
  variance in continuation adoption) and it has NO storm dynamics (state pinned
  per device; tracker 183) — it is the throughput floor, not a storm test.
- `t-storm-2.5k` (built 2026-08-29): same plan with a seeded fault-injection
  scenario (flaps, recoveries, repeats, multi-vantage, contradictions, the
  enterprise-outage chain) and ground truth scored by the twin's scorer;
  `StormShape` ladder 2/10/25/50 % for the P3 A/B.
- TTUR = `scripts/scale-rca-latency.py` T0..T6 (T4 is a proxy without ground
  truth; T4 correctness = the twin scorer's `affected_includes`/owner clauses).

## 2. Results — `t-nominal-2.5k` (single shard, same workload every leg)
| leg (doc) | completion | T1 p50 | T1 p95 | T1 p99 | T1 max | T-last p95 | notes |
|---|--:|--:|--:|--:|--:|--:|---|
| OLD `fa4857a5` (`STORM_MODE_2P5K_VERDICT`) | FAIL, 24.6k pending | 1,758 | 5,748 | 7,588 | 8,098 | 8,915 | baseline |
| P1 cohort-touch gate (`P1_2P5K_VERDICT`) | FAIL (~106 min) | 1,473 | 4,759 | 5,155 | 5,718 | 7,419 | −30 % versions |
| P2 s0–2 memo/caches/budget (`P2_STEPS012`) | FAIL, 21.6k | 940 | 2,960 | 3,937 | 4,114 | 5,097 | run_window 104 s total |
| P2 s4 async Evidence (`P2_STEP4`) | FAIL, 4.1k | 782 | 2,404 | 2,828 | 2,999 | 3,767 | hold leak |
| P2 s4b generational hold (`P2_STEP4B`) | **PASS 2,515 s** | 772 | 2,208 | 2,658 | 2,684 | 3,550 | first PASS (870k events) |
| P2 s5 batching+offload+CH budget (`P2_STEP5`) | **PASS 1,986 s** | 611 | 1,947 | 2,131 | 2,425 | 3,040 | full 900k; T7 p95 4 s |
| P2 s6 compact memo/prefilter/touch (`P2_STEP6`) | **PASS 2,439 s** | 660 | 2,105 | 2,483 | 2,513 | 3,303 | within noise |
| **Δ OLD → best (s5)** | never → PASS | **−65 %** | **−66 %** | **−72 %** | **−70 %** | **−66 %** | |

Verdict semantics held at every step (equivalence reviews: owner/tier/
confidence 100 % on matched incidents; merges/continuations explained).

## 3. Results — `t-storm-2.5k` (storm dynamics, ground truth)
| run | verdict | completion | stability | memflat | T1 p95 † | accuracy | note |
|---|---|--:|---|---|--:|--:|---|
| storm-s01 (image pre-`675966cd`) | 6/9 | PASS 2,171 s* | FAIL 115 s stall | FAIL (api query) | 1,376 ‡ | 93.0 % | *65k evictions, consumer ejected; counts inflated by redelivery |
| storm-s02 (after 185 parts 1–2) | 8/9 | PASS 118 s | FAIL 35.7 s stall, 2 restarts | PASS (65.5 % of cap) | **1,055** | 93.33 % | lifecycle pass still on the loop |
| storm-s03 (after the merge-index fix) | 7/9 | PASS 104 s | FAIL 27.7 s stall, 1 restart | PASS (81.7 % of cap) | **1,203** | 93.04 % | merge index confirmed fixed (278 pairs / 0.47 s); 1 `netops.findings` row lost (tracker 188) |
| **storm-s04 (after `2852ad6f`)** | **PASS 9/9** | PASS 144 s | **PASS — 0/0/0 restarts**, worst stall 29,974 ms | **PASS (79.5 % of cap, ×0.961)** | **832** | **94.49 %** | accounting exact; 3 findings transport failures all retried and recovered; **27,844 ms of the stall is a BLOCKED sync stretch at `reconcile.find_continuation`** (tracker 185 residual) |

† **All T1 p95 figures for s02/s03/s04 were re-queried in ONE session
(2026-08-30 07:44Z)** with the §5.3 clean-scope query of
`RUN_PLAN_P3_AB_2026-08-29.md` (storm-aggregate cid excluded, scope from each
run's own `report.json`), because legs queried on different days are not
comparable — the P2 wave's lesson. ‡ s01's value is the original-session number
and is **not** same-session comparable; it is kept for continuity only.

Full s04 numbers and the stall analysis:
`docs/scale/STORM_S04_2P5K_VERDICT_2026-08-30.md`.

Accuracy misses are all one clause on chained outages (tracker 187); 31 % of
chain lines are not parser-promotable (tracker 184). The storm-time trend across
the four legs is 93.0 → 93.33 → 93.04 → **94.49 %**, detection 100 % and
specificity 100 % on every leg.

## 4. Where the time goes now (storm-s02, replica-4)
`persist.decision` 916 s (Decision write: blob + 2 inserts) · `run_window` 270 s
(executor) · `handle.syslog` 1,325 s (ingest, starved by the stall) ·
`persist.batch_flush` 309 s (wall, off-loop) · lifecycle pass: the remaining
loop-thread stage (tracker 185 part 2). Evictions 23,210 (nominal 17.8k) — the
identities that age out unevaluated are the P3 population.

## 5. The SLO statement (honest)
The memo's proposed T1 p95 of 5 s is not reachable on one 4-core shard for a
15-minute 1,000-eps storm: the p95 is queueing time behind the burst
(T3−T1 = 0 at max on every leg; decision latency is ~0). What P0–P2 achieved is
a 3× reduction of that queue (5,748 → ~1,950 s) with completion inside the
45-minute budget, lossless, and semantics preserved. The remaining order of
magnitude is either (a) P3 aggregation when the storm carries repeats, or (b)
more shards — the P5 the owner ruled out.

**(a) is now measured, not projected** (`docs/scale/P3_AB_2P5K_VERDICT_2026-08-29.md`,
five legs, one image, arms verified per replica over mTLS):

| rung | projected signal reduction (§6b) | **measured** | measured TTUR effect | measured accuracy | gate outcome |
|---|--:|--:|---|---|---|
| 10 % storm share | −36 % | **−41.0 %** (98,636 → 58,194 forwarded; −19.2 % on the engine-side `sigs` measure) | T1 p95 2,763 → 1,985 s = **−28.2 %**; p50 −35.0 %; p99 −27.4 %; T-last p95 −25.9 % | 89.85 → 89.45 % (−0.40 pp) | ON 9/9 vs OFF 9/9 — **criterion met** |
| 25 % storm share | −56 % | **−58.1 %** (172,453 observed = 72,293 forwarded + 100,160 suppressed) | OFF was **INCOMPLETE** (78,663 pending at the 2,700 s cap); ON **completed in 192 s** after a 2,263 s drain | 81 % → **89 %** | ON 8/9 (memflat only) vs OFF 6/9 — **FAIL → PASS** |
| 2 % storm share (neutrality guard) | ~0 % | **−9.1 %** (54,767 observed, 4,967 suppressed) | T1 p95 **+13.1 % vs one OFF baseline, +28.9 % vs the other**, against an OFF-vs-OFF spread of **13.11 %**; p50 −57/−64 % | 93.0/93.3 % → **94.8 %** (+1.45/+1.74 pp) | ON 5/9 — new `memflat` and `onboard` FAILs → **criteria 1 and 3 fail** |

**Outcome: `CORR_AGGREGATION_PLANE` stays OFF by default** and opt-in behind
`deployment/docker/compose.agg.yml`. The reduction is real and the 25 % rung's
INCOMPLETE→PASS is the strongest single result of the programme; neither buys
past the neutrality guard, which is what the decision rule says. The wave's own
verdict recommends **one matched fresh-container OFF/ON pair at `t-storm-2.5k`
on the post-`2852ad6f` image** to settle whether the 2 % failures are the
plane's or the rig's (`P3_AB_2P5K_VERDICT` §3.6). Half of that pair now exists:
**storm-s04 is the fresh-container OFF baseline** (9/9, T1 p95 832 s, accuracy
94.49 %, memflat 79.5 % of cap).

The SLO question this raises — whether to promise a latency number at all, and
whether to state it per identity class (first occurrence vs repeat) relative to
burst end — was a product decision, and it has now been taken: **the ratified
storm-time SLO is the Option A statement in §8** (completion + losslessness +
memory + accuracy as the gate; T1 p95 published as a tracked indicator, not a
pass/fail contract). Read §8 for the statement itself and for why B was not
pursued and C is held contingent.

## 6. Defects found by the programme's own gauges (all filed)
177 T4 gap → closed by ground truth · 178 replay direction · 180 profiler
rejects windows · 181 shadow device rows · 183 benchmark fidelity · 184 parser
coverage · 185 storm batch-flush stall · 186 backfill worker · 187 chain
attribution; plus ClickHouse merge budget, system-log self-merge, pool
thresholds, harness producer loss, injector shortfall, memflat clause
semantics, run lock/namespace residue.

## 7. Remaining to close P4

**The measurement side of P4 is CLOSED.** Steps 1 and 2 of the original list are
DONE — the lifecycle work reached storm 9/9 (`storm-s04`, §3) and the P3 A/B ran
all five legs with the rule applied (§5) — and the owner SLO decision, which was
the last true blocker, was taken on 2026-08-30 (§8: Option A ratified). Nothing
in P4 is waiting on a measurement. What remains is execution:

1. **The matched fresh-container OFF/ON pair at `t-storm-2.5k`** — *pending owner
   approval; not scheduled.* This is the only thing that can move Option C from
   candidate to adoptable (`P3_AB_2P5K_VERDICT` §3.6). The OFF half already
   exists (storm-s04, 9/9 on the post-`2852ad6f` image), so one ON leg on fresh
   containers completes it and settles A/B criteria 1 and 3. Cost ~1.5 h, and it
   requires **two force-recreate arm switches** (OFF → ON to run the leg, ON →
   OFF to restore the shipping default). Do not run it without the owner's
   go-ahead.
2. **Tracker 185 residual, then one confirming `t-storm-2.5k`.**
   `reconcile.find_continuation` still blocks the event loop for 27.8 s (92.9 %
   of the worst stall); it no longer ejects the consumer only because the session
   timeout was widened 30 s → 60 s. Chunk-and-yield or offload that site, then
   run **one** `t-storm-2.5k` to confirm — sequenced **after** the matched pair
   so the pair is measured on the same image as its storm-s04 OFF half. This does
   not affect the ratified SLO: completion, accounting and accuracy are all
   unaffected by the stall.
3. **Tracker 190 — harness stability gate stale at 30,000 ms.** The gate was
   derived from the old 30 s Kafka session timeout, which is now 60 s, so it no
   longer measures what it names; storm-s04 PASSed it by **26 ms**, which is a
   coin-flip, not a margin. Raise or re-derive the threshold against the 60 s
   timeout (and state the derivation in the harness), independently of the 185
   fix that reduces the stall itself.
4. Trackers 186 (backfill watermark), 187 (chain attribution, blocked on 184)
   and 189 (retry contract for six more tables) remain open and out of P4's
   scope.

## 8. SLO decision (owner, 2026-08-30) — Option A adopted

### DECISION — RATIFIED 2026-08-30 (owner)

**The storm-time SLO is Option A, verbatim:**

> *Under a 15-minute 1,000-eps storm on 2,500 devices, the platform MUST
> evaluate the whole workload within 45 minutes of burst end, lose nothing
> (injected == persisted, 0 DLQ), stay within memory caps, and keep RCA accuracy
> ≥ 93 %. T1 p95 is measured and published every run but is not a pass/fail
> gate.*

This statement is **ratified** and is the SLO the product ships against. It is
the one option every clause of which is already met and already gated on the
current build (storm-s04: completion 144 s of a 2,700 s budget, accounting exact
900,001 == 900,001 with 0 DLQ, memflat 79.5 % of cap, accuracy 94.49 %).

**Option B is NOT pursued.** Its per-identity-class classifier (first occurrence
vs repeat) exists only *inside* the aggregation plane
(`corr_agg_forwarded_total{class}`), which is OFF by default — so on the shipping
configuration there is nothing to key the SLO on, and adopting B would mean
building an equivalent classifier on the OFF path. If Option C ever lands, that
classifier arrives with the plane and B becomes a **refinement of C** rather than
a project of its own; it is retired as an independent option.

**Option C remains a candidate, contingent** on the matched fresh-container
OFF/ON `t-storm-2.5k` pair (§7.1) clearing the 2 % neutrality guard. That pair is
**not yet approved to run** — it needs owner approval and two force-recreate arm
switches, and it is to be scheduled, not assumed. Until it clears, the
aggregation plane stays OFF by default and C is not adoptable.

### The options, kept for the record

The three options below are retained as the reasoning behind the decision above,
each derived from measurements in this document. **A is adopted; B is not
pursued; C is contingent.** All three assume the ratified rig: one 4-core box,
2,500 devices, 900k events in 15 minutes, single shard.

### Option A — Completion-and-losslessness is the SLO; T1 p95 is a tracked indicator — **ADOPTED**

**Statement.** *Under a 15-minute 1,000-eps storm on 2,500 devices, the platform
MUST evaluate the whole workload within 45 minutes of burst end, lose nothing
(injected == persisted, 0 DLQ), stay within memory caps, and keep RCA accuracy
≥ 93 %. T1 p95 is measured and published every run but is not a pass/fail gate.*

**Backing numbers.** Every gate in that sentence has been met on the current
build: storm-s04 completion **144 s** against a 2,700 s budget (19× margin),
accounting exact 900,001 == 900,001 + 0 DLQ, memflat 79.5 % of cap and falling,
accuracy **94.49 %**. It also survives the hard case: at the 25 % storm rung the
plane ON completed in **192 s** where OFF was INCOMPLETE.

**What it costs.** Nothing to implement — it is what the harness already gates.
The honest cost is that it declines to promise a latency number, and T1 p95 is
what an operator actually feels (832–1,203 s at the 2 % rung, 1,985–2,763 s at
10 %). Choosing A means saying openly that storm-time latency is a queueing
property of one shard, not a contract.

**Recommended, and ADOPTED (owner, 2026-08-30)** — a defensible SLO the
product can ship today.

### Option B — Per-identity-class, relative to burst end — **NOT PURSUED**

**Statement.** *Relative to the end of the burst: the FIRST occurrence of each
identity is correlated and persisted within 300 s p95; repeats within the same
identity within 900 s p95; the whole workload complete within 45 minutes. Stated
per class, never as one number.*

**Backing numbers.** This is the shape the data actually has. T1 p50 collapsed
to **68 s** on storm-s04 (from 383–460 s) while T1 p95 is 832 s and T-last p95
2,251 s — the median incident is fast and the tail is queue. The same split is
the clearest result of the A/B: at the 2 % rung the plane moved p50 **−57 to
−64 %** while moving p95 **+13 to +29 %**. A single-number SLO averages those
two opposite movements into noise; a per-class SLO reports them.

**What it costs.** Real work. TTUR is currently computed per *incident* from
`min(window_start)`, not per identity class — the classifier (first occurrence
vs repeat) exists inside the aggregation plane (`corr_agg_forwarded_total{class}`)
but is OFF by default, so on the shipping configuration there is nothing to key
the SLO on. Option B therefore implies either turning the plane on (see C) or
building an equivalent classifier on the OFF path, plus harness and dashboard
work. Budget it as a project, not a knob.

### Option C — Option A or B, with the aggregation plane ON at storm rungs — **CONTINGENT**

**Statement.** *As A or B, but `CORR_AGGREGATION_PLANE=1` for tenants whose storm
share exceeds ~10 %, with a tighter completion target (10 minutes after burst
end) justified by the measured reduction.*

**Backing numbers.** At 10 % the plane removes **41.0 %** of the signals reaching
the engine and improves every TTUR percentile (p95 **−28.2 %**, p50 −35.0 %,
p99 −27.4 %, T-last p95 −25.9 %) for **−0.40 pp** of accuracy. At 25 % it turns
an INCOMPLETE run into a **192 s** completion and moves accuracy **81 % → 89 %**.
Those are the two largest wins the programme produced.

**What it costs.** The neutrality guard has not been cleared: at the 2 % rung the
ON leg regressed T1 p95 by +13.1 %/+28.9 % against an OFF-vs-OFF spread of
13.11 %, and introduced `memflat` (96.2 % of cap) and `onboard` FAILs — on a leg
that was third in a row on one container and ran without `2852ad6f`. So C is
**not available today**: it requires the matched fresh-container pair of §7.2
first, and a per-tenant storm-share signal to switch on. If that pair clears the
guard, the decision rule already says default ON, and C becomes the strongest
option on the table.

### Summary

| option | promises | evidence today | cost | available now |
|---|---|---|---|---|
| **A** | completion + lossless + memory + accuracy ≥ 93 % | every clause met on storm-s04, and at the 25 % rung with the plane ON | none (already gated) | **yes** |
| **B** | per-class latency relative to burst end | p50 68 s vs p95 832 s vs T-last p95 2,251 s — the split is real and measured | new classifier on the OFF path + harness/dashboard work | no |
| **C** | A or B with a tighter target at storm rungs | −41 % signals / −28 % p95 at 10 %; INCOMPLETE → 192 s and 81 → 89 % at 25 % | one matched fresh-container pair, then per-tenant storm-share routing | not yet |

**Decision recorded:** **A** adopted and ratified 2026-08-30 (statement verbatim
at the top of this section). **B** not pursued — its classifier lives only inside
the plane, so it becomes a refinement of C if C lands. **C** still a candidate,
gated on the matched fresh-container pair of §7.1, which is not yet approved to
run.
