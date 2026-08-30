# P4 — Storm-time RCA optimisation programme: consolidated measurement (draft, 2026-08-29)

Owner constraint (2026-08-28): no more hardware; success = engine efficiency +
TTUR SLOs on the existing 4-core box. P5 (scale-out proof) dropped. Authority:
owner memo `/var/tmp/Correlix-Bottleneck-Modified.md`; every number below is
from a dated verdict doc in `docs/scale/` with the SQL/method stated there.
**FINAL — 2026-08-30. PROGRAMME CLOSED, measurement and execution both.** The
lifecycle fix and the P3 A/B are measured and recorded below; the owner ratified
the storm-time SLO (§8, Option A); the matched OFF/ON pair ran and was graded;
trackers 185 and 191 are closed; and **Option C was adopted — the aggregation
plane is ON by default as of 2026-08-30 20:31Z** (`a9d9a10c`), confirmed on a
live `t-storm-2.5k` run at 9/9. §7 lists what is open; §8 records the decision.
**Sections 2, 3 and 5 quote accuracy as measured at the time, on the v1 scorer —
see §7's closing note and §8 for the v2 re-score.**

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

> **SUPERSEDED 2026-08-30 20:31Z.** The outcome recorded in this section is the
> ladder wave's, on the v1 scorer. The matched fresh-container pair was
> subsequently run, the accuracy instrument it indicted was fixed (tracker 191)
> and the legs re-scored, and all three §7 criteria then held: the plane is now
> **ON by default** (`a9d9a10c`, `docker-compose.yml:1201`). See §8 and
> `STORM_S05_S06_CLOSEOUT_2026-08-30.md`. The measurements below are unchanged.

**Outcome at the time of the wave: `CORR_AGGREGATION_PLANE` stays OFF by
default** and opt-in behind `deployment/docker/compose.agg.yml`. The reduction is real and the 25 % rung's
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

**P4 is CLOSED — measurement and execution both.** The measurement side closed
on 2026-08-30 (the lifecycle work reached storm 9/9, the P3 A/B ran all five
legs, the owner ratified the SLO in §8). The execution side closed the same day:
the matched fresh-container pair ran and was graded, the instrument defect it
exposed was fixed, the engine residual it inherited was bounded, and the
aggregation plane was flipped to ON by default and confirmed on a live run.

**What P4 executed after the pair (all committed, all measured):**

1. **Tracker 191 — twin scorer `affected_includes` tie-break. CLOSED**
   (`06450430`). The clause is now evaluated over the **union** of the objects
   touching the story and `best` is deterministic on
   `(tier, node_count, confidence, correlation_id)`; reports carry
   `scorer_version: 2`. All 10 surviving legs were re-scored from resident
   `corr_objects` at zero rig cost. Every 345-story leg now scores **345/345 =
   100.00 %** with a spread of **0.00 pp**, where the v1 coin flip produced
   93.04 % ± 0.71 pp.
   Confirmed on **live** runs (`storm-s05` / `storm-s06`, both
   `scorer_version: 2`, both 345/345).
2. **Tracker 185 — `reconcile.find_continuation` loop block. CLOSED**
   (`0bfdce1c`). The seam bridge re-derived per candidate pair; it is now cached
   and per-inventory, with Jaccard computed without a union set. Fixture:
   sync span **13,787 ms → 46.8 ms (294×)**, signal touches 42,573,150 → 94,500.
   Live: `corr_sync_stretch_max_ms` **443.5 ms** (s05) / **401.1 ms** (s06) with
   **0** overruns on both, and the worst site moved off
   `reconcile.find_continuation` to `lifecycle.merge_index`. Worst in-window loop
   stall fell 29,974 ms (s04) → **4,122 / 4,450 ms**.
3. **`CORR_AGGREGATION_PLANE` default ON — DECIDED, DEPLOYED, CONFIRMED**
   (`a9d9a10c`, 20:31Z). §7 of `RUN_PLAN_P3_AB_2026-08-29.md` re-applied on the
   v2 numbers: **criteria 1, 2 and 3 all hold**. See §8 and
   `P3_PAIR_2P5K_VERDICT_2026-08-30.md` §8. Confirmed by `storm-s06`
   (`t-storm-2.5k` **9/9** on the shipped default).

**What is actually open, and none of it blocks P4:**

| # | item | pri | why it is not a P4 blocker |
|---|---|---|---|
| **187** | Cause device dropped from `affected` when the object CLOSES — 3–5 `bgp_peer_flap` stories per 1,005-story leg, the **same story ids on both arms**, so arm-independent engine behaviour. Its original premise (the engine omits the cause) was falsified by the pair and by the v2 re-score; what remains is a **close-time shrink** of an object's final `affected` below its own version history. | Med | This is the honest remaining **accuracy** defect. It does not move any P4 verdict — every P4 leg's accuracy is reported on scorer v2 and the arms are equal — but it is the reason "100.00 %" must not be read as "attribution is perfect". |
| **190** | Harness `stability` gate still derived from a hard-coded 30,000 ms while the engine runs a 60 s session timeout. | Low | With worst in-window stalls now ~4 s (s05/s06) the stale gate no longer bites. It is still wrong and should be re-derived from the live timeout. |
| **192** | Un-instrumented ~9–14 s loop block on the cleanup / re-key path — process-lifetime `corr_loop_lag_max_ms` **9,134.9 ms** (s05) / **13,881.1 ms** (s06), outside the stability window, no `sync_span` site attributed. | Med | Distinct from 185, whose site is bounded and proven bounded. Needs a `sync_span` and a bound in the `0bfdce1c` style. |
| **193** | No `.dockerignore` at the repository root while eight services build with `context: ../..` over a 16 GB tree. | Low | Benign today (narrow `COPY`s); wasted transfer, cache-busting, latent leak risk. |
| **186 / 189** | Backfill watermark; retry contract for six more correlation-written tables. | High / Med | Outside P4's scope, unchanged. |

**Still unmeasured, and stated:** the plane's `contradiction`, `new_vantage` and
`new_modality` classes have **never fired** on any leg — the harness stamps
`observer_id` from the event's own device, so every `AggKey` has exactly one
possible observer and one modality. The plane's behaviour under multi-vantage or
multi-modality telemetry is unmeasured; closing that needs a workload with a
second independent vantage per entity (harness work, adjacent to tracker 183).

**A note on every accuracy figure in this document.** §2, §3 and §5 quote the
scores as they were measured at the time, on the **v1** scorer. Those numbers
were produced by an instrument that decided one clause by a correlation-UUID
coin flip (tracker 191). Re-scored on **v2**, every 345-story storm leg is
**345/345 = 100.00 %** and the 1,005/1,773-story ladder legs are 1002/1005,
1000/1005, 1772/1773 and 1770/1773. Read the v1 figures as historical, and the
v2 figures as the current instrument's — with tracker 187 as the named,
measured residue that v2's union-over-objects reading does not catch.

## 8. SLO decision (owner, 2026-08-30) — Option A adopted; Option C adopted 20:31Z

### DECISION — RATIFIED 2026-08-30 (owner)

**The storm-time SLO is Option A, verbatim:**

> *Under a 15-minute 1,000-eps storm on 2,500 devices, the platform MUST
> evaluate the whole workload within 45 minutes of burst end, lose nothing
> (injected == persisted, 0 DLQ), stay within memory caps, and keep RCA accuracy
> ≥ 93 %. T1 p95 is measured and published every run but is not a pass/fail
> gate.*

This statement is **ratified, unchanged, and remains the SLO the product ships
against** — the Option C adoption below changed the *configuration* the SLO is
measured on, not a word of the SLO itself. It is the one option every clause of
which is already met and already gated on the current build.

**Met on the OFF configuration** (storm-s04): completion 144 s of a 2,700 s
budget, accounting exact 900,001 == 900,001 with 0 DLQ, memflat 79.5 % of cap,
accuracy 94.49 % (v1 scorer; **345/345 = 100.00 %** re-scored on v2).

**Met on the shipped ON configuration** (`storm-s06`, `t-storm-2.5k` **9/9**,
image `c3f627581082` / `0bfdce1c`, plane ON as the compose default): completion
**124 s** of the 2,700 s budget, accounting exact **900,001 == 900,001 + 0 DLQ**,
memflat **82.7 % of cap, ×1.021 FLAT**, accuracy **345/345 = 100.00 %** on
`scorer_version: 2`. Its matched OFF control `storm-s05` is 9/9 and 345/345 too.
`STORM_S05_S06_CLOSEOUT_2026-08-30.md`.

**Every accuracy number quoted in this section is scorer v2 unless marked v1.**
On v2 the storm corpus scores ~100 % and the arms are exactly equal. That is a
statement about the *corrected clause*, not about attribution being perfect: the
honest remaining accuracy defect is **tracker 187** — an object's final
`affected` shrinking below its own version history when it CLOSES (3–5
`bgp_peer_flap` stories per 1,005-story leg, the same story ids on both arms,
arm-independent). v2's union is over *objects*, not over *versions*, so it does
not catch 187. The `accuracy ≥ 93 %` clause must therefore be read as
"≥ 93 % on the v2 instrument, with 187 open".

**Option B is NOT pursued.** Its per-identity-class classifier (first occurrence
vs repeat) exists only *inside* the aggregation plane
(`corr_agg_forwarded_total{class}`). When B was declined the plane was OFF by
default, so there was nothing on the shipping configuration to key the SLO on.
**That premise has now changed** — with C adopted, the classifier ships and is
live (`storm-s06`: `first` 41,928 · `state_transition` 3,223 · `recovery` 4,708 ·
`count_threshold` 22 · `repeat` 32). B is still not pursued: it was retired as an
independent option and becomes a **refinement of C**, and taking it would need
TTUR keyed per identity class rather than per incident, plus harness and
dashboard work. It is available to revisit, not scheduled.

**Option C is ADOPTED — per its own stated contingency, which has been
discharged.** C was recorded as *"blocked on tracker 191 + a re-score of the
three resident legs, not on another leg"*, with the disposition *"if the
re-score confirms the counterfactual, the decision rule's own text — 'If both
hold, criteria 1+2+3 hold and the rule says default ON' — becomes live."* The
re-score was performed and **confirmed the counterfactual exactly**:

| §7 criterion | result on scorer v2 | numbers |
|---|---|---|
| **1 — neutrality guard** | **PASS** | All four TTUR clauses inside ±10 % against **both** OFF points (T1 p95 **−7.98 %** vs P1, **−0.24 %** vs s04; p50 0.00 %; p99 −1.30 %; T-last p95 −4.59 %); accuracy **100.00 % → 100.00 %, Δ 0.00 pp** against a −1.00 pp floor |
| **2 — the 10 % rung earns it** | **MET** | **−41.0 %** signals reaching the engine (98,636 → 58,194), T1 p95 −28.2 %, p50 −35.0 %, p99 −27.4 %, T-last p95 −25.9 %; re-scored accuracy **Δ −0.20 pp** (L1 1002/1005 → L3 1000/1005). Qualification retained: the engine-side secondary measure was −19.2 %, just under the bar |
| **3 — no new gate FAIL** | **PASS** | 0 phases PASS→FAIL on the pair; `memflat` and `cleanup` went FAIL→PASS; `stability` pre-existing on both (tracker 190's stale gate), 0 ejections either side. On the s05/s06 confirmation pair: **9/9 on both arms** |

**Executed 2026-08-30 20:31Z, committed `a9d9a10c`:**
`deployment/docker/docker-compose.yml:1201` now reads
`CORR_AGGREGATION_PLANE: ${CORR_AGGREGATION_PLANE:-1}`. The **image default
stays OFF** (`src/correlation/main.py`) so the A/B overlay contract still holds;
the fallback is `CORR_AGGREGATION_PLANE=0` in `deployment/docker/.env`. Both
replicas verified at deploy (env `=1`, `corr_agg_enabled 1`). Confirmed by
`storm-s06`, the first `t-storm-2.5k` on the shipped default: **9/9**.

**What was adopted, precisely, and what was not.** C's statement had two halves.
The **plane half is adopted, and adopted more broadly than C proposed**: rather
than routing per tenant above a ~10 % storm share, the plane is ON for every
tenant by default, because the matched 2 % neutrality pair showed it costs
nothing at the low rung (T1 p95 −7.98 %, accuracy Δ 0.00 pp, `memflat`
FAIL→PASS) — so there is no rung at which it needs to be withheld. That also
**removes the per-tenant storm-share routing signal from the critical path**; it
is no longer a prerequisite for anything. The **tighter-completion-target half
is NOT adopted**: the SLO statement above is unchanged, still 45 minutes, still
Option A's wording. Nothing about the SLO was renegotiated on the strength of
the plane's gains — they show up as margin, not as a tighter promise.

### The options, kept for the record

The three options below are retained as the reasoning behind the decision above,
each derived from measurements in this document. **A is adopted; B is not
pursued; C is ADOPTED (2026-08-30 20:31Z).** All three assume the ratified rig:
one 4-core box, 2,500 devices, 900k events in 15 minutes, single shard.

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

### Option C — Option A or B, with the aggregation plane ON at storm rungs — **ADOPTED 2026-08-30 20:31Z**

**Statement.** *As A or B, but `CORR_AGGREGATION_PLANE=1` for tenants whose storm
share exceeds ~10 %, with a tighter completion target (10 minutes after burst
end) justified by the measured reduction.*

**Backing numbers.** At 10 % the plane removes **41.0 %** of the signals reaching
the engine and improves every TTUR percentile (p95 **−28.2 %**, p50 −35.0 %,
p99 −27.4 %, T-last p95 −25.9 %) for **−0.40 pp** of accuracy. At 25 % it turns
an INCOMPLETE run into a **192 s** completion and moves accuracy **81 % → 89 %**.
Those are the two largest wins the programme produced.

**What it cost, and how the guard was cleared.** L5's regression (T1 p95
+13.1 %/+28.9 %, `memflat` at 96.2 % of cap, an `onboard` FAIL) was measured on
a leg that was third in a row on one container and ran without `2852ad6f`. The
matched pair of §7 removed those confounds and **reversed the TTUR result**:
T1 p95 **−7.98 %** vs its matched OFF leg and **−0.24 %** vs storm-s04,
`memflat` **PASS** (83.4 % of cap vs the OFF leg's failing 85.4 %), `onboard`
PASS 0.66, criterion 3 clean. Criterion 1 then failed on **one clause only —
accuracy, −1.74 pp** — measured by an instrument the same pair proved defective.
That instrument was fixed (**tracker 191**, `06450430`) and the three legs were
re-scored from resident `corr_objects` at zero rig cost: **P1 100.00 %,
P2 100.00 %, s04 100.00 %, Δ 0.00 pp.** Criterion 1 passes on every clause;
criteria 2 and 3 were already met; **the rule says default ON, and it was
executed** (`a9d9a10c`, 20:31Z) and confirmed on a live `t-storm-2.5k` run of
the shipped default (`storm-s06`, 9/9). At 2 % the plane also removed **7.6 %**
of the signals reaching the engine (8.87 % suppressed on the pair, 8.86 % on
s06) where §6b projected 0 % — the projection understates the low rung.

**Adopted broader than proposed, and only in part.** The plane is ON for **every
tenant**, not only those above a ~10 % storm share, because the 2 % neutrality
pair showed it costs nothing at the low rung — so the **per-tenant storm-share
routing signal is no longer needed** and is off the critical path. The **tighter
completion target is NOT adopted**: the SLO stays Option A's 45 minutes, and the
plane's gains are recorded as margin rather than as a tighter promise.

**Still unmeasured, and stated:** the plane's `contradiction` / `new_vantage` /
`new_modality` classes have **never been exercised** (all forwarded 0 on every
leg including `storm-s06` — the harness gives every entity a single observer and
a single modality), so the shipped configuration's behaviour under multi-vantage
or multi-modality telemetry is unmeasured. Closing that needs a workload with a
second independent vantage per entity (harness work, adjacent to tracker 183).

### Summary

| option | promises | evidence today | cost | available now |
|---|---|---|---|---|
| **A** | completion + lossless + memory + accuracy ≥ 93 % | every clause met on storm-s04 (OFF) **and on `storm-s06` (ON, the shipped default): 9/9, completion 124 s, exact accounting, memflat 82.7 % FLAT, accuracy 345/345 on scorer v2** | none (already gated) | **yes — ADOPTED** |
| **B** | per-class latency relative to burst end | p50 68 s vs p95 832 s vs T-last p95 2,251 s — the split is real and measured; the class classifier now **ships with C** (`storm-s06`: first 41,928 / state_transition 3,223 / recovery 4,708 / count_threshold 22 / repeat 32) | TTUR keyed per identity class + harness/dashboard work | not pursued — a refinement of C, available to revisit |
| **C** | the plane ON at storm rungs (adopted for **all** tenants; the tighter completion target was **not** taken) | −41 % signals / −28 % p95 at 10 %; INCOMPLETE → 192 s and 81 → 89 % at 25 %; **matched 2 % pair re-scored on scorer v2: criteria 1, 2 and 3 ALL hold — TTUR within ±10 % on every clause, accuracy Δ 0.00 pp**; confirmed live by `storm-s06` 9/9 | already paid: tracker 191 (`06450430`) + tracker 185 (`0bfdce1c`) + the flip (`a9d9a10c`) | **yes — ADOPTED, DEPLOYED 20:31Z** |

**Decision recorded:** **A** adopted and ratified 2026-08-30 — the statement
verbatim at the top of this section is unchanged and is what the product ships
against. **B** not pursued; its classifier now ships with C, so it is a
refinement rather than a project, available to revisit. **C** **ADOPTED
2026-08-30 20:31Z** (`a9d9a10c`): the matched fresh-container pair ran, its one
failing clause was traced to the instrument, the instrument was fixed
(tracker 191) and the legs were re-scored — criteria 1, 2 and 3 all hold, so
`CORR_AGGREGATION_PLANE` is **ON by default in `docker-compose.yml`** (image
default still OFF; `CORR_AGGREGATION_PLANE=0` in `.env` to fall back), confirmed
by `storm-s06` at 9/9.

**A's accuracy clause, re-baselined (the caveat is now discharged — and
replaced).** Option A gates on *"RCA accuracy ≥ 93 %"*. On the **v1** scorer that
clause was near-worthless: 35 of the 345 stories were decided by a
correlation-UUID coin flip, giving an expected 93.04 % with 1σ = 0.71 pp, so the
threshold sat at the noise distribution's own mean and the three pair legs
(94.20 / 92.46 / 94.49 %) were all inside a 2σ band of pure chance, with P2
*below* the ratified floor. On the **v2** scorer (tracker 191, `06450430`) that
noise is gone: every 345-story leg — P1, P2, s04, L5, s02, s03 and now
`storm-s05` and `storm-s06` — scores **345/345 = 100.00 %**, spread **0.00 pp**. The 93 % clause is now
comfortably clear of the instrument's noise and is a real gate again. The SLO
statement is not reopened.

**What replaces it is a smaller, honest defect: tracker 187.** The v2 clause
reads `affected_includes` as a union over the objects touching a story — not
over an object's *versions*. Measured across 10 legs, 3–5 `bgp_peer_flap`
stories per 1,005-story leg have an object whose versions 1–4 (`open`) name the
cause device and whose final `closed` version drops it; the scorer judges the
current version, so the attribution is lost at CLOSE. The same story ids fail on
both arms, so it is arm-independent engine behaviour, not variance, and it is
invisible to the 345-story storm corpus. **"100.00 %" means "the corrected
clause passes", not "attribution is perfect"** — 187 is the named residue, and
it is the honest remaining accuracy defect on the shipped build.
