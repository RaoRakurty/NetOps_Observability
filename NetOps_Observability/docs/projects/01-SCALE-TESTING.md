# Project 1 — Scale Testing  🔴 HIGH PRIORITY

**Rewritten 2026-08-30 against HEAD (`71adcfc6`); refreshed 2026-08-31 after the
engine wave was validated on `storm-s07`.** Working checklist, not a history —
the history is in `docs/scale/` and `git log`.

**Scope.** Establish the **host ceiling** on the owner's box — max sustained
devices at nominal AND storm with all gates green — and the **binding resource**
at that ceiling. Output feeds (a) per-resource pricing standards and (b) the
customer hosting-requirement spec.

**Hardware under test:** 4 cores (Xeon E5-2683 v4 @ 2.1 GHz), 15 GiB RAM, 77 GB
disk. Owner constraint (2026-08-28): **no more hardware** — success is engine
efficiency + TTUR on this box; the P5 scale-out proof is **dropped**
(`docs/scale/P4_PROGRAMME_WRITEUP_2026-08-29.md` header).

**DONE means:** every rung of the ladder run to a graded verdict on this box,
the ceiling and binding resource written down as a deliverable doc (§D below),
and no open software defect that changes those numbers. Anything needing a
second box, an 8-core node or a real rig is **out of scope** (owner decision,
2026-08-31).

**Model rule:** Fable specs + grades; Opus implements every code change.

---

## Completed (evidence, not claims)

- **P0–P4 optimisation programme CLOSED**, measurement *and* execution —
  `docs/scale/P4_PROGRAMME_WRITEUP_2026-08-29.md` §7 (final 2026-08-30).
  T1 p95 fell 4,771 s → 1,947 s → 816 s across P1/P2/P3 (§2–§3 tables).
- **Storm-time SLO ratified (Option A, owner 2026-08-30)** — complete within
  45 min of burst end, lossless (injected == persisted, 0 DLQ), within memory
  caps, RCA accuracy ≥ 93 %; T1 p95 published but not a gate. P4 §8; recorded as
  an invariant in `docs/audit/INVARIANTS.md` §10; commit `237b1161`.
  Option B not pursued; **Option C adopted**.
- **Aggregation plane ON by default** — `a9d9a10c`
  (`deployment/docker/docker-compose.yml:1201`, image default stays OFF,
  `CORR_AGGREGATION_PLANE=0` in `.env` is the fallback). Decision trail:
  `docs/scale/P3_PAIR_2P5K_VERDICT_2026-08-30.md` §8 + P4 §8.
- **`t-storm-2.5k` 9/9 on both arms** — `storm-s05` (OFF control) and
  `storm-s06` (ON, the shipped default), same image `c3f627581082` / `0bfdce1c`:
  completion **95 s / 124 s** of a 2,700 s budget, accounting exact
  900,001 == 900,001 + 0 DLQ, memflat 83.2 % → 82.7 % of cap FLAT, accuracy
  **345/345** on scorer v2 both legs.
  `docs/scale/STORM_S05_S06_CLOSEOUT_2026-08-30.md`, commit `71adcfc6`.
- **Storm ladder A/B measured at 2 / 10 / 25 / 50 % storm share** — plane ON
  turns the 25 % rung from INCOMPLETE into a 192 s completion.
  `docs/scale/P3_AB_2P5K_VERDICT_2026-08-29.md`.
- **Engine wave VALIDATED on `storm-s07`** (`08310154mmk9`, ON, code `de8ca5b1`)
  — **8/9 gates**, accuracy **345/345**, accounting exact 900,001 == 900,001 + 0
  DLQ, completion **94 s** of 2,700 s. The one FAIL (`memflat`) is attributed
  with evidence to tracker **186** and a young api process, not to the wave.
  Full record: `docs/scale/PROJECT1_WAVE_VALIDATION_2026-08-31.md`.
  Nine tracker rows closed and deleted:

  | # | commit(s) | evidence on s07 |
  |---|---|---|
  | **190** | `0a4e57d2` | stability line now derives from the live gauge: session timeout **60,000 ms read from 2 replicas**, override `null`; worst stall 3,623 ms = 6.0 % |
  | **167** | `3001d440` + `9990adec` | counters registered and read live: **230,824 / 954,500 = 24.2 %** selectivity (19.8 % offline) |
  | **171** | `0a4e57d2` + s07 measure | `corr_prune_gap_max_s` **137.2 s** vs the 300 s epoch budget (45.7 %), **0** budget exits |
  | **192** | `79e27efc` + s07 | worst block NAMED `reconcile.continuation_index` **385.3 ms** under a 500 ms budget, **0** overruns; loop lag **13,881 → 4,278 ms** (residual = accumulation of spans, not a dark block) |
  | **187** | `de8ca5b1` + s07 | terminal shrink **526 → 0**, lost entity mentions **2,427 → 0**; history accumulator **16,622 / 20,000** cap = **83.1 %** → **ladder watch item** |
  | **164** | `9990adec` + s07 | bound present, never engaged: admission waits **0**, queue peak **4** against an inflight limit of **8** |
  | **181** | `b408cdbf` | 11 tests + the deployed binary; s07 onboard reports **0 absorbed shadow rows**, cleanup leaves 0 `mlx-` devices of ANY run id |
  | **157** | `39eba8c0` + s07 | role-grounding gate fired **35,940** times; `spine-leaf-path-degradation` top-hypothesis **589 → 0**, redistributed to `local-link-fault` **169 → 788**; accuracy **flat at 345/345** |
  | **175** | `8d0ba1e5` | live drain on a real store: **72,927 → exactly 10,000** tombstones (`DefaultTombstoneMax`) — the 5k/10k run-blocker is discharged |

  Whole-run health: TTUR p95 **908 s** vs s06's 816 s (**+11.3 %**, at the top of
  the six-leg 816–908 s envelope = noise, and p95 is published-not-gated); plane
  accounting exact (54,767 = 49,900 + 4,867); carrier correlation memory
  **×0.941, 79.1 % of cap — the first leg ever to fall below ×1.0**.
- **gNMI stretch DONE** — `ccfda64c`: the twin serves gNMI, so the
  `ENABLE_GNMI_COLLECTION` path has labelled-fault coverage end to end
  (digital-twin design §4.6).
- **5k/10k ladder profiles authored** — `63198dcd`
  (`t-nominal`/`t-storm` × 5k/10k in `SCALE_PROFILES`); not yet run.
- **Trackers closed today:** 185 + 191 (`0bfdce1c`, `06450430`, both evidenced in
  the close-out) and the 17 shipped rows pruned from `docs/TRACKER.md` in this
  commit — 156, 158, 159, 162, 163, 165, 166, 168, 169, 170, 172, 173, 174, 176,
  177, 179, 182. Carry-forwards: 179's step-3 VVR descope → P4 §7; 172's
  "unit-proven, dormant in production" → INVARIANTS §10.

---

## Open software work

| # | Item | Why it is here |
|---|------|----------------|
| **186** | Time-intelligence backfill query is **unbounded**, not merely un-incremental. On s07 it took **1.86 GiB / 35.4 GB read / 49.2 s** and was the named victim of a ClickHouse 4 GiB overcommit — evicting two background merges with it. 241/159 on **12 of 41 passes since 08-30 16:57**; read volume grows **~0.6 GiB per leg** with retention. | **The sole blocker to a 9/9 `t-storm-2.5k` leg on a cold api** — it causes both `memflat` clauses. Needs the watermark AND a per-query memory/read budget. |
| **194** | Watchdog cannot see an api-only outage: `:8000/` is answered by the SPA, `/healthz` has no nginx location and falls through to the SPA, the api container declares no healthcheck, and the one api-touching probe (`/admin/version`) is classified advisory. Observed blind for ~2 min on 2026-08-31 01:48–01:51. | Low. Honest probe = `/admin/version`, CRITICAL class, with a **~2.5 min** cold-boot grace. |

### Then the ladder (the ceiling itself)

1. **Run the 5k and 10k rungs.** Profiles exist (`63198dcd`); tracker 175 is
   discharged, so the tombstone debt is no longer a run-blocker. Carry the
   **187 watch item** into pre-flight: `corr_affected_history_entities_max` was
   **83.1 %** of its 20,000 cap at 2,500 devices, and the cap must be raised or
   made fleet-relative before a rung is graded if 5k crosses it.
2. **§D — grade and capture the ceiling** (the deliverable doc): per rung
   drain / `correlation_completion` / stability / memflat / accounting, plus
   correlation QUALITY under storm (did the flood collapse into the *right*
   incidents), then record max devices nominal & storm, the binding resource,
   and the per-device envelope → pricing + hosting spec.
3. **155 — partition-ownership correctness programme.** `931efffb` (durable
   continuation seeding on assignment) landed **after** s07, so it is committed
   but **UNVALIDATED**; the twin ownership runs
   (`scripts/lab/twin/ownership.py`, 21 tests, PASS/FAIL/**INVALID**) are the
   validation and are in flight.

## Finish

- [ ] Owner runs **`/code-review ultra`** on the branch.
