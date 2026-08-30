# Project 1 — Scale Testing  🔴 HIGH PRIORITY

**Rewritten 2026-08-30 against HEAD (`71adcfc6`).** Working checklist, not a
history — the history is in `docs/scale/` and `git log`.

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
- **Trackers closed today:** 185 + 191 (`0bfdce1c`, `06450430`, both evidenced in
  the close-out) and the 17 shipped rows pruned from `docs/TRACKER.md` in this
  commit — 156, 158, 159, 162, 163, 165, 166, 168, 169, 170, 172, 173, 174, 176,
  177, 179, 182. Carry-forwards: 179's step-3 VVR descope → P4 §7; 172's
  "unit-proven, dormant in production" → INVARIANTS §10.

---

## Open software work (buildable on this box, in order)

| # | Item | Why it is here |
|---|------|----------------|
| **190** | Harness `stability` gate hard-codes 30,000 ms while the engine runs a 60 s session timeout — read the live timeout, state the derivation. | Low; ~4 s stalls leave it no room to bite, but the gate is wrong. Close-out §6.3. |
| **167** | Live selectivity of the template index is still UNVALIDATED — needs one 1K run at `--event-mix realistic` (the harness gap is closed; the run never happened). | The only thing between 167 PASS-offline and PASS-live. Expect worse than 22 %; that is the honest number. |
| **171** | No gauge publishes the prune-starvation interval; the P2 epoch wall-time budget (`CORR_ENGINE_EPOCH_BUDGET_S`) plausibly bounds it but that is **unverified on the current build**. | Add the gauge, re-measure, then close or fix. |
| **192** | Un-instrumented ~9–14 s loop block on the cleanup / re-key path (`corr_loop_lag_max_ms` 9,134.9 / 13,881.1 ms, outside the stability window, no `sync_span` attributed). | Distinct from 185. Add the span, bound it `0bfdce1c`-style, confirm on one `t-storm-2.5k`. |
| **187** | An object's final `affected` shrinks below its own version history at CLOSE (3–5 `bgp_peer_flap` stories per 1,005-story leg, same ids on both arms). | The named residue behind "100.00 %". Decide: fix the close path, or read the accuracy clause over versions. |
| **164** | `_offload` uses the default executor — bounded workers, **unbounded** queue. | §9 boundedness defect; not the bottleneck, but pre-GA hardening. |
| **181** | Device create absorbed by dedupe persists a SHADOW row (`main.go:2368` Upsert before `ResolveIdentity`). | Left 1,000 shadow devices from overlapping runs; needs an isolation-aware fix + `org_isolation_test.go`-shaped test. |
| **157** | `spine-leaf-path-degradation` ranks confidence 1.0 in a topology with no spine — token co-occurrence, not structure. | Accuracy class, measured + evidenced, not started. |

### Then the ladder (the ceiling itself)

1. **Author + run 5k and 10k profiles** (`t-nominal-5k` / `s1-5k`,
   `t-nominal-10k` / `s1-10k`) — none exist in `SCALE_PROFILES` today.
   **First** discharge tracker **175** (device-store tombstone growth, file
   backend: 35,427 tombstones / 142 MB for 0 real devices; row status verified
   today = `Med · ⏳ follow-up, not started`). At 5k/10k the per-run churn is
   2–4× today's, so the tombstone debt is a run-blocker before it is a defect.
2. **§D — grade and capture the ceiling** (the deliverable doc): per rung
   drain / `correlation_completion` / stability / memflat / accounting, plus
   correlation QUALITY under storm (did the flood collapse into the *right*
   incidents), then record max devices nominal & storm, the binding resource,
   and the per-device envelope → pricing + hosting spec.
3. **155 — partition-ownership correctness programme.** Harness built
   (`scripts/lab/twin/ownership.py`, 21 tests, PASS/FAIL/**INVALID**); the
   ownership-move runs are buildable now — validation is the twin ownership
   runs on this box.
4. **gNMI stretch** (digital twin, design §4.6) — the twin serves gNMI so the
   `ENABLE_GNMI_COLLECTION` path gets labelled-fault coverage end-to-end.

## Finish

- [ ] Owner runs **`/code-review ultra`** on the branch.
