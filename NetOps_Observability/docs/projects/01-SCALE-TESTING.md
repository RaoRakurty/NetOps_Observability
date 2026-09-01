# Project 1 — Scale Testing  ✅ **DONE 2026-09-01**

**Completion record: `docs/scale/PROJECT1_DONE_2026-09-01.md`** — the DONE
definition graded criterion by criterion, the SLO scorecard with `storm-s09` as
the leg of record, the full rung ladder, and the closure records for trackers
186 and 199. This checklist is retained as the project's map; nothing on it is
open.

**Scope (as ratified).** Establish the **host ceiling** on the owner's box — max
sustained devices at nominal AND storm with all gates green — and the **binding
resource** at that ceiling. Output feeds (a) per-resource pricing standards and
(b) the customer hosting-requirement spec.

**Hardware under test:** 4 cores (Xeon E5-2683 v4 @ 2.1 GHz), 15 GiB RAM, 77 GB
disk. Owner constraint (2026-08-28): no more hardware; P5 scale-out dropped.

**DONE meant:** every rung of the ladder run to a graded verdict on this box,
the ceiling and binding resource written down as a deliverable doc, and no open
software defect that changes those numbers. **All three criteria are met** —
the grading is `PROJECT1_DONE_2026-09-01.md` §1.

**Model rule (held throughout):** Fable specs + grades; Opus implements.

---

## Formal closure (owner, 2026-09-01)

```
PROJECT 1 — SCALE PROGRAMME
STATUS: COMPLETE
DATE: 2026-09-01
```

*Post-closure note (2026-09-01 late): the ultra-review fix wave was deployed (correlation `23dc2b88e966`, api `f6c67a4d0195`, HEAD `0f8ea9d4`) and re-qualified — `storm-s11` (`090121382mk4`) scored the programme's **first 9/9** and is now the `CORRELIX_REFERENCE_CAPACITY_V1` baseline run of record, superseding s09 (kept as the pre-fix-wave baseline).*

**Closing conclusion.** The single-reference-host envelope is **measured, not
estimated**. The platform meets the ratified Option A SLO at 2,500 devices /
~1,000 eps with lossless ingestion, bounded memory, full completion, and
qualifying RCA accuracy. Behaviour beyond the envelope is characterized —
queueing and recall degradation, never loss, never false attribution. **Further
synthetic capacity expansion is deferred until customer requirements justify
it.**

### FREEZE (owner, 2026-09-01) — none of the following without a real customer requirement that justifies it

- No 5K/10K-specific optimization.
- No topology sharding now.
- No Go/Rust rewrite (of the correlation engine) for capacity.
- No hardware acquisition for benchmarks.
- No SLO capacity inflation.
- No endless device ladder.

### Engineering resource shift (owner guidance, not rigid)

- **≈ 50 %** — UI / demo / operator experience
- **≈ 20 %** — deployment / onboarding
- **≈ 15 %** — integrations
- **≈ 10 %** — hardening / security
- **≈ 5 %** — reference benchmark regression (tracker 203 / `CORRELIX_REFERENCE_CAPACITY_V1.md`)

---

## Completed (evidence, not claims)

- **P0–P4 optimisation programme CLOSED** — T1 p95 4,771 → 1,947 → 816 s across
  P1/P2/P3 (`P4_PROGRAMME_WRITEUP_2026-08-29.md` §2–§3).
- **Storm-time SLO ratified (Option A, owner 2026-08-30, `237b1161`)** and — at
  close-out — **met on every clause on the leg of record**: `storm-s09`
  completion 93.7 s, lossless exact, **memflat PASS (first ever at 2,500
  devices)**, accuracy 345/345; T1 p95 912 s published. Recorded in
  `docs/audit/INVARIANTS.md` §10.
- **Aggregation plane ON by default** (`a9d9a10c`); neutrality proven at 2 %,
  −41 % signals at 10 %, INCOMPLETE→192 s at 25 %
  (`P3_AB_2P5K_VERDICT_2026-08-29.md`, `P3_PAIR_2P5K_VERDICT_2026-08-30.md` §8,
  `STORM_S05_S06_CLOSEOUT_2026-08-30.md`).
- **`t-storm-2.5k` 9/9 on both arms** — `storm-s05` / `storm-s06`
  (`STORM_S05_S06_CLOSEOUT_2026-08-30.md`).
- **Engine wave VALIDATED on `storm-s07`** — nine tracker rows closed on its
  measurements (`PROJECT1_WAVE_VALIDATION_2026-08-31.md`).
- **Tracker 155 CLOSED — identity survives operations.** Four-run arc 155a→155d;
  positive pass 1.00/1.00 on both disturbed arms, v1–v10 gapless across the
  handoff, 0 duplicate versions, flush 210–652 ms
  (`OWNERSHIP_155_VALIDATION_2026-08-31.md`).
- **Tracker 186 CLOSED** — the backfill worker bounded end to end (watermark +
  splitter `9ed38cbb`, 512 MiB budget made effective `cfd7ebdc`,
  irreducible-only skips `e86ec6aa`, like-units exemption `22bdaeb1`); the gate
  it blocked passes on s09. Closure record: `PROJECT1_DONE_2026-09-01.md` §3.
- **Tracker 199 CLOSED** — graceful-shutdown handoff flush (`36036db5`),
  mutation-verified tests, validated live at deploy G. Record: DONE doc §4.
- **The api `MemMetricsStore` defect** — found by `storm-s08`'s memflat gate,
  fixed `eb29c87a`, deploy-H plateau +91/+24/+6.7 MiB → ~155 MiB = 27 % of cap,
  proven by s09 (`API_MEMSTORE_DEFECT_2026-09-01.md`). Never needed a tracker
  row: found→fixed→validated in one cycle.
- **The ladder is complete and graded** — 3,500-device isolating rung (7/9,
  engine clean, 483/483, fleet axis does not bind), 5k nominal + 5k storm (the
  wall, bracketed to (3,500, 5,000] at storm density), 10k documentation rung
  (the saturation-cascade order; ingest lossless at 4×; tracker 189's first
  live evidence). `HOST_CEILING_2026-08-31.md` §4.
- **§D deliverable FINAL: `HOST_CEILING_2026-08-31.md`** — two-axis envelope
  (≤ ~1,000 eps; 2,500 @ 0.4 eps/device planning number, stretching to ~3,500 @
  ~0.29), binding-resource ranking, degradation shape (queueing, never loss),
  per-device envelope + pricing feed.
- **gNMI stretch DONE** (`ccfda64c`); **5k/10k profiles** (`63198dcd`);
  **watchdog api liveness** (tracker 194, `61974003`); twin scorer v2
  (`06450430`) with 4,278/4,278 labelled stories at 100 % at or below the
  ceiling.

## Open

**Nothing — for this project.** The residual rows in `docs/TRACKER.md` — 189,
195, 196, 197, 198, and the close-out filings 200 (latent alias ORDER-BY
sites), 201 (undetermined-frequency query cost), 202 (onboard ratio clause) —
are **platform-backlog items, not Project-1 work**: cost, robustness and
harness refinements whose rows each state what they cost. None changes a
ceiling number or invalidates a graded verdict (DONE doc §1 criterion 3, §8).

## Finish

- [x] Project DONE — 2026-09-01.
- [ ] Owner runs **`/code-review ultra`** on the branch — **launching now** as
  the finish line.
