# Defect note — the api's unbounded in-memory metrics store (found s08, fixed `eb29c87a`, validated at deploy H / `storm-s09`)

**One-cycle defect record.** This defect never had a tracker row — it was found,
root-caused, fixed, deployed and validated inside a single session (2026-09-01) —
so per the tracker's ships-are-deleted rule this note is its record of existence.
It is referenced by `PROJECT1_DONE_2026-09-01.md` §2 and by the `storm-s08` row
of `HOST_CEILING_2026-08-31.md` §4.

## Found — `storm-s08` (`09010312jpiu`, 2026-09-01 03:12Z)

On an ordinary clean `t-storm-2.5k` run (image `d584f8aaab4d` / `1c402b5c`) the
api climbed to **100.0 % of its 565 MiB cap** — one burst from an OOM kill — and
its auth path timed out (`POST /api/auth/login` gave up after 5 attempts), which
failed the run's cleanup phase and the twin scorer's first attempt. memflat
FAILed on the cap-headroom clause; the run graded **6/9** with accuracy still
345/345 and accounting still exact. The TTUR excursion on the same leg
(T1 p95 **1,101 s**, the only reading ever outside the 816–912 s band; p50 110 vs
the usual 79–88) is owned by this defect, not the engine — incident count and
accuracy were flat.

## Root cause — `timeintel.MemMetricsStore.by`, proven live before restart

The in-memory backend the lab's file store selects retained **every** snapshot
the backfill catch-up folded, with no eviction of any kind:

- `/proc/<pid>`: VmRSS 543 MiB, VmHWM 585 MiB, VmData 949 MiB; smaps_rollup
  anonymous 522 MiB + SwapPss 256 MiB ≈ **778 MiB** of anonymous memory.
- The api's own pass logs since its 00:31Z recreate: **13 passes, 259,999 rows
  written** — all resident in the map.
- Arithmetic: ~3 KB/row on the Go heap × 260k rows ≈ **780 MB predicted.
  Expected equals measured; no other owner needed.**
- The 30-day window held 918,294 `corr_current` objects with the cursor at
  2026-08-28 and `caught_up=false` — full catch-up would have needed **~2.7 GiB.
  The breach was guaranteed, not incidental.**
- Cascade: once at cap and swapping, every ClickHouse fetch timed out
  client-side and logins timed out — the auth-latency-first failure mode the 10k
  rung had already documented, reproduced at 1× load by a leak instead of
  overload.

## Fix — `eb29c87a` (deploy H, api image `eefcc527730a`, started 07:00:12Z)

The bound is derived from what the READS can return, so eviction never changes
an answer: `MemRowCapPerTenant = SnapshotCap` (20,000 — the snapshots handler
clamps List to it and the rollups call ListWindow with exactly it),
`MemRetention = 366 d` (rollup handlers clamp `since` ≤ 365 d), amortized
compaction (hysteresis slack 1,024), per-tenant eviction (§3a — one tenant's
overflow can never touch another's rows), observable via `Evicted()`. Upsert
stays a pure PK overwrite, so the fold's idempotency is untouched; the PG
backend was never affected. Tests: `timeintel/metrics_store_bounds_test.go`
(bound, eviction order, idempotent re-fold, retention-first eviction, per-tenant
isolation; removing the eviction fails the fold test).

## Validated — deploy H, then `storm-s09`

- **The plateau is real:** across three consecutive 20k-row backfill passes the
  api grew **+91 / +24 / +6.7 MiB**, settling at **~155 MiB = 27 % of cap** —
  a converging series where the old store added ~60 MiB per pass forever. At
  close-out the live api reads 142 MiB (25.2 %) with a 19,419-row pass completed
  minutes earlier.
- **Side effect:** pass throughput recovered (the store no longer swaps mid-pass).
- **Rig-level proof:** `storm-s09` (`09010750fq0u`) passes `memflat` with the api
  at **198 MiB end = 33.4 % of cap, ×1.035 vs the warm anchor** — inside every
  clause — as part of the first-ever 2,500-device memflat PASS.
