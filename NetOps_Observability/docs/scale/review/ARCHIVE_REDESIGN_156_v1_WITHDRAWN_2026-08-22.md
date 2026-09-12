# [WITHDRAWN] Archive persistence redesign v1 — two-layer archive

> **STATUS: WITHDRAWN 2026-08-22, same day it was written.** Both adversarial
> peer reviews rejected Layer 2 (see `ARCHIVE_V1_CORRECTNESS_REVIEW` and
> `ARCHIVE_V1_STORAGE_REVIEW` in this directory). The shipped design is v2 —
> `../ARCHIVE_REDESIGN_156_2026-08-22.md` (component-only slice). This file
> preserves v1 verbatim because v2 §9's revival conditions reference it and
> because the review findings are unintelligible without the text they attack.
> Do NOT implement anything below.

---

# Archive persistence redesign — slice sized by the object, context shared per epoch

**Date:** 2026-08-22 · **Status: DESIGN — approved direction from the pre-GA
architecture review (§18.1), not yet implemented.**
**Fixes:** tracker 156 residual = tracker 166's measured blocker.
**Charter constraints honoured:** replay exactness per object version is a
product contract and is preserved BYTE-IDENTICALLY; 165/168/170 untouched.

---

## 1. The defect, restated from measurement

`_persist_snapshot` stage [8] writes, per persisted object VERSION, an archive
slice whose membership rule is *"every node whose activity interval overlaps
the object's [window_start, window_end]"*. Under estate-wide activity every
object's span overlaps essentially every active node, so each version archives
**~the whole retained tenant window (~30–40 k rows ≈ 4 chunks — confirmed by
1,130 inserts / ~282 versions ≈ 4)**. Measured: 98.6 % of all correlation
persistence time, 0.47 objects/s, one cohort > the whole 2,160 s budget.

The cost is O(object-versions × window). Tracker 168 multiplied versions by
~1,500; the window term was never re-shaped. This is the fourth instance of
the programme's one defect class: per-object work sized by a global.

## 2. The key insight

The slice has two parts with different sharing structure:

1. **The object's own evidence** — component signals + in-bounds clears +
   matched identity signals. O(object). Genuinely per-version.
2. **Context** — every OTHER time-overlapping node, included so replay is a
   true *re-derivation* (replay re-runs edge admission against plausible
   neighbours and confirms they did not join). O(window). **Identical for
   every object of the same epoch — it IS the epoch's frozen window.**

Today part 2 is duplicated into every object version. The fix is not to weaken
the slice rule — it is to stop duplicating the shared part.

## 3. Design: two layers

### Layer 1 — per object version, materialized (readers unchanged)

Keep writing `netops.corr_signals_archive` rows stamped
(`archived_for`, `archived_version`) — but ONLY the object's own evidence:
component signals, in-bounds loose clears, matched identities. This is
literally tracker 156's prescription ("sized by the object"). Expected size:
tens of rows (live objects: ≤7 nodes), not 30–40 k.

Every existing Go reader (`correlations.go` timeline, `cloud_notify.go`,
`cloud_handlers.go`, `cloud_network_overview.go`, `wireless_actions.go`)
queries by `archived_for` — they continue to work unchanged, now returning the
object's evidence rather than the whole window. For the object-scoped surfaces
(timeline, notify, overview) that is arguably the more correct payload; any
surface that genuinely wants ambient context joins Layer 2.

### Layer 2 — per epoch, shared, new small table

At epoch freeze (`_begin_epoch`, right after `ep.snapshot = tuple(...)`),
write the tenant window MEMBERSHIP once:

```sql
CREATE TABLE netops.corr_epoch_members (
    tenant_id   LowCardinality(String),
    epoch_id    UUID,                    -- minted per (epoch, tenant)
    seq         UInt32,                  -- position in the frozen snapshot order
    signal_id   UUID,
    ts_override Nullable(DateTime64(3)), -- ONLY for clock-clamped signals (§5.1)
) ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMM(archived_at))
ORDER BY (tenant_id, epoch_id, seq)
SETTINGS non_replicated_deduplication_window = 1000;
```

[REVIEW NOTE, added at withdrawal: this DDL does not parse — `archived_at` is
not a defined column and there is a trailing comma. The storage review's
corrected DDL is preserved in `ARCHIVE_V1_STORAGE_REVIEW_2026-08-22.md` §3 and
is the mandatory starting point for any revival.]

Rows are ~40–60 B (vs ~1 KB full signal rows). One insert per tenant per
epoch, dedup token = `epoch:{epoch_id}` (idempotent on epoch retry — a retry
builds a NEW epoch with a new id, so a stale write can never alias).

`corr_objects` gains one additive column: `epoch_id UUID DEFAULT
toUUID('00000000-0000-0000-0000-000000000000')` — stamped on every version
persisted from that epoch. Zero-UUID = legacy object → legacy read path.

### Read path

* **replay.py** — `stored.epoch_id` zero → legacy `_select_slice` over fat
  archive rows (unchanged, forever, for pre-migration objects). Non-zero →
  fetch membership (tenant, epoch_id) → bounded-scan `corr_signals` over the
  membership's [min ts, max ts] (the same bounded-scan shape the readers use
  today) → rehydrate in `seq` order, applying `ts_override` where present →
  **apply the pure `_archive_slice(snap, window)` function itself** → replay.
  The slice rule executes at read time on the reconstructed window, so replay
  remains the strong re-derivation — byte-identical membership by
  construction, pinned by the equivalence oracle (§6).
* **Go timeline fallback** — the existing newest-`archived_version`-≤-v
  resolution keeps working on Layer 1 rows; no change required to ship.

## 4. What this does to the numbers

| | today (measured) | redesigned (modelled) |
|---|---:|---:|
| archive rows / object version | ~30–40 k | **~10–10² (component-sized)** |
| archive rows / epoch (~282 versions) | ~10⁷ (13.6 M/cohort at 1,500 obj) | ~10⁴ (L1) + 65 k tiny rows (L2, once) |
| archive share of persistence | **98.6 %** | ~1–5 % |
| per-version persistence | ~636 ms | **~30 ms** |
| object persistence rate | 0.47/s | **~25–30/s** |
| L2 cost location | — | once per epoch, ~1 insert, off the cohort loop |

[REVIEW NOTE: the storage review recomputed L2 honestly — membership re-lists
the whole window every 30 s epoch ⇒ ≤144 M rows/day, ~1.09 GB/day at NOMINAL
on an incident-free day, vs zero today. The "65 k tiny rows once" row above
was the central arithmetic error that killed Layer 2.]

No background-writer machinery is needed: L2 lands once per epoch inside
`_begin_epoch` (~150 ms class), L1 is small enough to stay on the existing
serial path. The asymptotic shape becomes O(window) per EPOCH + O(object) per
version — the identical hoist pattern the 166 epoch applied to preparation,
now applied to persistence.

## 5. Edge cases that are load-bearing (each gets a test)

1. **Clock-clamped signals (THE trap).** `buffer_signal` clamps far-future
   device timestamps to arrival time and keeps `stored_signal_id`. The
   `corr_signals` row was written by the batcher BEFORE the clamp — so
   rehydrating from `corr_signals` alone would resurrect the unclamped ts and
   replay would drift. Hence `ts_override` in the membership row, written for
   exactly the signals whose in-window ts ≠ their persisted ts. Rare
   (`EVENT_TS_FUTURE_CLAMPED` counted), cheap (Nullable), and the equivalence
   oracle must include a clamped-signal fixture.
   [REVIEW NOTE: incomplete in the wrong direction — the row is also
   UNREACHABLE by ts-range scan (it lives at the raw future ts, possibly in a
   future daily partition), and `tenant_id` diverges the same way
   (''→'global' canonicalized after the row was written). See storage review
   findings 3–4.]
2. **Membership = the frozen snapshot, not a time-range query.** Capacity
   head-drops, dedup, debug-probe exclusions, per-tenant watermarks — none of
   these are reconstructable from `corr_signals` by ts-range. The membership
   list captures the retained set by construction, which is precisely why
   Layer 2 must exist at all.
3. **Duplicate rows in `corr_signals`.** The batcher's dedup window is
   bounded; late redelivery can duplicate a row. Rehydration reads
   `LIMIT 1 BY signal_id` (any copy is byte-equal — same serializer).
4. **Retention coupling.** Layer 2 references `corr_signals`, so the
   replayability horizon for new objects = corr_signals HOT retention (180 d
   default, corr_retention.go), beyond which the existing cold Parquet export
   is the recovery path. `corr_epoch_members` TTL must be ≤ corr_signals hot
   TTL. This is a (mild) contract change to state at ratification: today's fat
   archive was self-contained per its own TTL. If a longer self-contained
   horizon is required, the alternative is copy-on-expiry materialization —
   deliberately NOT built until someone needs it.
   [REVIEW NOTE: the retention facts here are WRONG — corr_signals hot TTL is
   30 d (`ch_retention.go:88`), the archive is 90 d (`corr_retention.go`), so
   this design would have silently cut the replay horizon 90 d → 30 d.]
5. **Damping.** `_ARCHIVE_SLICE_HASH` now keys on Layer-1 membership only —
   which changes less often than window membership, so damping strictly
   improves. Epoch membership needs no damping (once per epoch by design).
6. **Merged/closed persists** (`window=[]`) archive nothing today; unchanged.
   [REVIEW NOTE: false as designed — stamping terminal versions with the
   CURRENT epoch_id points replay at a membership that cannot contain the
   closed object's evidence. Correctness review finding 2.]

## 6. Correctness argument and test plan

The replay-exactness argument is UNCHANGED because the slice function is
unchanged — only where it executes moves (write time → read time) and what is
stored moves (materialized rows → the exact inputs the function needs). Two
pure inputs fully determine the slice: the frozen window (membership + row
content + ts overrides) and the snapshot bounds/identities (already in the
object row). Determinism of `_archive_slice` is already pinned.

Tests (extends `test_archive_slice.py` / `test_replay_archive_slice.py`, §11):

* **Equivalence oracle**: for every object in the fixture corpus (incl. a
  clamped-ts signal, a capacity-dropped window, a multi-tenant epoch):
  derived slice == today's materialized slice, byte-identical, same order.
* **Replay clean** over the derived path (drift = red).
* **Legacy path**: zero-epoch objects replay via `_select_slice` untouched.
* **Mutation tests**: drop `ts_override` handling → red; substitute ts-range
  query for membership → red on the capacity-drop fixture; skip `LIMIT 1 BY`
  → red on the redelivery fixture; write L1 with full window → the write-amp
  regression test (rows per version bounded by component size) goes red.
* **Isolation test** (§3a): membership reads tenant-scoped; cross-tenant
  epoch_id probe returns nothing.

[REVIEW NOTE: `test_replay_archive_slice.py` does not exist — the real pin is
`test_archive_slice.py`; and the isolation test as written is vacuous because
the Python reader queries at `tenant_scope='__all__'`.]

## 7. Rollout

1. Migration: create `corr_epoch_members`, add `corr_objects.epoch_id`
   (additive, default zero-UUID — old rows untouched).
2. Ship write path (L1 shrink + L2 write + epoch_id stamp) and replay dual
   path in ONE change (§7 modification rules: one bounded context — this is
   one: the archive subsystem).
3. Go readers: no change required at ship. Optional later: context join for
   surfaces that want ambient window context.
4. Qualification: Falsification Test A from the architecture review — the
   post-fix truthful 1K (keyed harness, deployed `ch_insert` fix), graded
   against the ratified workload (`EPS_BASELINE_PROPOSAL_2026-08-22.md`).
   Acceptance: archive ≤5 % of persistence time; pending → 0 in budget.

## 8. Explicitly unchanged

165 retention semantics · 168 identity scoping (both layers) · 170 completion
gate · the slice membership RULE and replay exactness · version scoping and
the newest-≤-v fallback · Go reader query shapes · `corr_signals` write path ·
the 160 durability boundary (L1 archive stays non-critical/retry-whole; the
frontier never waits on L2 — it lands before cohorts start).
