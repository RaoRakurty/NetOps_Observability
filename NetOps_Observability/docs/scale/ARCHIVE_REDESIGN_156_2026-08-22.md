# Archive persistence redesign v2 — component slice only (post-review)

**Date:** 2026-08-22 · **Status: DESIGN v2 — revised after two independent
adversarial reviews (correctness; storage/ops). v1's Layer 2 is WITHDRAWN.**
**Fixes:** tracker 156 residual = tracker 166's measured blocker.
**Awaiting:** owner sign-off on ONE product question (§5), then implementation
on Opus per the model policy.

---

## 0. Review outcome that produced this revision

v1 proposed two layers: a component-sized per-version slice (L1) plus an
epoch-shared window-membership table (L2) so replay could re-derive against
ambient context. Two independent reviews returned:

* **Correctness review: REJECT v1.** Central finding, verified by experiment
  and independently reproduced in-session: removing the ambient-context rows
  from the pinned replay fixture still replays **clean, zero drift** — the
  property L2 existed to preserve is not part of the replay contract as
  actually pinned (`replay._diff` compares only component-local facts), and
  the code's own exactness argument (`main.py` `_archive_slice` docstring:
  pair-local edge admission ⇒ an excluded node could only have joined via an
  edge the live run would also have admitted — contradiction) already proves
  ambient context is not load-bearing for exactness.
* **Storage/ops review: APPROVE L1 WITH CHANGES, REJECT L2 as specified.**
  Independent kill-shots on L2: the DDL did not parse; membership rows carried
  no timestamp so the prescribed bounded read was circular; clamped signals'
  `corr_signals` rows live under their RAW pre-clamp ts (the batcher writes
  BEFORE `buffer_signal` clamps) so rehydration could not even locate them;
  tenant `''`→`'global'` canonicalization happens after the row is written,
  breaking tenant-keyed lookup; replay horizon would silently shrink 90 d →
  30 d (v1 had the retention facts wrong: `corr_signals` hot TTL is 30 d via
  `ch_retention.go:88`, the archive is 90 d via `corr_retention.go`); no
  fail-closed path on a failed membership write (silently unreplayable
  objects); a converge race (the correlation container has no dependency on
  the Go schema converge, so the new table may not exist when first written);
  and the cost model inverts — L2 is O(window × epochs) regardless of
  incidents: **1.09 GB/day at nominal on a day with zero RCA objects**, vs
  zero today, with each admitted signal re-listed ~30×/day.

Both reviews independently recommended the same thing: **ship the component
slice alone.** It captures ~100 % of the measured win (the 98.6 % is entirely
per-version archive volume), touches no schema, needs no migration, and rolls
back trivially. This document is that design.

## 1. The defect (measurement unchanged from v1, with one honesty note)

Per persisted object version, `_archive_slice` includes every node whose
activity interval overlaps the object's span — under estate-wide activity that
approaches the whole retained tenant window. Measured (`082201589waa`):
`corr_signals_archive` = 1,130 inserts, p50 152 ms, **222.4 of 232.4 s of all
correlation insert time (98.6 %)**; 0.47 objects/s; one cohort > the 2,160 s
budget. Slice size: observed insert `row_count`s of 8,461/8,904 with
1,130 inserts / ~282 object rows ≈ 4 inserts per version. Whether that means
~8.5 k-row slices written once per re-archive or ~38 k-row slices in 4 chunks
is **not settled by the existing evidence** (the two readings disagree; v1
asserted the latter, the correctness review disputed it) — the implementation
adds a slice-size counter so the next run measures it instead of arguing. The
fix is identical either way.

## 2. The design: change ONE membership rule

`_archive_slice` membership changes from

> every node whose activity interval overlaps the object's
> [window_start, window_end]

to

> **every signal of every COMPONENT node** (node-complete — nodes are never
> clipped), plus in-bounds loose signals (`*_clear`, app-identity) as today,
> plus the object's matched identity signals as today.

Everything else is byte-for-byte today's behaviour: same table, same columns,
same (ts, signal_id) ordering, same damping (`_ARCHIVE_SLICE_HASH` — which now
damps MORE, since component membership changes less often than window
membership), same chunking, same non-critical/retry-whole durability class,
same version scoping, same newest-`archived_version`-≤-v reader fallback.

**Node-completeness is load-bearing (storage review finding 15):** L1 must be
"every signal of every component node", never "the signals attached to the
object" — both the exactness argument and the rollback story rest on whole
nodes. A mutation test pins it (§7).

**No schema change. No new table. No migration. No epoch stamping.**
Terminal persists (`merged`/`closed`, `window=[]`) are genuinely unchanged —
the v1 blocker about stamping them with a current-epoch reference is moot.

### Rollback

Verified by the storage review: old code reading new (component-only) slices
resolves them through the existing newest-≤-v fallback and replays them clean
by the same pair-locality argument. New code reading old (fat) slices is
today's path. No stranded data in either direction.

### What is genuinely lost, stated rather than buried

The archive alone can no longer answer "what else was happening in this
tenant's window at the time" with capacity-drop/dedup/watermark fidelity, and
the window-global gap-hint count remains un-replayed (it already was). Ambient
context for HUMANS remains available from `corr_signals` by (tenant, ts-range)
— see §5 — but that query cannot know which signals the live window had
excluded (capacity drops, dedup, debug-probe exclusions). That fidelity was
the only thing L2 bought, at the §0 cost list; both reviews judged it a
diagnostic nicety, not a contract. If a future need proves otherwise, v1's L2
returns via §9's revival conditions — not before.

## 3. Modelled effect (unchanged goal, cleaner path)

| | today (measured) | v2 (modelled) |
|---|---:|---:|
| archive rows / version | ~8.5–38 k (window-shaped) | **O(component)** — live objects ≤7 nodes ⇒ typically tens; bounded by component size, NOT constant (a 48 k-edge storm object archives its whole component; the regression test keys on component size) |
| archive share of persistence | 98.6 % | ~1–5 % |
| per-version persistence | ~636 ms | ~30 ms |
| object persistence rate | 0.47/s | ~25–30/s |
| storage/day at stress | ~52 GB | **~0.6 GB (≈48×, storage review §4)** |
| storage/day, incident-free | ~0 | ~0 (unlike L2's 1.09 GB floor) |

## 4. Reader impact — the eight call sites, honestly

The reviews enumerated **eight** archive readers, not v1's five, and three
change *meaning* under component-only slices:

| Reader | Today reads | Under v2 | Class |
|---|---|---|---|
| `replay.py` | full slice | component slice — replay-clean (proven on fixture; corpus gate in §7) | unchanged contract |
| `correlations.go` timeline + `timeline_evidence.go` | full window slice; renders **`unlinked`** evidence ("shared a token, no edge met threshold") and byModality/byStatus counts | `unlinked`/`malformed` collapse to ~0 unless context is re-sourced | **product decision (§5)** |
| `cloud_handlers.go` `observer_count` ("who actually saw it") | uniq observers over full slice | uniq observers over component — drops sharply | **product decision (§5)** |
| `timeintel_api.go` detection latency (`min(ingest_ts)`) | over full slice | over component — value shifts | **product decision (§5)** |
| `path_graph_api.go` path ranking by archive row count | window-shaped counts | component-shaped counts — arguably MORE correct (ranks by the object's own evidence) | behaviour change, state in changelog |
| `cloud_notify.go` / `cloud_network_overview.go` ("has a `source='cloud'` archive row") | fires on context rows too | fires only on objects whose OWN evidence is cloud — fewer pages, arguably a fix | behaviour change, state in changelog |
| `wireless_actions.go` | object-scoped already | unchanged | none |

## 5. The ONE owner decision required before implementation

**DECIDED (owner, 2026-08-22): option (a).** The Inspector timeline
re-sources ambient context from `corr_signals` at display time; the engine
change ships first, the Go display join follows as its own bounded change.
The original options, for the record:

* **(a) RECOMMENDED — re-source context at read time.** The timeline (and the
  two derived numbers, if desired) additionally query `corr_signals` by
  (tenant, [window_start−ε, window_end+ε]) — display-only, no exactness
  contract, no schema change, one bounded Go-side change per surface. Honest
  caveat shown in §2: the context query cannot reflect live-window exclusions.
* **(b) Accept the narrowed semantics** — timeline shows the object's own
  evidence only; `observer_count` becomes "observers of this object";
  detection latency likewise object-scoped. Zero extra work; visible product
  change.

Either answer unblocks implementation; (a) can also ship per-surface after the
engine change, since the engine fix and the display join are independent.

## 6. Required implementation details (from the reviews)

1. **Membership rule change** in `_archive_slice` — component nodes + loose
   in-bounds + identities; ordering/damping/chunking untouched.
2. **Fix the stale citation** in `main.py`'s archive docstring: it cites
   `test_replay_archive_slice.py`, which does not exist — the real pin is
   `test_archive_slice.py`. Update alongside.
3. **Slice-size observability**: counter/histogram for archive rows per
   version (settles §1's 8.5 k-vs-38 k question on the next run; also the
   write-amp regression signal).
4. **No new fields enter `content_hash`/`material_hash`** — nothing in this
   change touches them; the damping regression test (§7) pins it anyway
   (lesson from the withdrawn L2's epoch_id, storage review finding 16).
5. Reader changes only per the §5 decision; everything else ships untouched.

## 7. Test plan (merged from both reviews)

* **Corpus falsification — the ship gate**: for EVERY object in the fixture
  corpus (multi-tenant, seam-bridged/folded components, boundary-node cases,
  clamped-ts signal, identity-matched objects): component-only replay is
  CLEAN. One already-reproduced instance exists; the corpus run is the gate.
  If ANY object drifts → stop, revisit §9.
* **Terminal-version replay** (both reviews): persist open → close
  (`window=[]`) → replay the terminal version via the ≤-v fallback. Currently
  untested anywhere.
* **Node-completeness mutation**: trim one signal from a component node's
  archive set → replay must go red (pins finding 15).
* **Membership mutation**: restore the old overlap rule → the new write-amp
  regression test (rows/version bounded by component size on a fixture with
  heavy non-component context) must go red.
* **Damping regression**: same component membership across versions → damped;
  changed component → re-archived. (Exists; re-pin against the new rule.)
* **Reader-regression assertions** with stated expected deltas:
  timeline `counts.unlinked`, `observer_count`, `min(ingest_ts)`,
  `cloud_notify` candidate set — per the §5 decision.
* **Rollback test**: new-format slice read through the OLD `_select_slice`
  path replays clean.
* **Equivalence-comparison level**: Signal-level (`to_ch_row()` of rehydrated
  vs original), never archive-row bytes — `ingest_ts`/`archived_at` differ by
  construction (correctness review, test-gap 8).

## 8. Explicitly unchanged

165 retention semantics · 168 identity scoping · 170 completion gate ·
version scoping and newest-≤-v resolution · archive durability class
(non-critical, retry-whole on next persist) · `corr_signals` write path ·
90-day archive retention (self-contained slices — the horizon v1's L2 would
have silently cut to 30 d) · the 160 frontier boundary · all DDL.

## 9. Layer 2 — withdrawn, with revival conditions

v1 is preserved verbatim at `review/ARCHIVE_REDESIGN_156_v1_WITHDRAWN_2026-08-22.md`,
and both review verdicts (with the storage review's corrected DDL) at
`review/ARCHIVE_V1_CORRECTNESS_REVIEW_2026-08-22.md` and
`review/ARCHIVE_V1_STORAGE_REVIEW_2026-08-22.md`, should it ever be revived. It may be reconsidered ONLY if the
corpus falsification (§7) finds a real object whose component-only replay
drifts, or a ratified product requirement demands exclusion-faithful ambient
context. Any revival must carry: the corrected DDL (real time column, src_ts
lookup keys, tenant_src, daily partitions, TTL, row policy, dedup-safe
registration), lazy first-persist writes, a fail-closed fat-slice fallback,
random per-(replica, epoch, tenant) UUIDv4 minting, and a converge-existence
probe — none of which are built today, deliberately.
