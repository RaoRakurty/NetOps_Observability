# Archive redesign v1 — storage/ops/migration review (preserved)

**Date:** 2026-08-22 · **Reviewer:** independent adversarial storage review
(Opus subagent) · **Subject:** `ARCHIVE_REDESIGN_156_v1_WITHDRAWN_2026-08-22.md`
· **VERDICT: APPROVE WITH REQUIRED CHANGES for Layer 1 — REJECT Layer 2 as
specified** (DDL does not parse, read path cannot execute, failure mode is
silent unreplayability, justification contradicted by the exactness argument
already in `main.py`).

Preserved findings table, corrected DDL, and storage arithmetic — the parts
v2 §9's revival conditions depend on. Prose vectors condensed; the verdict,
numbers and required changes are verbatim.

---

## Findings

| # | Sev | Finding | Required change |
|---|---|---|---|
| 1 | BLOCKER | Proposed CREATE does not parse: `PARTITION BY` references `archived_at` which is not a column; trailing comma | Corrected DDL below |
| 2 | BLOCKER | Membership rows carry **no timestamp** → the prescribed "bounded scan over [min ts, max ts]" is **circular**; `corr_signals` ORDER BY `(tenant_id, ts, source, entity_type, entity_id)` has **no signal_id index** → without a ts bound the scan reads the tenant's whole retention | Store `ts` (in-window) AND `src_ts` (as persisted) per member row |
| 3 | BLOCKER | Clamped signals' `corr_signals` rows were written under the RAW pre-clamp ts (batcher runs BEFORE `buffer_signal`) — they sit outside the window's ts range, in a future daily partition: **the bounded scan cannot retrieve them at all**. `ts_override` restores the value but not the reachability | `src_ts` as the lookup key, `ts` as the restored value; drops `ts_override` |
| 4 | BLOCKER | `canon_tenant` rewrites `''→'global'` AFTER the row is serialized → tenant-keyed, partition-pruned lookup returns nothing for those signals; returned ones rehydrate mixed-tenant and `prepare_run_window` rejects | Canonicalize before `to_ch_row()` or persist `tenant_src`; add a global-tenant fixture |
| 5 | BLOCKER | Retention premise wrong: `corr_signals` hot TTL = **30 d** (`ch_retention.go:88`, `corr_schema.go:77`), archive = **90 d** (`corr_retention.go:119`, profiles :54-62) → design silently cuts the replay horizon 90 d → 30 d while `corr_objects` keeps 180 d | Raise `CH_CORR_SIGNALS_RETENTION_DAYS` ≥ archive profile, or state the cut for sign-off |
| 6 | BLOCKER | No fail-closed path: a REJECTED L2 insert returns False silently (non-critical table) → epoch proceeds, versions stamped with nonexistent membership = permanently, silently unreplayable. A TRANSPORT failure re-raises out of `_begin_epoch` → the WHOLE sweep is lost — slow ClickHouse now stops correlation entirely, strictly worse than today | Per-epoch archive mode: any L2 non-commit ⇒ zero epoch_id + fat-slice L1 fallback for that epoch |
| 7 | BLOCKER | Converge race: correlation container has no dependency on the Go schema converge (`docker-compose.yml:1245-1248`); converge is a detached best-effort goroutine (10×6 s, warn, never fatal; `clickhouse_policies.go:35-51`, `main.go:980`) → engine can stamp epoch_ids before the table exists | Startup table-existence probe or default-off feature flag, fat-slice fallback |
| 8 | BLOCKER | Merged/closed persists (`window=[]`) stamped with the current epoch_id → derived path applies the slice rule to a window that no longer contains the object → empty slice on every terminal version | Stamp epoch_id only when window non-empty; terminal versions keep zero-UUID |
| 9 | MAJOR | epoch_id minting unspecified: deterministic mint over (tenant, epoch time) collides across replicas (the lab splits one tenant) → shared dedup token makes ClickHouse silently drop the second replica's membership → its objects replay against the WRONG window, no counter | Mandate random UUIDv4 per (replica, epoch, tenant), pinned by test |
| 10 | MAJOR | Dedup window pointless as designed: `ch_insert` retries only `CH_DEDUP_SAFE_TABLES` members; new table absent → transient rejection = permanent hole despite the window being set | Add to `CH_DEDUP_SAFE_TABLES` + the `MODIFY SETTING` converge |
| 11 | MAJOR | Unconditional O(window × epochs) floor: each admitted signal re-listed 900/30 = 30×/day; **incident-free day costs 1.09 GB/day vs zero today**; no TTL in DDL and `corr_retention.go`'s table lists are hardcoded literals | TTL from day one; write L2 lazily on the epoch's FIRST persist (fixes 6, 11, 14 together) |
| 12 | MAJOR | No row policy (hand-maintained list at `corr_schema.go:414-422`; guard `TestCorrSchemaRowPoliciesCoverAllTables` would catch); §6 isolation test vacuous — the Python reader hardcodes `tenant_scope='__all__'`; replay isolation is actually enforced by the Go API's `chTenantScope` | Add `StrictRowPolicyDDL` + init.sql policy; re-word the test claim |
| 13 | MAJOR | Interactive replay regression: ~65 k rows parsed through `ch.query → r.json()` synchronously ON the engine's event loop, un-offloaded, un-bounded (7.6× today's 8.5 k); at storm the ts-range scan over-reads 16–28× | Offload rehydration, bound rows, re-measure /replay p95 |
| 14 | MAJOR | Epoch start blocks on network IO: per-tenant serial inserts × `CORR_CH_TIMEOUT_S`=30 s ahead of every cohort, vs a 30 s engine interval; measured CH insert latency already 14,395 ms. §8's "frontier never waits on L2" has it backwards — landing before cohorts IS the critical path | gather-with-bound, or (preferred) lazy write per finding 11 |
| 15 | MAJOR | **L1 must be NODE-complete** ("every signal of every component node"), never "signals attached to the object" — the exactness argument AND the rollback story rest on whole nodes | Specify + mutation-test (ADOPTED in v2) |
| 16 | MAJOR | `epoch_id` must never enter `content_hash`/`material_hash` — else damping fires every epoch and reinstates the write amplification this fix removes | Stamp post-`to_object_row`; damping regression test (lesson ADOPTED in v2 §6.4) |
| 17 | MAJOR | `corrOrphanCloseInsertHead` (corr_reconcile.go:68-78) enumerates columns and already silently drops `attribution` — epoch_id would be zeroed on janitor orphan-closes (which is accidentally CORRECT per finding 8; make it explicit) | Add column to INSERT+SELECT lists deliberately |
| 18 | MAJOR | L2 makes replay depend on a table whose write path can LOSE rows (rejected batch → DLQ → dropped, `main.py:4409-4440`); membership then references rows that never exist; fat archive is immune (written from memory) | `members_found / members_expected` as a first-class metric; misses ⇒ *degraded*, never "clean" |
| 19 | MINOR | `seq` mis-documented: `_archive_slice` re-sorts into (ts, signal_id); seq is a physical clustering key only | Re-document |
| 20 | MINOR | Monthly partitions defeat cheap expiry with `ttl_only_drop_parts` (30 d TTL retains up to 60 d); every hot corr table uses daily | `PARTITION BY (tenant_id, toYYYYMMDD(epoch_at))` |
| 21 | MINOR | Missing repo conventions: `DEFAULT ''` on tenant_id, `index_granularity`, `ttl_only_drop_parts`; DDL must be mirrored in FOUR places (init.sql, corr_schema.go CREATE, policy list, retention list) | See corrected DDL |

## Corrected DDL (mandatory starting point for any L2 revival — v2 §9)

```sql
-- Layer 2: per-epoch frozen window membership. One insert per (replica, tenant, epoch).
-- Rows are references, not content: replay rehydrates from netops.corr_signals.
CREATE TABLE IF NOT EXISTS netops.corr_epoch_members
(
    tenant_id    LowCardinality(String) DEFAULT '',  -- canonical (post canon_tenant) tenant
    epoch_id     UUID,                     -- RANDOM v4, minted per (replica, epoch, tenant)
    epoch_at     DateTime64(3) DEFAULT now64(3),     -- epoch freeze time: partition + TTL key
    seq          UInt32,                   -- physical clustering key (arrival order); NOT
                                           -- used by the derivation, which re-sorts by (ts,id)
    signal_id    UUID,                     -- join key into netops.corr_signals
    ts           DateTime64(3),            -- the IN-WINDOW ts (post-clamp) replay must restore
    src_ts       DateTime64(3),            -- the ts the corr_signals row was WRITTEN under
                                           -- (pre-clamp). THE LOOKUP KEY: corr_signals is
                                           -- ORDER BY (tenant_id, ts, ...) and has no
                                           -- signal_id index. Equals `ts` for unclamped rows.
    tenant_src   LowCardinality(String) DEFAULT ''   -- the tenant_id the corr_signals row was
                                           -- written under (pre canon_tenant). '' vs 'global'.
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMMDD(epoch_at))
ORDER BY (tenant_id, epoch_id, seq)
TTL toDateTime(epoch_at) + INTERVAL 30 DAY      -- MUST be <= corr_signals hot TTL (finding 5)
SETTINGS index_granularity = 8192,
         ttl_only_drop_parts = 1,
         non_replicated_deduplication_window = 1000;

CREATE ROW POLICY IF NOT EXISTS tenant_iso_corr_epoch_members ON netops.corr_epoch_members
    USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__'
    TO ALL;   -- STRICT: no untagged-shared clause, matching the corr family
```

Read shape it enables: one contiguous PK range read of the epoch's members,
then per distinct `tenant_src` a PK-pruned `corr_signals` range scan over
`[min(src_ts), max(src_ts)]` with `LIMIT 1 BY signal_id`.

`corr_objects` change (three places, all required): init.sql CREATE literal;
`corr_schema.go` converge `ADD COLUMN IF NOT EXISTS epoch_id UUID DEFAULT
toUUID('00000000-...') AFTER attribution` (metadata-only on MergeTree — proven
pattern ×4 at corr_schema.go:102/183/190/197); `corr_reconcile.go:71-76`
INSERT+SELECT lists (deliberately zero-UUID for orphan closes).

## Storage arithmetic (the numbers that killed L2)

Row ≈ 53 B raw, **≈21 B on disk** (epoch_id/seq/tenant compress to ~0;
signal_id incompressible 16 B; ts deltas 2-3 B).

| Workload | Window | Epoch period | Epochs/day | L2 rows/day | L2 disk/day | copies/signal |
|---|---:|---:|---:|---:|---:|---:|
| Nominal (20 sig/s) | 18,000 | 30 s | 2,880 | **51.8 M** | **1.09 GB** | **30×** |
| Stress S2 (65 k window) | 65,000 | 250 s | 346 | 22.5 M | 0.47 GB | 3.6× |
| Worst (150 k buffer @30 s) | 150,000 | 30 s | 2,880 | **432 M** | **9.1 GB** | 30× |

vs the fat archive replaced: stress **51.8 GB/day → 1.08 GB/day (48× less)**;
nominal ~5.4 GB → 1.12 GB (4.8×); **zero-incident day: 0 GB → 1.09 GB (∞×
more)**. Conclusions: TTL mandatory day one; the cost model INVERTS against
load (fewer epochs at stress ⇒ fewer membership rows than at nominal — the
binding number is the 30 s interval floor, not the storm); the floor is
unconditional and independent of object count.

## Key vector conclusions (condensed)

* **Rollback (H):** better than feared — old code reads component-only L1
  through the newest-≤-v fallback and replays clean by pair-locality, PROVIDED
  L1 is node-complete (finding 15). Adopted as v2's rollback argument.
* **Read cost (B):** nominal derived replay ≈ 18 k rows / 10–30 ms (fine);
  storm ≈ 16× over-read, ~1 GB scanned (not acceptable un-offloaded).
* **Migration (G):** `ADD COLUMN` metadata-only ✓; but init.sql runs only on
  fresh volumes and the converge is best-effort/detached → probe, don't
  assume (finding 7).
* **Is L2 worth it (I): No, not at ship.** The code's own exactness argument
  (pair-locality + contradiction) already proves ambient context is not
  load-bearing; L2 buys a non-contractual diagnostic ("what else was
  happening", exclusion-faithful) at the §Findings cost list.
  **Recommendation: ship L1 with findings 15+16, take the 48× win, re-run
  Falsification Test A.** Revive L2 only if the corpus equivalence oracle
  shows a real derivation gap — with lazy first-persist writes, fat-slice
  fallback on failure, random UUIDv4 minting, and this corrected DDL.

## Disposition (v2 traceability)

Findings 15, 16 → adopted into v2 (§2 node-completeness + mutation test;
§6.4 hash-purity note). Findings 1–14, 17–21 → moot with L2's withdrawal;
preserved here as v2 §9 revival conditions. The recommendation paragraph IS
v2's design.
