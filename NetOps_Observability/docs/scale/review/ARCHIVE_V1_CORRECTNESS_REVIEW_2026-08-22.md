# Archive redesign v1 — adversarial correctness review (verbatim)

**Date:** 2026-08-22 · **Reviewer:** independent adversarial design review
(Opus subagent) · **Subject:** `ARCHIVE_REDESIGN_156_v1_WITHDRAWN_2026-08-22.md`
· **Outcome:** REJECT — drove the v2 (component-only) revision.
Preserved verbatim from the review deliverable; the central experimental claim
(finding 1) was independently reproduced in-session before acceptance.

---

## 1. VERDICT

**REJECT.** Layer 1 (component-sized slice) is correct and fixes the measured
defect; **Layer 2 is unjustified** — I ran the repo's own pinned replay fixture
with the context rows removed and it replays **clean, zero drift**, so the
property Layer 2 exists to preserve is not measured by `DriftReport._diff`,
while its cost (~144 M rows/day, computed from `WINDOW_BUFFER` maxlen ×
epochs/day) is larger than the defect being fixed — and it carries two
independent BLOCKER correctness holes on top.

---

## 2. Findings

| # | Sev | Vector | Finding | Evidence | Required change |
|---|---|---|---|---|---|
| 1 | **BLOCKER** | I / §2 | Layer 2's entire justification ("replay re-runs edge admission against plausible neighbours and confirms they did not join") is a property **nothing diffs**. `_diff` compares only top_hypothesis, verdict_tier, confidence, node_count, signal_count, edge set — all component-local. I removed the two context nodes from the pinned fixture and replayed: `full clean: True []` / `L1 clean: True []`. | `replay.py:215-232`; `test_archive_slice.py:98-114,116-127`; `main.py:3040-3050` (the docstring's own pair-locality argument) | Run the falsification over the whole fixture corpus and **report the result in the doc**. If it holds, ship L1 alone and delete Layer 2. |
| 2 | **BLOCKER** | C / §3 | `_persist_snapshot` is called for `state='merged'`/`'closed'` with `window=[]` — the object closed *because* its component aged out of the window. Stamping those versions with the **current** epoch_id points replay at a membership that provably does not contain the object's evidence. Today the terminal version is replayable via `_select_slice`'s newest-≤-v fallback. New path → "recomputation produced N objects, none with the stored id". | `main.py:3494,3510`; `replay.py:271-284`; design §5.6 calls this "unchanged" | Terminal versions must carry the epoch_id of the last **materially archived** version, or zero-UUID (legacy path). Test: close an object, replay its terminal version. |
| 3 | **BLOCKER** | B | A `corr_signals` batch that is **positively rejected** is DLQ'd and **dropped**, but `batch_signal()` runs *before* `buffer_signal()` at every lane — so the signal is in the window with no row behind it. Under L2 the membership references a row that does not exist and rehydration **silently returns a shorter window**. The codebase already names this exact failure: *"the replay source silently grew holes"*. Design has no missing-row detection. | `main.py:4173-4176`, `4438`, `3992-3999`, `5796-5797` (order), `6122-6124`, `6158-6160` | Rehydration MUST assert `count(rehydrated) == count(membership)` and emit a named `DriftReport` finding on shortfall. Silent shrinkage is forbidden. |
| 4 | **BLOCKER** | C | L2 failure semantics are unspecified. `corr_epoch_members` is not in `CH_CRITICAL_TABLES`, so `ch_insert` returns `False` silently; the epoch then proceeds, every version persisted in it is stamped with an epoch_id whose membership does not exist, and `_mark_processed(_cohort)` advances the frontier anyway → permanently unreplayable versions, no counter. Design only argues idempotency. | `main.py:4022-4030`, `3813-3818`, `3527-3531` (frontier); design §3 "dedup token = epoch:{epoch_id}" | L2 write must be a **hard gate**: raise on failure, abort the epoch before any cohort persists. State it in §8's durability boundary. |
| 5 | **MAJOR** | F / §5.4 | Retention premise is **factually wrong**. Design: "replayability horizon = corr_signals HOT retention (180 d default, corr_retention.go)". Reality: `corr_signals` TTL is **30 days** and is owned by `ch_retention.go`, not `corr_retention.go`; the archive it replaces is **90 days** (production profile). The design **shortens the replay horizon 3×** and reports it as unchanged-or-better. | `init.sql:228`; `ch_retention.go:88`; `corr_retention.go:57` | Correct the numbers; state the 90 d → 30 d regression as a contract change requiring sign-off, or bump `CH_CORR_SIGNALS_RETENTION_DAYS` to ≥ Archive. |
| 6 | **MAJOR** | F | The L2 volume model is off by ~3 orders. Membership is the **whole window, every epoch**; `_begin_epoch` runs once per sweep, sweep sleeps `CORR_ENGINE_INTERVAL_S=30`, window is capped at 50 000. → 2 880 epochs/day × ≤50 k = **≤144 M rows/day**; a signal surviving the ~400 s reach is re-listed ~13-20×. Under a 30 d TTL that is ~4 B rows resident. §4 accounts for it as "65 k tiny rows (L2, once)". | `main.py:668,918-919,3568,3585,1621`; design §4 table row "L2 cost location — once per epoch" | Recompute honestly, or make membership a **delta** per epoch. As written this recreates the 29.9 M-row problem `corr_retention.go` was built to fix, 5× worse per day. |
| 7 | **MAJOR** | A / §5.1 | `ts_override` covers the clamp but **not the second row-affecting mutation at the same chokepoint**: `buffer_signal` rewrites `tenant_id` via `canon_tenant` ("" → "global") *after* `to_ch_row()` was already handed to the batcher. So the persisted row says `tenant_id=''` while the in-window signal says `'global'`. Rehydrating from `corr_signals` (a) misses those rows under a `tenant_id='global'` membership filter and (b) yields a mixed-tenant window that `prepare_run_window` rejects. Pinned as live behaviour by an existing test. | `main.py:1464-1465`; `test_canon_tenant.py:27-35`; `main.py:2500-2505`; design §5.1 calls the clamp "THE trap" (singular) | Enumerate **every** post-row mutation at `buffer_signal`, not just ts. Either canonicalise before `to_ch_row()` at all lanes, or add `tenant_override` alongside `ts_override`. |
| 8 | **MAJOR** | H | The design's "readers unchanged" is a product regression it waves away. `serveCorrelationTimeline` is documented as *"the FULL window slice of signals for one object — every signal in the window, attached or not"*, and `MergeTimelineEvidence` renders `link_status: "unlinked"` with the reason *"shares a topology/seam token with the graph, but no edge met the attach threshold"*. Component-only L1 makes `unlinked` and `malformed` **identically zero** and collapses `byModality`/`byStatus`. That is the Inspector's differentiating feature. | `correlations.go:503-506,645-650`; `timeline_evidence.go:196-215` | Own it: either keep an ambient-context join for the timeline (design §3 defers it to "optional later"), or get explicit product sign-off that the Inspector loses "what else was happening". |
| 9 | **MAJOR** | H | Two archive readers the design **did not enumerate at all**, plus one whose displayed number silently changes. `cloud_handlers.go` computes `observer_count = uniqExact(a.observer_id)` over *all* archive rows, labelled "who actually saw it" — that number drops sharply. `path_graph_api.go` ranks the object's path entity by archive row **count**. `timeintel_api.go` derives detection latency from `min(ingest_ts)` over archive rows. | `cloud_handlers.go:396`; `path_graph_api.go:117-123`; `timeintel_api.go:242-246`; design §3 lists only 5 readers | Extend the reader inventory to all 8 call sites; state the expected delta for each; add a reader-regression test for `observer_count` and detection latency. |
| 10 | **MAJOR** | E / §6 | "The slice function is unchanged" is false. `_archive_slice(snap: ObjectSnapshot, ...)` needs `.window_start`, `.window_end`, `.identity_signals`; `StoredObject` carries **none** of them and `replay_object` never reads `corr_evidence`, where the matched-identity ids actually live (`subject_kind='app'`). The function must be re-signatured or a shim snapshot synthesised — which is where the byte-identity argument would break. | `main.py:3037-3060`; `replay.py:47-80,253-268`; `engine.py:1795-1806` | Re-signature to `_archive_slice(ws, we, identity_ids, window)` and pin the shim with the equivalence oracle; add the `corr_evidence` identity-id fetch to the read path. |
| 11 | **MAJOR** | E / G | Calling `_archive_slice` at read time reuses `_WINDOW_INDEX_CACHE`, a module-global keyed by `id(window)` whose safety argument is *"the cache is cleared per cycle regardless (see engine_cycle)"*. A replay HTTP request is not a cycle: it inserts an entry the cycle never clears, retaining `sid`/`ordinal` dicts for a 30-50 k window in the 1280 MiB-floor container, and re-introduces the recycled-`id()` risk the guard only partially covers. Replay also runs **on the event loop**, un-offloaded — the design moves O(window) work from write-once to read-per-request onto the loop that is the bottleneck. | `main.py:3011-3025,3035`, `3262-3277`, `7127-7139` | Give the read path its own index construction (no module cache), and offload it via `_offload`. |
| 12 | **MAJOR** | D | The proposed DDL has **no row policy**, while every sibling table has a `tenant_iso_*` FORCE policy, and the correlation reader queries at `tenant_scope='__all__'` — so the policy is not the backstop either; the tenant filter must be literal in the SQL. §3a.4 makes the storage-layer policy mandatory. | `init.sql:675-700`; `main.py:3974-3980`; design §3 DDL block | Add `tenant_iso_corr_epoch_members` (strict, no untagged-shared clause) and make the membership SQL carry `tenant_id = <stored.tenant_id>` explicitly. |
| 13 | **MINOR** | — | The proposed DDL is **not executable**: `PARTITION BY (tenant_id, toYYYYMM(archived_at))` references a column absent from the column list. No TTL clause either, despite §5.4 requiring one. | design §3 DDL | Fix before ratification. |
| 14 | **MINOR** | — | The design's central pin, `test_replay_archive_slice.py`, **does not exist** (nor does the `main.py` docstring's citation of it). The real pin is `test_archive_slice.py`. | `ls src/correlation/`; `main.py:3049`; design §6 | Correct both citations; the stale `main.py` reference should be fixed in this change. |
| 15 | **MINOR** | §1 | The measurement premise is internally inconsistent: the source doc measures `row_count=8461/8904` and concludes "~8,500 rows per object"; the design restates it as "~30-40 k rows ≈ 4 chunks" from a divide (1,130/282) that ignores damping. `CORR_ARCHIVE_CHUNK_ROWS` defaults to 10 000 with no compose override, so 8 461 is a **whole slice**, not a chunk. | `main.py:2181`; bottleneck doc "Observed slice sizes"; design §1 | Reconcile. 4× inflation in the doc justifying the change. |
| 16 | **MINOR** | §3 | "Expected size: tens of rows (live objects: ≤7 nodes)" is not a bound — the same codebase profiles a live **48,375-edge** object. | `main.py:3093-3096` | State the L1 bound as O(component), and write the write-amp regression test against component size, not a constant. |

---

## 3. Attack vectors

**A. Row-content fidelity.** Field-by-field, `corr_signals` and
`corr_signals_archive` have identical column sets (`init.sql:188-229` vs
`242-285`) and both rows come from the same `to_ch_row()`
(`signals.py:688-745`), so the shape holds. The `attrs` mutation path the
prompt flagged is **safe**: `classify_probe` stamps
`probe_intent`/`probe_authority`/`seam_id` etc. *before* `to_ch_row()` at both
probe call sites (`main.py:5750-5762`, `5795-5797`, `5810-5813`), and
`to_ch_row`'s `observer_kind` stamp copies rather than mutates — checked,
holds. Entity-string sharing is immutable-by-type — checked, holds. **What
does not hold is `tenant_id`** (finding 7): `buffer_signal` rewrites it after
the row is written. `ingest_ts` also diverges (archive gets its own
`now64(3)`), which is harmless for `from_ch_row` but means the §6 oracle must
compare at the `to_ch_row()` level, not the archive-row level.

**B. ts_override coverage.** It covers the future-clamp only. Two gaps:
`tenant_id` (finding 7), and the missing-row case (finding 3). On the latter —
the batcher's documented rejection path *drops the batch* after DLQ'ing it
(`main.py:4173-4176`), and `buffer_signal` runs after the enqueue, so window
membership and `corr_signals` membership can legitimately diverge. Today
`corr_signals_archive` materialises the row and papers over it; under L2 it
becomes silent replay corruption. Design has no shortfall check. Note also
that `buffer_signal` drops `probe_authority=debug_only` and
`probe_scope=internal_self_probe` signals from the window *after* they were
written to `corr_signals` (`main.py:1446-1454`) — the reverse direction,
harmless for membership-driven reads but it disproves any "the window is a
ts-range of corr_signals" shortcut (which §5.2 already concedes).

**C. Epoch membership timing.** The epoch↔window correspondence is sound:
`_persist_snapshot` receives `ep.by_tenant[tenant]` via
`evaluated.append((tenant, window, snapshots))` (`main.py:3385`, `3326`), and
the snapshot is frozen at `_begin_epoch` (`main.py:2466`) — checked, holds for
open persists. It fails for terminal persists (finding 2) and on L2 write
failure (finding 4). One thing that *does* survive: the
abort-after-`corr_objects`-insert scenario from the bottleneck doc's secondary
finding — L2 lands before any cohort, so a whole-cohort retry in epoch E2 that
dedups back onto E1's row still points at an existing E1 membership.

**D. Multi-tenant.** `ep.by_tenant` is per-tenant and the DDL comment says
epoch_id is minted per (epoch, tenant), which is the right shape — but the
minting mechanism is unspecified (a `uuid5(now, tenant)` would collide across
replicas; `--scale correlation=N` is a supported topology,
`docker-compose.yml:1126-1143`), and the table has no row policy while the
reader runs at `tenant_scope='__all__'` (finding 12). The object→membership
join is tenant-scoped only if the SQL says so; `replay_object`'s existing
queries carry no tenant predicate at all (`replay.py:253-268`).

**E. Derived slice at read time.** Bounds are recoverable — `corr_objects`
stores `window_start`/`window_end` (`init.sql:295-296`,
`engine.py:1739-1740`) and `StoredObject` could read them. Matched identity
ids are recoverable only from `corr_evidence` (`engine.py:1795-1806`), which
replay does not query. `_archive_slice` cannot be called unchanged (finding
10), and calling it in-process has cache/loop consequences (finding 11).

**F. Retention orderings.** The design names one ordering
(`corr_epoch_members` TTL ≤ `corr_signals` TTL) and gets the underlying number
wrong by 6× (finding 5). It misses two more: (i) `corr_signals` (30 d) <
`corr_objects` History (180 d) means a 31-day-old object is **unreplayable
while still listed** — today the archive (90 d) partially covers that; (ii)
`corr_signals` PARTITIONs by `toYYYYMMDD(ts)` with `ttl_only_drop_parts=1`
(`init.sql:230-232`), so expiry is whole-day-granular and a window straddling
a partition drop loses *part* of its membership — the exact silent-shrinkage
case of finding 3, arriving via TTL rather than via a rejected write.

**G. Concurrency/restart.** Replica collision is avoidable with uuid4 but
unstated (finding 12/D). The H13 content-hash dedup interplay **holds** with
an added `epoch_id` column, because `epoch_id` is not in the token
(`main.py:3106-3113`) and is not in `content_hash` — a re-minted identical
version dedups to the earlier row and keeps the earlier epoch_id, whose
membership exists. That is correct behaviour, but it should be written down,
because it means `epoch_id` is *not* always the epoch the surviving row was
persisted from.

**H. Go readers.** Not unchanged — see findings 8 and 9. Three surfaces change
semantically (timeline `unlinked`/`byStatus`, `observer_count`, detection
latency), two change selection (`cloud_notify` / `cloud_network_overview`
define "cloud object" as *"exists an archive row with source='cloud'"*,
`cloud_notify.go:148-153`, `cloud_network_overview.go:52-58` — under L1 these
fire on fewer objects, i.e. **fewer pages**; arguably a fix, but it is a live
notification-path behaviour change shipped unannounced).

**I. Simpler alternatives.** The doc compares nothing. The obvious candidate —
**L1 component-only with no Layer 2** — achieves ~100 % of the measured win
(the 98.6 % is entirely per-version archive inserts), needs no new table, no
migration, no epoch stamping, no retention coupling, no read-path fork, and
**passed the replay-clean bar on the repo's own fixture in my run above**. The
prompt's other candidate (per-epoch full-row archive) is strictly worse than
L2 on volume and should be recorded as rejected-with-reason. Both belong in
the doc.

---

## 4. Test-plan gaps

The §6 plan is directionally right but misses the cases that would actually
catch findings 2, 3, 5 and 7:

1. **Terminal-version replay** — persist open, then close (`window=[]`), then
   replay the *terminal* version. Currently untested anywhere; it is the case
   finding 2 breaks.
2. **Missing-row fixture** — membership references a signal whose
   `corr_signals` row was rejected/DLQ'd. Must produce a **named DriftReport
   finding**, never a shorter window.
3. **Tenant-canon fixture** — a `tenant_id=''` signal buffered as `'global'`;
   assert rehydration recovers `'global'`. Mirror `test_canon_tenant.py:27-35`.
4. **TTL-boundary fixture** — a window straddling a `corr_signals`
   day-partition drop (`ttl_only_drop_parts=1`); assert loud failure, not
   shrinkage.
5. **The falsification the doc owes**: full fixture corpus, component-only
   slice vs full slice, drift diff. If it is clean everywhere, Layer 2 does
   not ship.
6. **Reader-regression assertions** (not just "readers unchanged"): timeline
   `counts.unlinked`, `observer_count`, `minIngestTS`, and the `cloud_notify`
   candidate set, each with a stated expected delta.
7. **Volume regression**: assert L2 rows/day against a budget derived from
   `WINDOW_BUFFER` maxlen × epochs/day — the number in finding 6 should be a
   failing test, not a footnote.
8. **Equivalence-oracle comparison level** must be specified as
   `to_ch_row()`-of-Signal, not archive-row bytes (`ingest_ts`/`archived_at`
   differ by construction), or the oracle will be either spuriously red or
   quietly weakened to compare only ids.

---

## Disposition (added at filing, v2 traceability)

Findings 1, 6, 13 → Layer 2 withdrawn entirely (v2 §0/§9). Findings 2, 3, 4,
5, 7, 10, 11, 12 → moot with L2's withdrawal; preserved as revival conditions
(v2 §9). Finding 8, 9 → v2 §4 reader table + owner decision §5 (option (a)
chosen 2026-08-22). Finding 14 → fixed in the v2 implementation (docstring
citation corrected). Finding 15 → v2 §1 carries both readings + the
slice-size counter that settles it. Finding 16 → v2 §3 states the O(component)
bound; write-amp regression test keys on component size. Test-plan gaps 1, 5,
6, 8 → implemented (`test_archive_slice.py`,
`test_archive_corpus_replay_156.py`); gaps 2, 3, 4, 7 → moot with L2.
