// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/platformdb"
	"strings"
	"time"

	"netops/backend/chhttp"
	"netops/backend/internal/chschema"
	"netops/backend/maintenance"
	"netops/backend/timeintel"
)

// timeintel_backfill.go — RCA Time Intelligence #84 tail: the backfill that
// POPULATES incident_time_metrics. The live per-incident view DERIVES phase
// metrics from corr objects on read (no engine change); this worker computes the
// same decomposition for every corr object in a window and persists it as a
// durable, RLS-scoped snapshot. The reliability rollups READ these snapshots
// (timeintel_reliability.go, ListWindow) — persisted rows outlive the CH TTL,
// lift the old 5000-row live-scan cap, and carry the grounded seam_type plus the
// rollup grouping facts (owner/state/internal/group_keys, migration 0027) without
// re-parsing the hypotheses blob. Since tracker 197 the pass never reads that
// blob at all: seam_type is a projection column, so both halves of a page read
// the narrow netops.corr_current.
//
// Two backends like every other store (CLAUDE.md §3a): in-memory (default,
// tenant-filtered IN the store) and Postgres (tenant_iso FORCE-RLS via withTenant).
// Tenant is stamped from the corr object's own tenant_id (the data), never a
// request body — the worker spans tenants but each row is written default-closed
// under its own scope.

// The snapshot store moved to timeintel/metrics_store.go (Phase-2 W1.5).
// Aliases keep the worker, reliability rollups and handler source-compatible.
type (
	incidentTimeMetricRow    = timeintel.MetricRow
	incidentTimeMetricsStore = timeintel.MetricsStore
)

const timeIntelBackfillCap = timeintel.SnapshotCap

// newIncidentTimeMetricsStore selects pg under STORE_BACKEND=postgres, else in-memory.
func newIncidentTimeMetricsStore() incidentTimeMetricsStore {
	if ps, ok := platformdb.ActivePG(); ok {
		return timeintel.NewPGMetricsStore(ps.DB())
	}
	return timeintel.NewMemMetricsStore()
}

// ── the backfill worker ───────────────────────────────────────────────────────

const (
	// timeIntelBackfillLookback bounds how far back a COLD pass scans — i.e. the
	// window a pass with no stored cursor starts from. Once the cursor exists it
	// is the lower bound and this is only the floor under it.
	timeIntelBackfillLookback = 30 * 24 * time.Hour

	// timeIntelBackfillTag attributes this pass in system.query_log
	// (log_comment) and routes it to the #101 `background` workload profile.
	// It used to share `worker:cross-tenant` with the appid fusion store, which
	// is why the 2026-08-29 storm incident took a query_log dig to pin on this
	// worker rather than a one-line lookup. The pick and the fetch carry
	// SEPARATE tags for the same reason: on storm-s07 the two halves of this
	// pass had wildly different costs and only one aggregate number to show it.
	timeIntelBackfillTag     = "worker:timeintel-backfill"
	timeIntelBackfillPickTag = "worker:timeintel-backfill-pick"

	// ── page geometry (tracker 186 clause 2) ──────────────────────────────────
	//
	// timeIntelBackfillPageRows is the objects fetched by ONE read, and
	// timeIntelBackfillMaxPages bounds a pass. Their product is deliberately
	// timeIntelBackfillCap (20 000), the old single-shot cap: a pass still does
	// at most the same amount of work, but it does it in ten bounded steps that
	// each advance the watermark, instead of one step that re-read the same
	// oldest 20 000 objects forever.
	//
	// 2 000 is chosen from the storm-s07 measurement rather than taste: that
	// pass read 1 931 054 rows / 35.4 GB and peaked at 1.86 GiB for 20 000
	// objects, and the read was linear in objects picked. Tracker 197 removed
	// that linearity — both halves of a page now read the NARROW projection, and
	// a whole 2 000-key page costs one 555 MiB query (measured) instead of 32
	// sub-fetches totalling ~37.8 GiB — so the page size is no longer what
	// bounds the cost. It is kept because it is what makes the watermark advance
	// in useful strides.
	timeIntelBackfillPageRows = 2000
	timeIntelBackfillMaxPages = 10

	// timeIntelBackfillRescanPages is how much of that page budget the bounded
	// RE-SCAN behind the watermark may spend (see timeIntelBackfillWatermarkSlack).
	// The rest is reserved for FORWARD progress, and that reservation is the
	// whole point: under a storm the window behind the mark can hold more
	// objects than an entire pass, so an undivided loop would spend every tick
	// re-reading them and the watermark would never move — the same stall, in a
	// new costume.
	timeIntelBackfillRescanPages = 1

	// timeIntelBackfillPagePause YIELDS between pages. The storm-s07 overcommit
	// did not merely fail this query — it evicted two background MergeParts (on
	// netops.findings and netops.corr_objects), i.e. the api starved the store's
	// own merges. A pass that runs ten reads back to back would hold a worker
	// lane continuously; a short gap between pages gives the merge scheduler a
	// window it can actually use.
	timeIntelBackfillPagePause = 250 * time.Millisecond

	// timeIntelBackfillBudget bounds ONE PAGE server-side (max_execution_time).
	//
	// It used to be 120 s, MEASURED against a full 20 000-row single-shot pass
	// (79.9 s on the live storm table). A page is a tenth of that and carries a
	// tight created_at slice, so 30 s is the same measurement divided by the
	// same factor, with headroom for contention. A breach is loud and
	// self-healing: the pass is idempotent, so the next tick redoes it.
	//
	// Why a long-ish budget is acceptable HERE and nowhere near the UI: the
	// pass is de-prioritized (#101 `background` profile, priority 2), runs every
	// 15 minutes, blocks no request, and is memory- and read-capped. The
	// transport timeout is derived from it (chClientForBudget) so the
	// classified server-side error is what surfaces instead of a Go-side
	// "Client.Timeout exceeded".
	timeIntelBackfillBudget = 30 * time.Second

	// timeIntelBackfillPassTimeout bounds the WHOLE pass (every page's read and
	// its upserts). DERIVED from the page budget and the page count so the two
	// can never invert the way the transport timeout and the read budget did
	// before chClientForBudget.
	//
	// A page is TWO reads of the same narrow projection — one pick, one fetch —
	// each bounded by the page budget, plus the inter-page pause (tracker 197;
	// before it the fetch was a TREE of sub-fetches against corr_objects with a
	// wall-clock deadline of its own, and this derivation had to name it). The
	// pass timeout must always exceed what the page loop is allowed to spend, or
	// it silently becomes the real bound and pages die mid-page.
	timeIntelBackfillPassTimeout = timeIntelBackfillMaxPages*
		(2*timeIntelBackfillBudget+timeIntelBackfillPagePause) +
		60*time.Second

	// timeIntelBackfillBlockRows / timeIntelBackfillThreads bound the block
	// geometry of both reads. They were sized against corr_objects.hypotheses
	// (48 GiB uncompressed / 26 KB per row with 49 MiB storm outliers, so a
	// default 8192-row block of that one column is ~256 MiB PER reading thread;
	// default geometry peaked at 1.8 GiB and was refused at the 2 GiB cap, while
	// 1024 x 2 peaked at 447-484 MiB). Tracker 197 took that column out of this
	// pass entirely — the same geometry over the narrow projection peaks at
	// 44 MiB for a whole 2 000-key page — so these are now simply a modest,
	// measured ceiling on a read that no longer needs rescuing.
	timeIntelBackfillBlockRows = 1024
	timeIntelBackfillThreads   = 2

	// timeIntelBackfillMemoryBytes is this worker's OWN per-query memory ceiling,
	// tighter than the generic 1 GiB worker guard (chWorkerReadMemoryBytes).
	//
	// The arithmetic, from the storm-s07 number rather than a round guess:
	// 1.86 GiB was measured for a 20 000-object page against corr_objects, whose
	// cost was linear in objects picked — 190 MiB of page-linear share for 2 000
	// objects, plus a page-INDEPENDENT ~53 MiB floor of in-flight blocks that a
	// single 49 MiB outlier row could land inside, doubled for headroom: 512 MiB.
	//
	// Tracker 197 left that ceiling ~12x larger than the workload it now bounds
	// (44 MiB peak for a whole 2 000-key page off the narrow projection). It is
	// KEPT at 512 MiB deliberately: it is the guard rail that made the storm-s07
	// overcommit impossible, not a tuning knob, and lowering it would only trade
	// headroom for a new way to fail.
	//
	// What that buys the box: the 4 GiB server cap now sees at most two worker
	// lanes at 512 MiB (this one and corr_current_reconcile, whose heaviest
	// healthy read in 24 h of query_log was 310 MiB) plus the 1 GiB hot-UI lane
	// — under 2 GiB committed, leaving over half the server for the background
	// merges this worker evicted on storm-s07.
	timeIntelBackfillMemoryBytes = 512 << 20

	// timeIntelBackfillReadBytes caps the VOLUME one page may read
	// (max_bytes_to_read). storm-s07 read 35.4 GB in a single pass and its read
	// volume grew ~0.6 GiB per leg with retention — a cost that rises with the
	// table no matter how the query is shaped. This is the hard stop for that
	// growth. It was sized against a page that read the hypotheses blobs of
	// ~2 000 objects (~50-500 MB depending on granule density, i.e. 4-40x
	// headroom and 17x UNDER the observed regression); since tracker 197 a whole
	// page reads 555 MiB of the narrow projection, so the cap is ~3.7x headroom
	// on a read that no longer grows with the blob column. Tripping it is loud
	// (TOO_MANY_BYTES) and costs one pass, which the watermark then resumes.
	//
	// NOT max_rows_to_read: the picked objects are scattered across the
	// correlation_id (UUID) key space, so ClickHouse reads whole granules to
	// find them and "rows read" over-counts by up to the granule size. Bytes is
	// the axis that actually tracks the cost, and the one the incident measured.
	timeIntelBackfillReadBytes = 2 << 30

	// timeIntelBackfillMaxResponseBytes bounds the JSON body ONE PAGE reads into
	// the API process — the second half of the storm-s07 memflat FAIL, where a
	// 20 000-row answer was parsed as ONE 70.70 MiB JSON document and showed up
	// as the api RSS sawtooth (sampled trough-vs-peak).
	//
	// The arithmetic, measured on the live storm table over the picked set:
	// affected 285 B + evidence_missing 376 B + top_hypothesis 31 B + ids,
	// timestamps and JSON keys ~= 1.0 KB/row, so a 2 000-row page renders ~2 MB.
	// 8 MiB is that with 4x headroom for fatter blast radii, and it is still a
	// hard ceiling: exceed it and the page fails loudly instead of returning a
	// prefix. The peak parse is now bounded by the PAGE, not by the table.
	//
	// Tracker 197 did not move it: the response is the SAME twelve values per
	// row it always was. Only their source changed.
	timeIntelBackfillMaxResponseBytes = 8 << 20

	// timeIntelBackfillPickResponseBytes bounds the narrow pick's body: four
	// small columns, ~140 B/row, so a 2 000-row page is ~280 KB. 2 MiB is 7x
	// that and still two orders of magnitude under the old single parse.
	timeIntelBackfillPickResponseBytes = 2 << 20

	// timeIntelBackfillRescanSkipStep (ultra #5) is how far the re-scan's start
	// moves FORWARD after a pass whose re-scan was refused by ClickHouse — the
	// bounded skip that stops a deterministically failing region behind the
	// mark (e.g. a 159 TIMEOUT that the same window reproduces every tick) from
	// consuming the re-scan budget forever. The splitter's philosophy, one
	// layer up: progress over completeness, loudly — each move is counted on
	// netops_timeintel_rescan_skips_total and named at WARN.
	//
	// A quarter of the slack: four consecutive refusals walk the floor across
	// the whole 2 h re-scan window, so even a region that is unreadable END TO
	// END costs one hour of ticks before the re-scan is running again — and the
	// only data at risk is the re-scan's own redundancy (reconcile-repaired
	// rows), never forward progress, which ultra #5's other half already
	// unblocked. The floor is cleared by the first re-scan that completes.
	timeIntelBackfillRescanSkipStep = timeIntelBackfillWatermarkSlack / 4

	// timeIntelBackfillWatermarkSlack is how far BEHIND the stored cursor each
	// pass restarts. See timeintel.BackfillCursor.Rewind: corr_current is also
	// written by corr_current_reconcile.go, which repairs a drifted projection
	// row HOURLY and carries the object's ORIGINAL created_at across — so a row
	// can land in corr_current already behind the mark. Two hours = one
	// reconcile period plus one missed one. Re-reading that slice is free by
	// construction: the fold is an idempotent upsert on the snapshot PK.
	timeIntelBackfillWatermarkSlack = 2 * time.Hour
)

// Sentinel outcomes of the pass-serialization guard (ultra #6). Both are
// EXPECTED coordination results, not faults: the ticker logs them at INFO and
// the HTTP trigger maps them to 409 Conflict.
var (
	// errTimeIntelBackfillInFlight: another pass holds the inflight guard. The
	// caller yields — the running pass is doing the same work.
	errTimeIntelBackfillInFlight = errors.New("timeintel backfill: a pass is already in flight")
	// errTimeIntelBackfillStale: the watermark was reset while this pass was
	// running, so its remaining saves were discarded. The DISCARD is the point:
	// this pass's progress is measured against a watermark the operator just
	// declared void, and persisting it would silently undo the reset.
	errTimeIntelBackfillStale = errors.New("timeintel backfill: watermark was reset during the pass — the pass's progress was discarded, the reset stands")
)

// timeIntelBackfillKey is one picked object: the primary-key tuple plus the
// cursor position it occupies.
type timeIntelBackfillKey struct {
	TenantID      string
	CorrelationID string
	Version       int
	CreatedAt     time.Time
}

// timeIntelBackfillResult is what one pass did. Pages and Cursor are what make
// the pass observable: "wrote 0" now distinguishes caught-up from stalled.
type timeIntelBackfillResult struct {
	Written  int
	Pages    int
	Cursor   timeintel.BackfillCursor
	CaughtUp bool // a page came back short → nothing left past the cursor
}

// ── SQL ───────────────────────────────────────────────────────────────────────
//
// The pass is TWO bounded reads per page, not one. Both are pure builders so
// the regression tests can assert their bounds without a ClickHouse.
//
// ── 2026-08-29 storm incident (the query shape) ───────────────────────────────
//
// The original shape folded the ENTIRE corr_objects history to find each
// object's latest version (ORDER BY tenant_id, correlation_id, version DESC +
// LIMIT 1 BY, lookback applied OUTSIDE the fold) and then read the wide
// hypotheses column keyed on (correlation_id, version) — off the primary-key
// prefix. At 2 M history rows every pass read ~4 M rows / 45 GiB and peaked at
// 1.8 GiB: MEMORY_LIMIT_EXCEEDED or TIMEOUT_EXCEEDED on EVERY pass.
//
// That was repaired on 2026-08-29 by taking the latest version from
// netops.corr_current — the #100 hot projection, one narrow row per object,
// maintained by the engine's dual-write and repaired hourly by
// corr_current_reconcile.go. It is the same "latest version" the fold computed,
// by the more correct key: corr_current is ReplacingMergeTree(created_at), and
// an engine restart resets the in-memory version counter, so max(version) is
// not reliably the newest write.
//
// ── 2026-08-31 storm-s07 (why that was not enough) ────────────────────────────
//
// The repaired query was bounded in SHAPE but not in COST. It still re-picked
// the oldest 20 000 objects of a 30-day window on every 15-minute tick, so it
// read 1 931 054 rows / 35.4 GB / 1.86 GiB, grew ~0.6 GiB per leg with
// retention, and became the named victim of a 4 GiB total-memory overcommit
// that evicted two background merges with it. Two changes fix the cost:
//
//  1. WATERMARK. The pick is ordered by created_at (the ReplacingMergeTree
//     version column of corr_current — monotone per object across versions) and
//     starts strictly after the stored cursor, so a pass reads only what
//     changed. window_start, the old ordering key, is device event time and is
//     immutable across an object's versions: it can order a scan but it cannot
//     mark progress through one.
//  2. SPLIT. The pick runs on its own, so the fetch can be KEYED to exactly the
//     objects the cursor authorised instead of re-deriving them. It originally
//     also gave Go the page's [min,max] created_at to prune corr_objects'
//     toYYYYMMDD(created_at) partitions with; tracker 197 moved the fetch onto
//     corr_current, which is partitioned by tenant_id alone, so that half of the
//     split's value is gone and the keying is the whole of it.
//
// The split also removes a STALL: the cursor advances from what the PICK
// returned, not from what the fetch found — so a page can never be held still
// by whatever the fetch did or did not find.
//
// ── 2026-09-02 tracker 197 (why there is no wide half left) ───────────────────
//
// Both halves now read netops.corr_current. See timeIntelBackfillFetchSQL: the
// fold needs twelve values, the projection carried eleven, and the engine now
// projects the twelfth (seam_type) at persist time.

// timeIntelBackfillPickSQL builds the NARROW pick: the next page of objects
// past the cursor, in cursor order. No wide column may ever appear here (#100
// rule 2b) — this half exists precisely so the fetch can be keyed.
func timeIntelBackfillPickSQL(lookbackSeconds, pageRows int, from, until timeintel.BackfillCursor) string {
	// Non-narrowing floor: an object is persisted at or after its window opens,
	// so the lookback still bounds a COLD pass with no cursor.
	win := intToString(lookbackSeconds)
	where := "WHERE window_start >= now() - INTERVAL " + win + " SECOND"
	switch {
	case from.IsZero():
		// First pass: the floor above is the only lower bound.
	case timeintel.ValidCorrelationUUID(from.CorrelationID):
		// Tie-broken, strictly forward — the in-pass page boundary.
		where += "\n   AND (created_at, correlation_id) > (" +
			timeIntelCHDateTime64(from.CreatedAt) + ", toUUID('" + from.CorrelationID + "'))"
	default:
		// No usable tie-break (a rewound cursor, or a corrupt stored id): a
		// CLOSED lower bound re-reads the boundary instead of skipping it.
		where += "\n   AND created_at >= " + timeIntelCHDateTime64(from.CreatedAt)
	}
	// The optional CEILING is what keeps the re-scan phase from spilling into
	// the forward phase's territory: bounded above by the watermark, the
	// re-scan reads exactly the rewind window and nothing the forward phase is
	// about to read anyway.
	switch {
	case until.IsZero():
		// Forward phase: no ceiling.
	case timeintel.ValidCorrelationUUID(until.CorrelationID):
		where += "\n   AND (created_at, correlation_id) <= (" +
			timeIntelCHDateTime64(until.CreatedAt) + ", toUUID('" + until.CorrelationID + "'))"
	default:
		where += "\n   AND created_at <= " + timeIntelCHDateTime64(until.CreatedAt)
	}
	// ALIAS SHADOWING (2026-08-31 deploy pre-check, 186 hotfix). ClickHouse
	// resolves a SELECT alias INSIDE the WHERE and ORDER BY of the same query.
	// The first cut of this projection aliased the CONVERTED expressions back
	// onto the column names they were converted from — `toString(correlation_id)
	// AS correlation_id`, `<ISO text> AS created_at` — so every predicate below
	// bound the String expressions instead of the typed columns:
	//
	//   Code 43 ILLEGAL_TYPE_OF_ARGUMENT — no operation greater between String
	//   and DateTime64(3,'UTC')   (and Code 386 NO_COMMON_TYPE on the UUID once
	//   only created_at was renamed).
	//
	// It was a DELAYED trap, not an obvious one: the cold branch carries no
	// cursor predicate, so the FIRST pass succeeded and stored a watermark and
	// every later pass hard-failed — and 43 is not in the 241/159 retryable set,
	// so the worker stalled permanently rather than degrading.
	//
	// So the projected aliases are deliberately NON-SHADOWING (`_s`/`_iso`
	// suffixes) and the WHERE + ORDER BY below therefore bind the RAW typed
	// columns. ORDER BY matters as much as the predicates: the cursor is a
	// (created_at, correlation_id) tuple compared server-side, and UUID TEXT
	// order is not UUID NATIVE order — an ORDER BY that bound the String alias
	// would scan in a different order than the cursor advances in, and objects
	// between the two orders would be skipped permanently. The scan order and
	// the cursor comparison must be the same order, which means both must be
	// the raw columns. timeIntelPickPage reads the renamed result columns.
	return `
SELECT toString(tenant_id)      AS tenant_id_s,
       toString(correlation_id) AS correlation_id_s,
       version                  AS version,
       ` + chschema.ISO("created_at") + ` AS created_at_iso
  FROM netops.corr_current FINAL
 ` + where + `
 ORDER BY created_at ASC, correlation_id ASC
 LIMIT ` + intToString(pageRows) + `
 FORMAT JSON`
	// The created_at predicate is safe under FINAL even if the optimizer moves
	// it below the merge: created_at IS the ReplacingMergeTree version column,
	// so the surviving row of a duplicate group is by definition the one with
	// the greatest created_at. Filtering the older duplicates away first cannot
	// change which row survives — it can only drop groups whose newest row is
	// already behind the cursor, which is exactly what the cursor asks for.
}

// timeIntelBackfillFetchSQL builds the fold's read for one picked page: the
// twelve values foldTimeIntelPage needs, for exactly the keys picked — every
// one of them a PLAIN COLUMN of the narrow current-state projection.
//
// ── WHAT THE FOLD ACTUALLY NEEDS (checked 2026-08-31, 186 fix-2) ─────────────
//
// foldTimeIntelPage reads exactly twelve values off each row: tenant_id,
// correlation_id, window_start, window_end, created_at, verdict_tier,
// top_confidence, top_hypothesis, evidence_missing, affected, state, owner —
// and seam_type. Nothing here is speculative, so no column can be dropped to
// make the read cheaper; the set is pinned by
// TestTimeIntelBackfillFetchSelectsOnlyWhatTheFoldNeeds.
//
// ── WHY THIS READS corr_current AND NOT corr_objects (tracker 197) ───────────
//
// It used to read corr_objects and JSONExtractString `owner` and `seam_type`
// out of the ~5.7 KB hypotheses blob, because corr_current carried eleven of
// the twelve — owner among them (#100) — and only seam_type was missing. That
// ONE absent string cost the pass the entire wide read: `hypotheses` is 94 % of
// corr_objects, its granules are ~12 MiB and the picked correlation_ids are
// UUIDs scattered across the key space, so one key landed in one granule and
// shared it with nobody.
//
// MEASURED on the resident corpus (923 184 projection rows), identical budgets:
//
//	corr_objects, 64 keys (one sub-page) ..  1.18 GiB read, 35 070 rows, 133 MiB
//	corr_objects, 2 000 keys (one page) ...  REFUSED, Code 307 TOO_MANY_BYTES
//	                                         at 2.01 GiB — hence the sub-paging
//	corr_current, 2 000 keys (one page) ...  555 MiB read, 0.83 s, 36 MiB peak
//
// i.e. a page went from 32 sub-fetches totalling ~37.8 GiB to ONE 555 MiB
// query. The engine now projects seam_type at persist time (main.py
// `_current_badges`), so the wide read, the sub-paging splitter, its halving
// tree, its narrow-geometry floor retry and its oversize-skip path are all
// GONE — none of them had a reason to exist that survived the twelfth column.
//
// PRE-197 ROWS. A corr_current row written before the ALTER carries the column
// DEFAULT ” — which is exactly what JSONExtractString returned for an object
// that grounded on no seam, and what the fold has always read as UNGROUNDED.
// Old rows are therefore CORRECT, merely unlabelled, and the hourly drift
// repair (chschema.CorrCurrentNarrowInsertPrefix) re-projects them with the
// real value. Pinned by TestTimeIntelBackfillTreatsEmptySeamTypeAsUngrounded.
//
// FINAL. corr_current is a ReplacingMergeTree keyed on created_at, so FINAL is
// what collapses re-persists of the same object to its newest row. The key
// tuple keeps `version` for the same reason the pick emits it — it is the
// identity the pick authorised — and that predicate is safe under FINAL:
// `version` is not a sorting-key column, so optimize_move_to_prewhere_if_final
// leaves it ABOVE the merge and it can only ever filter the surviving row,
// never resurrect a stale duplicate. The rare loser is an object re-persisted
// between the pick and the fetch: it is not folded on this page and is picked
// up again by the next forward page, whose created_at is newer.
//
// NO created_at RANGE. The corr_objects read carried one to prune partitions
// (corr_objects is partitioned on toYYYYMMDD(created_at)); corr_current is
// partitioned by tenant_id ALONE and must stay that way (its dedup key may not
// span partitions), so the same predicate prunes nothing — measured byte-for-
// byte identical with and without it — while adding one more way to miss a
// re-persisted row. It is gone with the table it belonged to.
func timeIntelBackfillFetchSQL(keys []timeIntelBackfillKey) string {
	if len(keys) == 0 {
		return ""
	}
	var tuples strings.Builder
	for i, k := range keys {
		if i > 0 {
			tuples.WriteString(",")
		}
		tuples.WriteString("(" + timeIntelCHString(k.TenantID) +
			",toUUID('" + k.CorrelationID + "')," + intToString(k.Version) + ")")
	}
	return `
SELECT toString(c.tenant_id)      AS tenant_id,
       toString(c.correlation_id) AS correlation_id,
       ` + chschema.ISO("c.window_start") + ` AS window_start,
       ` + chschema.ISO("c.window_end") + `   AS window_end,
       ` + chschema.ISO("c.created_at") + `   AS created_at,
       c.verdict_tier             AS verdict_tier,
       c.top_confidence           AS top_confidence,
       c.top_hypothesis           AS top_hypothesis,
       c.evidence_missing         AS evidence_missing,
       c.affected                 AS affected,
       c.state                    AS state,
       c.owner                    AS owner,
       c.seam_type                AS seam_type
  FROM netops.corr_current AS c FINAL
 WHERE (c.tenant_id, c.correlation_id, c.version) IN (` + tuples.String() + `)
 FORMAT JSON`
	// NO ORDER BY. The row loop upserts each snapshot independently, keyed by
	// (tenant, correlation, calc version), so iteration order cannot change what
	// is stored — while sorting the result set forces the reader to hold blocks
	// alive across the whole scan. Measured against corr_objects with identical
	// settings: 971 MiB peak with the ORDER BY (and a MEMORY_LIMIT_EXCEEDED at
	// the 1 GiB ceiling) versus 501 MiB without. The projection is far cheaper,
	// but the reason to leave it out has not changed.
}

// timeIntelCHDateTime64 renders a millisecond ClickHouse literal with an
// EXPLICIT timezone: the column's own timezone is a display attribute, but the
// STRING is parsed in whatever zone is named, and a server whose default is not
// UTC would silently shift every watermark comparison.
func timeIntelCHDateTime64(t time.Time) string {
	return "toDateTime64('" + t.UTC().Format("2006-01-02 15:04:05.000") + "', 3, 'UTC')"
}

// scrubLogValue makes a tenant-controlled string safe to put in a log record:
// control characters (newlines above all — the log-forging vector) removed, and
// the result length-capped. Sanitize all logs, no PII leakage (§8).
func scrubLogValue(s string) string {
	const max = 64
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if b.Len() >= max {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// timeIntelCHString renders a ClickHouse single-quoted string literal. Tenant
// ids come from ClickHouse itself, but a tenant id is tenant-CONTROLLED data
// and gets quoted like any other external input (§3 zero trust).
func timeIntelCHString(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

// ── the pass ──────────────────────────────────────────────────────────────────

// backfillIncidentTimeMetrics runs ONE bounded, watermarked pass in two phases,
// sharing a budget of timeIntelBackfillMaxPages pages of
// timeIntelBackfillPageRows objects:
//
//	phase 1 (<= timeIntelBackfillRescanPages)  the bounded RE-SCAN of the window
//	   behind the watermark, ceilinged AT the watermark so it cannot overlap
//	   phase 2. Skipped on a cold pass.
//	phase 2 (the rest)  FORWARD from the watermark, advancing and persisting it
//	   after every page whose upserts all succeeded.
//
// TENANT SCOPE (§3a). The read is deliberately platform-wide and stays that
// way: this is a cross-tenant WORKER, its output is written back under each
// corr object's OWN tenant_id (stamped from the data, never a request body) and
// read back through the tenant-filtered store, and its only HTTP trigger is
// requirePlatformAdmin. Nothing here widens a caller's view of anything — the
// watermark is one platform-global position, not per-tenant data.
//
// No-op when the metrics store isn't available.
func (s *server) backfillIncidentTimeMetrics(ctx context.Context, lookback time.Duration) (timeIntelBackfillResult, error) {
	var res timeIntelBackfillResult
	if s.incidentTimeMetrics == nil {
		return res, nil
	}
	if lookback <= 0 {
		lookback = timeIntelBackfillLookback
	}

	// ── inflight guard (ultra #6): AT MOST ONE pass, ticker or manual. TryLock
	// so the loser yields (the running pass is doing the same work) instead of
	// queueing a redundant pass behind a ~21-minute ceiling.
	if !s.timeIntelPassMu.TryLock() {
		return res, errTimeIntelBackfillInFlight
	}
	defer s.timeIntelPassMu.Unlock()
	gen := s.timeIntelCursorGeneration()

	cursors := timeintel.NewBackfillCursorStore("")
	stored, err := cursors.Load()
	if err != nil {
		// LOUD (§10). An unreadable cursor must NOT be read as "start from
		// scratch": that silently reinstates the full 35.4 GB re-read this
		// watermark exists to end, and it would do so on every tick.
		logError("timeintel", "backfill cursor unreadable — pass SKIPPED rather than restarting a full re-read", errf(err))
		return res, fmt.Errorf("timeintel backfill cursor: %w", err)
	}
	res.Cursor = stored

	pass := &timeIntelBackfillPass{
		srv: s, lookbackSeconds: int(lookback / time.Second),
		now: time.Now().UTC(), covered: s.timeIntelMaintenanceLookup(ctx),
		cursors: cursors, mark: stored, res: &res, gen: gen,
	}

	forwardPages := timeIntelBackfillMaxPages
	// PHASE 1 — the bounded re-scan behind the mark. Skipped on a cold pass
	// (there is nothing behind a zero mark) and capped at
	// timeIntelBackfillRescanPages so it can never eat the forward budget.
	//
	// Phase 1 can DEGRADE but it can NEVER BLOCK phase 2 (ultra #5): the
	// re-scan is redundancy (an idempotent re-read of rows the reconcile may
	// have repaired), phase 2 is the only mark-advancing phase — and a
	// deterministic refusal inside the FIXED window behind the mark (159
	// TIMEOUT hit 12 of 41 pre-rewrite passes, and 159 is not a code the fetch
	// splitter halves on) used to abort the whole pass right here, every tick,
	// forever: a permanently failing backfill with a healthy forward path.
	if !stored.IsZero() {
		forwardPages -= timeIntelBackfillRescanPages
		start := stored.Rewind(timeIntelBackfillWatermarkSlack)
		if !s.timeIntelRescanFloor.IsZero() && s.timeIntelRescanFloor.After(start.CreatedAt) {
			// A previous re-scan was refused below this point: resume from the
			// skip floor instead of asking the failing window the same question.
			start = timeintel.BackfillCursor{CreatedAt: s.timeIntelRescanFloor}
		}
		if _, rerr := pass.run(ctx, start, timeIntelBackfillRescanPages, false); rerr != nil {
			if ctx.Err() != nil {
				// The PASS was cancelled (shutdown, timeout) — that is not a
				// re-scan degradation; phase 2 could not have run either.
				return res, rerr
			}
			s.timeIntelRescanFailures.Add(1)
			fields := map[string]any{
				"err": rerr.Error(), "retryable": chhttp.Retryable(rerr),
				"rescan_from": start.CreatedAt.Format(time.RFC3339Nano),
			}
			var che *chhttp.Error
			if errors.As(rerr, &che) {
				// A server refusal reproduces on the same window (the re-scan
				// window is FIXED behind the mark), so move the floor a bounded
				// step forward — the splitter's philosophy one layer up:
				// progress over completeness, loudly. A transient refusal costs
				// at most one skipped slice of the re-scan's redundancy; a
				// deterministic one stops costing every tick.
				next := start.CreatedAt.Add(timeIntelBackfillRescanSkipStep)
				if next.After(stored.CreatedAt) {
					next = stored.CreatedAt
				}
				s.timeIntelRescanFloor = next
				s.timeIntelRescanSkips.Add(1)
				fields["ch_code"] = che.Code
				fields["skip_floor"] = next.Format(time.RFC3339Nano)
			}
			logWarn("timeintel", "backfill re-scan failed — counted (and skipped forward on a ClickHouse refusal); the forward phase still runs", fields)
		} else {
			// A completed re-scan clears the skip floor: the window is readable
			// again, so the next pass re-earns the full rewind.
			s.timeIntelRescanFloor = time.Time{}
		}
	}
	// PHASE 2 — forward from the mark. This is the phase that advances and
	// persists the watermark, so a pass always moves even when phase 1 could
	// not finish its window.
	caughtUp, err := pass.run(ctx, stored, forwardPages, true)
	res.CaughtUp = caughtUp
	return res, err
}

// timeIntelBackfillPass carries one pass's shared state through its two phases.
// A struct rather than nine positional arguments: every field here is either a
// bound or a destination, and both are easy to pass in the wrong slot.
type timeIntelBackfillPass struct {
	srv             *server
	lookbackSeconds int
	now             time.Time
	covered         func(tenant, device string, at time.Time) bool
	cursors         *timeintel.BackfillCursorStore
	mark            timeintel.BackfillCursor // the persisted watermark
	res             *timeIntelBackfillResult
	gen             int64 // watermark generation this pass runs under (ultra #6)
}

// run walks up to maxPages pages starting at `from`, folding each one.
//
// advance=false is the RE-SCAN phase: the pages are re-derived (idempotently)
// but the watermark is left alone, because those rows are behind it by
// construction. advance=true is the FORWARD phase: the watermark moves and is
// persisted after every page whose upserts all succeeded, so a crash costs a
// redo and never a gap.
//
// caughtUp reports that the phase ran out of rows — a short or empty page.
func (p *timeIntelBackfillPass) run(ctx context.Context, from timeintel.BackfillCursor, maxPages int, advance bool) (bool, error) {
	// The re-scan phase stops AT the watermark; the forward phase has no ceiling.
	var until timeintel.BackfillCursor
	if !advance {
		until = p.mark
	}
	page := from
	for i := 0; i < maxPages; i++ {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if p.res.Pages > 0 {
			// Yield to the store's own merges between pages (§9 backpressure).
			// The storm-s07 overcommit did not merely fail this query — it
			// evicted two background MergeParts, i.e. the api starved the
			// store's own merges.
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-time.After(timeIntelBackfillPagePause):
			}
		}
		pg, err := p.srv.timeIntelPickPage(ctx, p.lookbackSeconds, page, until)
		if err != nil {
			return false, timeIntelBackfillDegraded("pick", err, *p.res)
		}
		if pg.raw == 0 {
			return true, nil
		}
		if pg.invalid > 0 {
			// Invalid rows are PERMANENTLY unprocessable (ultra #3): re-picking
			// them can never make them valid, so they must not hold the page
			// cursor or the watermark still. They advance position like any
			// other row; this counter and WARN are the only trace they leave.
			p.srv.timeIntelInvalidRows.Add(int64(pg.invalid))
			logWarn("timeintel", "backfill pick returned rows that fail validation — counted, never folded, and the watermark advances past them", map[string]any{
				"invalid": pg.invalid, "raw": pg.raw,
			})
		}
		if len(pg.keys) > 0 {
			rows, err := p.srv.timeIntelFetchPage(ctx, pg.keys)
			if err != nil {
				return false, timeIntelBackfillDegraded("fetch", err, *p.res)
			}
			written, err := p.srv.foldTimeIntelPage(ctx, rows, p.covered, p.now)
			p.res.Written += written
			if err != nil {
				// A store failure leaves the watermark untouched: the page retries
				// next tick, and the upsert is idempotent, so the redo costs nothing.
				return false, err
			}
		}
		p.res.Pages++

		// Advance from the RAW tail of the page (ultra #3), never from the
		// validation-filtered key list: a page whose tail rows are invalid must
		// still move the cursor past everything the server returned, or those
		// rows are re-picked forever.
		if pg.last.IsZero() {
			// Not one raw row carried a parseable created_at — there is no
			// position to advance to. Loud and fatal for this pass rather than
			// a fake "caught up": the next tick retries, and if it persists an
			// operator has a schema-grade problem to look at.
			return false, fmt.Errorf("timeintel backfill: page of %d rows carried no usable cursor position — pass stopped without advancing", pg.raw)
		}
		page = pg.last
		if advance {
			p.mark = p.mark.Advance(pg.last.CreatedAt, pg.last.CorrelationID, p.now)
			if err := p.srv.timeIntelSaveMark(p.cursors, p.gen, p.mark); err != nil {
				if errors.Is(err, errTimeIntelBackfillStale) {
					// An operator reset landed mid-pass (ultra #6). Expected
					// coordination, not an outage: stop extending a watermark
					// the reset just declared void.
					logInfo("timeintel", "backfill pass stopped — watermark reset during the pass; its progress is discarded and the reset stands", map[string]any{
						"pages_done": p.res.Pages, "written": p.res.Written,
					})
					return false, err
				}
				// Durable progress failed. Stop rather than keep folding pages
				// the next pass would redo anyway — and say so.
				logError("timeintel", "backfill watermark could not be persisted — pass stopped; the next pass will redo these pages", errf(err))
				return false, fmt.Errorf("timeintel backfill cursor save: %w", err)
			}
			p.res.Cursor = p.mark
		}
		// Caught-up is judged on the RAW page (ultra #3): a short page means the
		// server ran out of rows past the cursor. Judging it on the FILTERED
		// list turned a fully-invalid page into a false "caught up" with nothing
		// advanced — the permanent re-pick of the same 2 000 corrupt rows.
		if pg.raw < timeIntelBackfillPageRows {
			return true, nil
		}
	}
	return false, nil
}

// timeIntelPickedPage is what one pick returned: the VALIDATED keys the fetch
// may use, plus the raw-page facts the page loop advances and terminates on.
// The split is the ultra-#3 fix: validation filters what gets FOLDED, never
// what counts as position or progress.
type timeIntelPickedPage struct {
	keys    []timeIntelBackfillKey
	raw     int // rows the server returned, before validation
	invalid int // rows validation refused — permanently unprocessable
	// last is the cursor position of the page's RAW tail: the newest row with a
	// parseable created_at, carrying its correlation_id as tie-break only when
	// that id is a renderable UUID (otherwise the position degrades to a closed
	// created_at bound, exactly like a rewound cursor). Zero only when no raw
	// row carried a parseable created_at at all.
	last timeintel.BackfillCursor
}

// timeIntelPickPage reads the next page of object keys past `from`, optionally
// stopping at `until` (the re-scan phase's ceiling; a zero value = no ceiling).
func (s *server) timeIntelPickPage(ctx context.Context, lookbackSeconds int, from, until timeintel.BackfillCursor) (timeIntelPickedPage, error) {
	rows, err := chWorkerQueryTuned(ctx, chWorkerRead{
		SQL:      timeIntelBackfillPickSQL(lookbackSeconds, timeIntelBackfillPageRows, from, until),
		Tag:      timeIntelBackfillPickTag,
		Budget:   timeIntelBackfillBudget,
		MaxBytes: timeIntelBackfillPickResponseBytes,
		Settings: timeIntelBackfillReadSettings(),
	})
	if err != nil {
		return timeIntelPickedPage{}, err
	}
	pg := timeIntelPickedPage{keys: make([]timeIntelBackfillKey, 0, len(rows)), raw: len(rows)}
	for _, r := range rows {
		// The pick projects NON-SHADOWING aliases on purpose (see
		// timeIntelBackfillPickSQL); these are those names, not the column names.
		id := strings.TrimSpace(asString(r["correlation_id_s"]))
		created := parseCHTime(r["created_at_iso"])
		// Zero trust on upstream rows (§3): a key that cannot be rendered as a
		// safe literal, or that carries no cursor position, is never folded and
		// never interpolated into SQL. It is COUNTED instead (ultra #3), and
		// position comes from the RAW tail below — so an invalid row advances
		// the watermark like any other; it just leaves no snapshot behind.
		if !timeintel.ValidCorrelationUUID(id) || created.IsZero() {
			pg.invalid++
			continue
		}
		pg.keys = append(pg.keys, timeIntelBackfillKey{
			TenantID:      asString(r["tenant_id_s"]),
			CorrelationID: id,
			Version:       int(asFloat(r["version"])),
			CreatedAt:     created,
		})
	}
	// The page's position, from the RAW tail. The server orders created_at ASC,
	// so scanning back from the end finds the newest parseable position; a row
	// behind an unparseable tail may be re-read (and re-counted) by the closed
	// bound once — harmless, the fold never sees it.
	for i := len(rows) - 1; i >= 0; i-- {
		created := parseCHTime(rows[i]["created_at_iso"])
		if created.IsZero() {
			continue
		}
		id := strings.TrimSpace(asString(rows[i]["correlation_id_s"]))
		if !timeintel.ValidCorrelationUUID(id) {
			id = ""
		}
		pg.last = timeintel.BackfillCursor{CreatedAt: created, CorrelationID: id}
		break
	}
	return pg, nil
}

// timeIntelFetchPage reads the fold's half of one picked page: ONE bounded,
// tagged, budgeted read of the narrow current-state projection.
//
// It used to be a TREE (tracker 186 fix-2/4/5): the page was cut into 64-key
// sub-pages, a sub-page refused with 307/241 was halved down to a single key,
// a single key refused at the production block geometry was retried once at
// max_block_size=1 / max_threads=1, and an object refused even THERE was
// counted on netops_timeintel_fetch_oversize_skipped_total, named at WARN and
// SKIPPED so the watermark could still advance — i.e. a snapshot was
// deliberately dropped to keep the pass moving.
//
// All of that machinery existed to survive reading the ~5.7 KB hypotheses blob
// out of corr_objects for one missing string. Tracker 197 removed the reason
// (see timeIntelBackfillFetchSQL), so the machinery is DELETED rather than left
// dormant: there is no sub-paging, no halving, no floor retry and no skip path,
// and therefore no page that silently folds fewer objects than it picked. A
// refusal here is once again a plain error — degraded, counted by chhttp,
// resumed from the watermark by the next tick.
func (s *server) timeIntelFetchPage(ctx context.Context, keys []timeIntelBackfillKey) ([]map[string]any, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	return chWorkerQueryTuned(ctx, chWorkerRead{
		SQL:      timeIntelBackfillFetchSQL(keys),
		Tag:      timeIntelBackfillTag,
		Budget:   timeIntelBackfillBudget,
		MaxBytes: timeIntelBackfillMaxResponseBytes,
		Settings: timeIntelBackfillReadSettings(),
	})
}

// timeIntelBackfillReadSettings is the per-query budget both halves carry. A
// guard that is only in a comment is not a guard, so every one of these is
// asserted as SENT by timeintel_backfill_test.go and, for the one the workload
// profile also declares, as EFFECTIVE against a real server by
// chhttp.TestLiveQuerySettingsBeatTheProfile.
//
// Sending is not the same as taking effect, and this pass learned it the hard
// way: these settings ride the `background` workload profile (ch_workload.go),
// and until 2026-08-31 chhttp emitted `profile=` AFTER them in the query
// string, so ClickHouse applied the profile last and replaced max_memory_usage
// with the lane default of 2 GiB. Run 08311437us3b is what that cost — a single
// Select swung to 1.578 GiB, tripped the 4 GiB server overcommit and evicted two
// MergeParts. At the 512 MiB written here a runaway read is refused EARLY, long
// before it can pressure the store's own merges.
func timeIntelBackfillReadSettings() map[string]string {
	return map[string]string{
		// Bound the block geometry of both reads. This was sized when the fetch
		// dragged corr_objects.hypotheses — the only column whose per-block
		// memory was measured in hundreds of MiB — through the pass; since 197
		// both halves read the narrow projection and it is simply a modest
		// ceiling (measured 44 MiB peak for a whole 2 000-key page).
		"max_block_size": intToString(timeIntelBackfillBlockRows),
		"max_threads":    intToString(timeIntelBackfillThreads),
		// Tighter than the generic worker guard: this pass must never again be
		// the biggest thing on a 4 GiB server (storm-s07).
		"max_memory_usage": intToString(timeIntelBackfillMemoryBytes),
		// And bound the read VOLUME, which grew with retention independently of
		// memory (56.81 → 59.89 GiB, ~0.6 GiB per leg).
		"max_bytes_to_read": intToString(timeIntelBackfillReadBytes),
	}
}

// timeIntelBackfillDegraded logs a refused read and returns it unchanged.
//
// A ClickHouse refusal here is a DEGRADATION, not a crash and not an empty
// success: codes 241 (MEMORY_LIMIT_EXCEEDED) and 159 (TIMEOUT_EXCEEDED) — which
// hit 12 of 41 passes since 2026-08-30 16:57 — are classified retryable by
// chhttp, already counted on the worker's existing failure metric
// (netops_clickhouse_failures_total{class="memory_limit"|"server_timeout"},
// recorded inside chhttp's classifier), and resumed from the watermark by the
// next tick. What this adds is the pass-level context that metric cannot carry:
// which half of the pass failed, and how far the pass had got.
func timeIntelBackfillDegraded(stage string, err error, res timeIntelBackfillResult) error {
	fields := map[string]any{
		"stage": stage, "pages_done": res.Pages, "written": res.Written,
		"retryable": chhttp.Retryable(err), "err": err.Error(),
		"cursor": res.Cursor.CreatedAt.Format(time.RFC3339Nano),
	}
	var che *chhttp.Error
	if errors.As(err, &che) {
		fields["ch_code"] = che.Code
		fields["ch_class"] = che.Classification
	}
	logWarn("timeintel", "backfill pass degraded — pages already folded are kept, the watermark resumes next tick", fields)
	return err
}

// ── pass serialization & the watermark write path (ultra #6) ─────────────────

// timeIntelCursorGeneration reads the current watermark generation. A pass
// snapshots it ONCE, before loading the cursor: any later reset bumps it, and
// every save that pass attempts afterwards is refused as stale.
func (s *server) timeIntelCursorGeneration() int64 {
	s.timeIntelCursorMu.Lock()
	defer s.timeIntelCursorMu.Unlock()
	return s.timeIntelCursorGen
}

// timeIntelSaveMark persists the watermark IF the pass's generation is still
// current. The check and the write share one mutex with the reset path, so
// there is no window in which a stale save can land after a reset it did not
// see — the blind platformdb.Save that let an in-flight pass clobber a
// POST ?reset is gone.
func (s *server) timeIntelSaveMark(cursors *timeintel.BackfillCursorStore, gen int64, c timeintel.BackfillCursor) error {
	s.timeIntelCursorMu.Lock()
	defer s.timeIntelCursorMu.Unlock()
	if s.timeIntelCursorGen != gen {
		return errTimeIntelBackfillStale
	}
	return cursors.Save(c)
}

// timeIntelResetCursor is the reset path the HTTP trigger uses: it bumps the
// generation and clears the stored watermark under the same lock, so an
// in-flight pass's next save is refused rather than clobbering the reset.
//
// "Mark the pass stale" was chosen over "make the reset wait", deliberately: a
// pass's ceiling is ~21 minutes, and the reset is an explicit operator command
// whose entire point is to void the position that pass is extending — blocking
// the operator behind work the reset invalidates would be priority inversion.
// Discarding the pass is free by construction: the fold is an idempotent
// upsert, so only the discarded WATERMARK writes are lost, and losing exactly
// those is what the reset asked for.
func (s *server) timeIntelResetCursor() error {
	s.timeIntelCursorMu.Lock()
	defer s.timeIntelCursorMu.Unlock()
	s.timeIntelCursorGen++
	return timeintel.NewBackfillCursorStore("").Reset()
}

// timeIntelMaintenanceLookup builds the per-pass maintenance-window memo (item
// 121): one store read per TENANT per pass, not one per corr object.
func (s *server) timeIntelMaintenanceLookup(ctx context.Context) func(tenant, device string, at time.Time) bool {
	winsByTenant := map[string][]maintenance.Window{}
	tenantWindows := func(tenant string) []maintenance.Window {
		if s.maintWindows == nil {
			return nil
		}
		if wins, ok := winsByTenant[tenant]; ok {
			return wins
		}
		wins, err := s.maintWindows.List(ctx, tenant, false)
		if err != nil {
			// Structured (§10), and the tenant id is SANITIZED before it reaches
			// a log line: it is tenant-controlled data, so a crafted id must not
			// be able to forge log records (§8, gosec G706).
			logWarn("timeintel", "maintenance window read failed — this tenant's snapshots go out unstamped", map[string]any{
				"tenant": scrubLogValue(tenant), "err": err.Error(),
			})
			wins = nil // fail toward unstamped, never toward wrong-tenant
		}
		winsByTenant[tenant] = wins
		return wins
	}
	return func(tenant, device string, at time.Time) bool {
		wins := tenantWindows(tenant)
		for i := range wins {
			if wins[i].Covers(at, device, "", "") {
				return true
			}
		}
		return false
	}
}

// foldTimeIntelPage derives and upserts one page's snapshots. Returns how many
// were written; a store error stops the page (the cursor is not advanced).
func (s *server) foldTimeIntelPage(ctx context.Context, rows []map[string]any,
	coveredAt func(tenant, device string, at time.Time) bool, now time.Time) (int, error) {
	written := 0
	for _, o := range rows {
		corrID := strings.TrimSpace(asString(o["correlation_id"]))
		if corrID == "" {
			continue
		}
		owner := strings.ToLower(strings.TrimSpace(asString(o["owner"])))
		sig := asString(o["top_hypothesis"])
		facts := timeintel.CorrTimeFacts{
			WindowStart:     parseCHTime(o["window_start"]),
			CreatedAt:       parseCHTime(o["created_at"]),
			VerdictTier:     asString(o["verdict_tier"]),
			Owner:           owner,
			EvidenceMissing: evidenceMissingFromBlob(asString(o["evidence_missing"])),
			Confidence:      asFloat(o["top_confidence"]),
			// State is stamped by DeriveMetricRow from its own `state` argument
			// (one source of truth); only the timestamp comes from the row here.
			WindowEnd: parseCHTime(o["window_end"]),
		}
		group := timeintel.GroupKeysFromAffected(asString(o["affected"]))
		if owner != "" {
			group["provider"] = owner
		}
		if sig != "" {
			group["signature"] = sig
		}
		// Maintenance stamp (item 121): was the incident's onset inside a covering
		// window for its tenant? Site/rule are unknown at corr-object granularity,
		// so only tenant-wide and device-scoped windows can match (conservative —
		// a sites- or rules-scoped window never over-stamps).
		maint := coveredAt(asString(o["tenant_id"]), group["device"], facts.WindowStart)
		row := timeintel.DeriveMetricRow(
			asString(o["tenant_id"]), corrID, timeIntelCalcVersion,
			facts, group, asString(o["seam_type"]), asString(o["state"]), maint, now)
		if err := s.incidentTimeMetrics.Upsert(ctx, row); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

// startIncidentTimeMetricsBackfill runs the backfill on a ticker. Started only when
// a metrics store exists; cadence TIMEINTEL_BACKFILL_INTERVAL (default 15m, 0/off
// disables). The first pass runs after one interval so startup isn't perturbed.
func (s *server) startIncidentTimeMetricsBackfill(ctx context.Context) {
	if s.incidentTimeMetrics == nil {
		return
	}
	interval := envDuration("TIMEINTEL_BACKFILL_INTERVAL", 15*time.Minute)
	if interval <= 0 {
		return // explicitly disabled
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				cctx, cancel := context.WithTimeout(ctx, timeIntelBackfillPassTimeout)
				res, err := s.backfillIncidentTimeMetrics(cctx, timeIntelBackfillLookback)
				cancel()
				// A failed pass NEVER takes the worker down: the watermark is
				// durable, so the next tick resumes exactly where this one
				// stopped. The failure itself is already counted by chhttp's
				// classifier; this line carries the pass-level context.
				if err != nil {
					if errors.Is(err, errTimeIntelBackfillInFlight) || errors.Is(err, errTimeIntelBackfillStale) {
						// Coordination outcomes (ultra #6), not faults: another
						// pass is doing the work, or an operator reset voided
						// this one. The next tick starts clean.
						logInfo("timeintel", "backfill pass yielded", map[string]any{
							"written": res.Written, "pages": res.Pages, "reason": err.Error(),
						})
						continue
					}
					logWarn("timeintel", "backfill pass ended early — resuming from the watermark next tick", map[string]any{
						"written": res.Written, "pages": res.Pages,
						"retryable": chhttp.Retryable(err), "err": err.Error(),
					})
					continue
				}
				if res.Pages > 0 {
					logInfo("timeintel", "backfill pass complete", map[string]any{
						"written": res.Written, "pages": res.Pages, "caught_up": res.CaughtUp,
						"cursor": res.Cursor.CreatedAt.Format(time.RFC3339Nano),
					})
				}
			}
		}
	}()
}

// ── HTTP: /api/reliability/time-metrics ───────────────────────────────────────

// handleReliabilityTimeMetrics serves the persisted phase-metric snapshots.
//
//	GET  — list the CALLER's own snapshots (tenant-scoped, default-closed).
//	POST — trigger a backfill pass. This recomputes across ALL tenants, so it is
//	       platform-admin only (CLAUDE.md §3a: a cross-tenant worker operation is
//	       platform-global plumbing, not per-tenant data). `?reset=true` clears
//	       the watermark first, so the next passes re-derive the whole lookback
//	       window (an explicit operator action, e.g. a calc-version bump).
func (s *server) handleReliabilityTimeMetrics(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		if _, ok := s.requirePlatformAdmin(w, r); !ok {
			return
		}
		if s.incidentTimeMetrics == nil {
			writeError(w, http.StatusConflict, errors.New("metrics store unavailable"))
			return
		}
		lookback := timeIntelBackfillLookback
		if d := strings.TrimSpace(r.URL.Query().Get("lookback")); d != "" {
			if pd, err := time.ParseDuration(d); err == nil && pd > 0 {
				lookback = pd
			}
		}
		if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("reset")), "true") {
			// The generation-bumping reset path (ultra #6): an in-flight pass's
			// later watermark saves are refused as stale, so a slow ticker pass
			// can never clobber this reset with its pre-reset position.
			if err := s.timeIntelResetCursor(); err != nil {
				writeError(w, http.StatusBadGateway, err)
				return
			}
		}
		// Bound the manual pass exactly as the ticker does (§9: all IO has a
		// timeout). A page loop is longer than a request normally is, so the
		// ceiling is stated here rather than left to the server's write deadline.
		pctx, cancel := context.WithTimeout(r.Context(), timeIntelBackfillPassTimeout)
		defer cancel()
		res, err := s.backfillIncidentTimeMetrics(pctx, lookback)
		if err != nil {
			if errors.Is(err, errTimeIntelBackfillInFlight) || errors.Is(err, errTimeIntelBackfillStale) {
				// Coordination, not failure: another pass holds the inflight
				// guard (its work covers this request, and any reset above
				// already stands, protected by the generation), or a reset
				// voided this pass mid-flight.
				writeError(w, http.StatusConflict, err)
				return
			}
			writeError(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"written": res.Written, "pages": res.Pages, "caught_up": res.CaughtUp,
			"cursor": res.Cursor.CreatedAt, "lookback": lookback.String(),
		})
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		if s.incidentTimeMetrics == nil {
			writeJSON(w, http.StatusOK, map[string]any{"snapshots": []incidentTimeMetricRow{}})
			return
		}
		tenant, cross := principalTenant(claims)
		// Fail closed (F-71/F-74 rule): a malformed or over-cap limit used to be
		// discarded, so a caller asking for MORE silently received the default.
		limit, lerr := intQuery(r, "limit", 500, 1, timeIntelBackfillCap)
		if lerr != nil {
			writeError(w, http.StatusBadRequest, lerr)
			return
		}
		rowsOut, err := s.incidentTimeMetrics.List(r.Context(), tenant, cross, limit)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"snapshots": rowsOut})
	default:
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}
