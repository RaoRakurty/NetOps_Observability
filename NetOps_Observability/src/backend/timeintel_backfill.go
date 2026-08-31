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
// re-parsing the hypotheses blob.
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
	// worker rather than a one-line lookup. The pick and the wide fetch carry
	// SEPARATE tags for the same reason: on storm-s07 the two halves of this
	// pass had wildly different costs and only one aggregate number to show it.
	timeIntelBackfillTag     = "worker:timeintel-backfill"
	timeIntelBackfillPickTag = "worker:timeintel-backfill-pick"

	// ── page geometry (tracker 186 clause 2) ──────────────────────────────────
	//
	// timeIntelBackfillPageRows is the objects fetched by ONE wide read, and
	// timeIntelBackfillMaxPages bounds a pass. Their product is deliberately
	// timeIntelBackfillCap (20 000), the old single-shot cap: a pass still does
	// at most the same amount of work, but it does it in ten bounded steps that
	// each advance the watermark, instead of one step that re-read the same
	// oldest 20 000 objects forever.
	//
	// 2 000 is chosen from the storm-s07 measurement rather than taste: that
	// pass read 1 931 054 rows / 35.4 GB and peaked at 1.86 GiB for 20 000
	// objects. The wide half of the read is linear in objects picked (the
	// hypotheses blob is fetched per picked row), so a tenth of the page is a
	// tenth of the peak — see timeIntelBackfillMemoryBytes.
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
	// before chClientForBudget. Two reads per page (pick + fetch), hence the 2x.
	timeIntelBackfillPassTimeout = timeIntelBackfillMaxPages*
		(2*timeIntelBackfillBudget+timeIntelBackfillPagePause) + 60*time.Second

	// timeIntelBackfillBlockRows / timeIntelBackfillThreads bound the WIDE part
	// of the read. corr_objects.hypotheses is 48 GiB uncompressed / 26 KB per
	// row average with 49 MiB outliers under a storm, so a default 8192-row
	// block of that one column is ~256 MiB — per reading thread. Measured on
	// the live table: default blocks/threads peaked at 1.8 GiB (and was refused
	// at the 2 GiB cap); 1024 rows x 2 threads peaks at 447-484 MiB.
	timeIntelBackfillBlockRows = 1024
	timeIntelBackfillThreads   = 2

	// timeIntelBackfillMemoryBytes is this worker's OWN per-query memory ceiling,
	// tighter than the generic 1 GiB worker guard (chWorkerReadMemoryBytes).
	//
	// The arithmetic, from the storm-s07 number rather than a round guess:
	// 1.86 GiB was measured for a 20 000-object page. The wide read's cost is
	// linear in objects picked, so the page-linear share of a 2 000-object page
	// is 1.86 GiB / 10 = 190 MiB. On top of that sits a page-INDEPENDENT floor —
	// max_block_size(1024) x max_threads(2) x the 26 KB average blob is ~53 MiB
	// of in-flight blocks, and a single 49 MiB outlier row lands inside one of
	// them. 190 + 53 + outlier headroom, doubled so a fatter-than-average page
	// fails on its own merits and not on a stingy ceiling, gives 512 MiB.
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
	// growth: a legitimate page reads the hypotheses blobs of ~2 000 objects
	// inside a created_at slice of minutes, ~50-500 MB depending on granule
	// density, so 2 GiB is roughly 4-40x headroom over a healthy page and 17x
	// UNDER the observed regression. Tripping it is loud (TOO_MANY_BYTES) and
	// costs one pass, which the watermark then resumes.
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
	timeIntelBackfillMaxResponseBytes = 8 << 20

	// timeIntelBackfillPickResponseBytes bounds the narrow pick's body: four
	// small columns, ~140 B/row, so a 2 000-row page is ~280 KB. 2 MiB is 7x
	// that and still two orders of magnitude under the old single parse.
	timeIntelBackfillPickResponseBytes = 2 << 20

	// timeIntelBackfillWatermarkSlack is how far BEHIND the stored cursor each
	// pass restarts. See timeintel.BackfillCursor.Rewind: corr_current is also
	// written by corr_current_reconcile.go, which repairs a drifted projection
	// row HOURLY and carries the object's ORIGINAL created_at across — so a row
	// can land in corr_current already behind the mark. Two hours = one
	// reconcile period plus one missed one. Re-reading that slice is free by
	// construction: the fold is an idempotent upsert on the snapshot PK.
	timeIntelBackfillWatermarkSlack = 2 * time.Hour

	// timeIntelBackfillFetchSlackSeconds widens the created_at slice the wide
	// fetch reads, around the picked page's own [min,max].
	//
	// The dual-write carries corr_objects.created_at VERBATIM into corr_current
	// (chschema.CorrCurrentNarrowInsertPrefix selects o.created_at), so the two
	// values are equal for the same (tenant, correlation, version) and the
	// honest slack is zero. 60 s is defence against a row written by an older
	// writer that let the column DEFAULT fire. It costs nothing: corr_objects
	// is partitioned by toYYYYMMDD(created_at), so a minute of slack widens the
	// scan by at most one partition at each end.
	timeIntelBackfillFetchSlackSeconds = 60
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
//  2. SPLIT. The pick runs on its own, so Go learns the page's exact
//     [min,max] created_at and can bound the wide fetch to that slice —
//     partition pruning on corr_objects' toYYYYMMDD(created_at) that a single
//     query could only have got by re-evaluating the pick as a scalar subquery
//     twice more.
//
// The split also removes a STALL: the cursor advances from what the PICK
// returned, not from what the fetch found. An object whose history row has
// already aged out of corr_objects would otherwise hold the watermark still and
// be re-picked forever.

// timeIntelBackfillPickSQL builds the NARROW pick: the next page of objects
// past the cursor, in cursor order. No wide column may ever appear here (#100
// rule 2b) — this half exists precisely so the wide half can be keyed.
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

// timeIntelBackfillFetchSQL builds the WIDE fetch for one picked page: the
// hypotheses-derived fields for exactly the keys picked, inside the page's own
// created_at slice.
//
// Two independent bounds, both required. The key tuple leads with tenant_id so
// the corr_objects primary key prefix (tenant_id, correlation_id, version) is
// usable; the created_at range prunes PARTITIONS (corr_objects is partitioned
// on toYYYYMMDD(created_at), chschema/corr_repartition.go), which is what stops
// a page from touching every retained day the way the un-watermarked pass did.
func timeIntelBackfillFetchSQL(keys []timeIntelBackfillKey, from, to time.Time) string {
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
	slack := intToString(timeIntelBackfillFetchSlackSeconds)
	return `
SELECT toString(o.tenant_id)      AS tenant_id,
       toString(o.correlation_id) AS correlation_id,
       ` + chschema.ISO("o.window_start") + ` AS window_start,
       ` + chschema.ISO("o.created_at") + `   AS created_at,
       o.verdict_tier             AS verdict_tier,
       o.top_confidence           AS top_confidence,
       o.top_hypothesis           AS top_hypothesis,
       o.evidence_missing         AS evidence_missing,
       o.affected                 AS affected,
       o.state                    AS state,
       JSONExtractString(o.hypotheses,'ranking','hypotheses',1,'verdict','owner') AS owner,
       JSONExtractString(o.hypotheses,'grounding_context','seams',1,'seam_type')  AS seam_type
  FROM netops.corr_objects AS o
 WHERE o.created_at >= ` + timeIntelCHDateTime64(from) + ` - INTERVAL ` + slack + ` SECOND
   AND o.created_at <= ` + timeIntelCHDateTime64(to) + ` + INTERVAL ` + slack + ` SECOND
   AND (o.tenant_id, o.correlation_id, o.version) IN (` + tuples.String() + `)
 FORMAT JSON`
	// NO ORDER BY. The row loop upserts each snapshot independently, keyed by
	// (tenant, correlation, calc version), so iteration order cannot change what
	// is stored — while sorting the result set forces the reader to hold blocks
	// of the wide hypotheses column alive across the whole scan. Measured on the
	// live storm table with identical settings: 971 MiB peak with the ORDER BY
	// (and a MEMORY_LIMIT_EXCEEDED at the 1 GiB ceiling) versus 501 MiB without.
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
		cursors: cursors, mark: stored, res: &res,
	}

	forwardPages := timeIntelBackfillMaxPages
	// PHASE 1 — the bounded re-scan behind the mark. Skipped on a cold pass
	// (there is nothing behind a zero mark) and capped at
	// timeIntelBackfillRescanPages so it can never eat the forward budget.
	if !stored.IsZero() {
		forwardPages -= timeIntelBackfillRescanPages
		if _, err := pass.run(ctx, stored.Rewind(timeIntelBackfillWatermarkSlack),
			timeIntelBackfillRescanPages, false); err != nil {
			return res, err
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
		keys, err := p.srv.timeIntelPickPage(ctx, p.lookbackSeconds, page, until)
		if err != nil {
			return false, timeIntelBackfillDegraded("pick", err, *p.res)
		}
		if len(keys) == 0 {
			return true, nil
		}
		rows, err := p.srv.timeIntelFetchPage(ctx, keys)
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
		p.res.Pages++

		last := keys[len(keys)-1]
		page = timeintel.BackfillCursor{CreatedAt: last.CreatedAt, CorrelationID: last.CorrelationID}
		if advance {
			p.mark = p.mark.Advance(last.CreatedAt, last.CorrelationID, p.now)
			if err := p.cursors.Save(p.mark); err != nil {
				// Durable progress failed. Stop rather than keep folding pages
				// the next pass would redo anyway — and say so.
				logError("timeintel", "backfill watermark could not be persisted — pass stopped; the next pass will redo these pages", errf(err))
				return false, fmt.Errorf("timeintel backfill cursor save: %w", err)
			}
			p.res.Cursor = p.mark
		}
		if len(keys) < timeIntelBackfillPageRows {
			return true, nil
		}
	}
	return false, nil
}

// timeIntelPickPage reads the next page of object keys past `from`, optionally
// stopping at `until` (the re-scan phase's ceiling; a zero value = no ceiling).
func (s *server) timeIntelPickPage(ctx context.Context, lookbackSeconds int, from, until timeintel.BackfillCursor) ([]timeIntelBackfillKey, error) {
	rows, err := chWorkerQueryTuned(ctx, chWorkerRead{
		SQL:      timeIntelBackfillPickSQL(lookbackSeconds, timeIntelBackfillPageRows, from, until),
		Tag:      timeIntelBackfillPickTag,
		Budget:   timeIntelBackfillBudget,
		MaxBytes: timeIntelBackfillPickResponseBytes,
		Settings: timeIntelBackfillReadSettings(),
	})
	if err != nil {
		return nil, err
	}
	out := make([]timeIntelBackfillKey, 0, len(rows))
	for _, r := range rows {
		// The pick projects NON-SHADOWING aliases on purpose (see
		// timeIntelBackfillPickSQL); these are those names, not the column names.
		id := strings.TrimSpace(asString(r["correlation_id_s"]))
		created := parseCHTime(r["created_at_iso"])
		// Zero trust on upstream rows (§3): a key that cannot be rendered as a
		// safe literal, or that carries no cursor position, is skipped rather
		// than interpolated. Skipping is safe — the page's LAST key still
		// advances the watermark past it.
		if !timeintel.ValidCorrelationUUID(id) || created.IsZero() {
			continue
		}
		out = append(out, timeIntelBackfillKey{
			TenantID:      asString(r["tenant_id_s"]),
			CorrelationID: id,
			Version:       int(asFloat(r["version"])),
			CreatedAt:     created,
		})
	}
	return out, nil
}

// timeIntelFetchPage reads the wide half for one picked page.
func (s *server) timeIntelFetchPage(ctx context.Context, keys []timeIntelBackfillKey) ([]map[string]any, error) {
	// The pick is ordered by created_at ASC, so the page's slice is [first,last].
	from, to := keys[0].CreatedAt, keys[len(keys)-1].CreatedAt
	if to.Before(from) {
		from, to = to, from
	}
	// Extract owner + seam_type server-side (JSONExtractString) instead of
	// pulling the whole hypotheses blob per object — at scale the blobs would
	// blow past the response cap and truncate.
	return chWorkerQueryTuned(ctx, chWorkerRead{
		SQL:      timeIntelBackfillFetchSQL(keys, from, to),
		Tag:      timeIntelBackfillTag,
		Budget:   timeIntelBackfillBudget,
		MaxBytes: timeIntelBackfillMaxResponseBytes,
		Settings: timeIntelBackfillReadSettings(),
	})
}

// timeIntelBackfillReadSettings is the per-query budget both halves carry. A
// guard that is only in a comment is not a guard, so every one of these is
// asserted on the wire by timeintel_backfill_test.go.
func timeIntelBackfillReadSettings() map[string]string {
	return map[string]string{
		// Bound the WIDE half of the read: hypotheses is the only column whose
		// per-block memory is measured in hundreds of MiB.
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
			if err := timeintel.NewBackfillCursorStore("").Reset(); err != nil {
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
