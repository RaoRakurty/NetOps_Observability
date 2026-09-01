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
	// before chClientForBudget.
	//
	// A page is now ONE pick (bounded by the page budget) plus a fetch that is a
	// TREE of sub-fetches (186 fix-2), bounded as a whole by
	// timeIntelBackfillFetchSplitDeadline rather than by a single query budget —
	// so the derivation names those two terms instead of the old "2 reads per
	// page". Stating the fetch's own ceiling here is what keeps this honest: the
	// pass timeout must always exceed what the page loop is allowed to spend, or
	// it silently becomes the real bound and pages die mid-tree.
	timeIntelBackfillPassTimeout = timeIntelBackfillMaxPages*
		(timeIntelBackfillBudget+timeIntelBackfillFetchSplitDeadline+timeIntelBackfillPagePause) +
		60*time.Second

	// timeIntelBackfillBlockRows / timeIntelBackfillThreads bound the WIDE part
	// of the read. corr_objects.hypotheses is 48 GiB uncompressed / 26 KB per
	// row average with 49 MiB outliers under a storm, so a default 8192-row
	// block of that one column is ~256 MiB — per reading thread. Measured on
	// the live table: default blocks/threads peaked at 1.8 GiB (and was refused
	// at the 2 GiB cap); 1024 rows x 2 threads peaks at 447-484 MiB.
	timeIntelBackfillBlockRows = 1024
	timeIntelBackfillThreads   = 2

	// timeIntelBackfillNarrowBlockRows / timeIntelBackfillNarrowThreads are the
	// geometry of the ONE extra query the splitter spends at its floor before
	// writing an object off as unreadable (186 fix-5).
	//
	// MEASURED live 2026-08-31 (fix-4): the ~2 objects per 2 000-key page that
	// are refused at EVERY key count under 1024x2 are NOT big themselves —
	// tracker 195 measured the four earlier victims at 22-30 KiB of hypotheses
	// each, dying at read_rows = 0 while allocating a 536 870 912-byte chunk.
	// The size belongs to their GRANULE NEIGHBOURS: corr_objects holds storm
	// aggregates up to 76 MiB against a 29 KiB mean, and a 1024-row block sized
	// for those neighbours is what overruns the ceiling. Read one row per block
	// and the neighbours are never in flight: both objects probed read CLEANLY
	// at max_block_size=1, max_threads=1 — 162 and 284 MiB peak, ~2.5 s each,
	// well inside the same 512 MiB / 2 GiB / 30 s budget the wide read carries.
	//
	// One row per block on one thread is the floor of the geometry, so a
	// refusal that survives it is a property of the object and not of how we
	// asked for it. That is the whole point: after this retry,
	// netops_timeintel_fetch_oversize_skipped_total{reason="oversize"} means
	// IRREDUCIBLE, and every non-zero sample is worth an operator's time.
	timeIntelBackfillNarrowBlockRows = 1
	timeIntelBackfillNarrowThreads   = 1

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

	// ── adaptive fetch sub-paging (tracker 186 fix-2) ─────────────────────────
	//
	// The 2026-08-31 deploy proved the page geometry above was still wrong on
	// its widest axis. The pick works and is cheap (2 000 keys, ~30 MiB), but a
	// SINGLE wide fetch for those 2 000 keys read 2.24 GiB in the deploy log and
	// was refused with Code 307 TOO_MANY_BYTES — on EVERY tick, identically,
	// because the pass is deterministic. pages=0, no watermark write, a
	// permanent stall: the exact failure mode the watermark was introduced to
	// end, one layer down. Reproduced the same day against the live table:
	// 69 355 rows / 2.01 GiB read, 488 MiB peak, refused at the 2.00 GiB cap in
	// 1.77 s — see TestTimeIntelBackfillWholePageFetchIsRefusedByLiveClickHouse,
	// which now asserts that refusal rather than merely remembering it.
	//
	// WHY 2 000 KEYS CAN NEVER FIT, which is the fact the c189d37e budget math
	// missed. That math assumed ~1 KB/row. The real unit is not a row, it is a
	// GRANULE of the hypotheses blob. corr_objects has adaptive granularity
	// (index_granularity_bytes = 10 MB) over a 70 GiB / 2.38 M-row blob column,
	// so a granule is ~400 rows and ~10-12 MiB, and the picked correlation_ids
	// are UUIDs scattered across the whole (tenant_id, correlation_id, version)
	// key space — one key lands in one granule and shares it with nobody.
	//
	//	bytes(fetch) ~= 12 MiB x distinct granules ~= 12 MiB x keys
	//
	// MEASURED live 2026-08-31 on the 2.38 M-row table: 125 keys read 1.22-1.45
	// GiB, 64 keys read 675-795 MiB. So the read cap alone permits at most ~170
	// keys per query and the 512 MiB memory cap bites first — 2 000 keys is
	// ~14x over, not marginally over. NO retry, NO budget bump and NO amount of
	// waiting fixes that; only a smaller key list does.
	//
	// So the fetch SUB-PAGES the pick's page up front instead of discovering the
	// same refusal every tick, and halves adaptively when a sub-page is still
	// refused. The pick's page size deliberately stays 2 000 (it is cheap, and
	// it is what makes the watermark advance in useful strides).
	//
	// timeIntelBackfillFetchSubPageKeys is that first cut. 64 from the
	// measurement, not from taste: at 64 keys a sub-fetch reads ~700 MiB (2.9x
	// under the 2 GiB read cap) and peaks at 79-253 MiB (2-6x under the 512 MiB
	// memory cap), where 125 keys sat at 1.2-1.4 GiB / 412+ MiB and was refused
	// on 3 of 16 sub-pages. Over the same 2 000-key page: 64 read 24.85 GiB in
	// 30.6 s, 125 read 28.4 GiB in 33.4 s — the smaller cut is cheaper BECAUSE
	// a refused sub-fetch still pays for the granules it read before the refusal.
	//
	// RE-MEASURED 2026-08-31 (186 fix-4) across 32/64/125-key arms over the same
	// live page: 64 remained the cheapest arm end-to-end, so this stays a
	// MEASURED literal rather than a value derived from the memory budget. A
	// derived cut would have to re-derive the granule constant to land on 64
	// anyway, and would then need its clamp floor lifted to
	// ceil(pageRows/maxSubFetches) so no page could exhaust the sub-fetch tree —
	// two moving parts bought for nothing while the measurement holds.
	timeIntelBackfillFetchSubPageKeys = 64

	// timeIntelBackfillFetchSplitMinKeys is where halving stops. ONE key, not a
	// round "min sublist" — because the live evidence says the poison is a
	// single object, not a neighbourhood. Halving a refused sub-page all the way
	// down isolated exactly 4 objects out of 2 000 whose own blob overruns the
	// 512 MiB ceiling by itself (a one-key fetch that reads 0 bytes and still
	// dies allocating a 512 MiB chunk while reading column hypotheses).
	//
	// Stopping at a coarser floor would throw away the ~31 healthy objects
	// sharing that floor's sublist AND would report a 32-wide id list instead of
	// naming the one object an operator has to go look at.
	timeIntelBackfillFetchSplitMinKeys = 1

	// timeIntelBackfillFetchSplitMaxDepth is a belt-and-braces bound on the
	// recursion. 64 -> 1 is six halvings; 8 leaves headroom without ever being
	// the thing that stops a descent (the min-keys floor is).
	timeIntelBackfillFetchSplitMaxDepth = 8

	// timeIntelBackfillFetchMaxSubFetches bounds the QUERY COUNT one page's
	// fetch tree may spend on the server — the load axis, which the wall-clock
	// deadline below does not bound on its own (a tree of cheap 40 ms refusals
	// could run hundreds of queries inside the deadline).
	//
	// MEASURED with the production splitter over the worst live 2 000-key page:
	// 80 sub-fetches (32 sub-pages + 24 splits and their halves) to fold 1 996
	// of 2 000 objects. 192 is 2.4x that, and a page that needs more is not fat,
	// it is broken.
	//
	// The floor's narrow retry (186 fix-5) draws on this same cap — at most one
	// extra query per floor refusal, ~2 per page live — and is bounded by it on
	// purpose: a page whose every object needs re-shaping must still cost a
	// bounded number of queries.
	timeIntelBackfillFetchMaxSubFetches = 192

	// timeIntelBackfillFetchSplitDeadline bounds the whole tree in WALL CLOCK.
	//
	// Hitting it is a DEGRADATION, never an error: the keys not yet fetched are
	// counted and logged, the page folds what it has, and the watermark still
	// advances — which is the entire point of this fix. Making it an error would
	// reinstate the stall on any page that is merely slow.
	//
	// But a skip is DATA LOSS (a snapshot that will not be written), so this
	// must only fire on a genuinely pathological page, never on a fat one.
	// MEASURED end-to-end with the production splitter over the worst live
	// 2 000-key page: 80 sub-fetches, 24 splits, 48.0 s — and that is over the
	// docker-exec path, which pays a process spawn per query that the worker's
	// HTTP client does not. 3x the page budget is ~1.9x over that pessimistic
	// number.
	//
	// The consequence, stated rather than discovered later: with 10 pages the
	// derived pass timeout is ~21 min, longer than the 15-minute tick. That is
	// the CEILING for an all-pathological backlog drain, not the normal case (a
	// clean page is ~32 sub-fetches, ~15 s), and it is harmless by construction
	// — the ticker drops missed ticks, and every page has already persisted its
	// watermark, so back-to-back passes resume rather than repeat.
	timeIntelBackfillFetchSplitDeadline = 3 * timeIntelBackfillBudget

	// timeIntelBackfillSkipLogIDs caps how many correlation_ids one page's WARN
	// line carries. Sanitize/bound all logs (§8): a fully poisoned page must not
	// be able to emit a 2 000-id log record.
	timeIntelBackfillSkipLogIDs = 16
)

// ClickHouse DB::Exception codes the fetch splitter reacts to. Both mean "this
// key list is too wide for the per-query guard rails" and both are fixed by the
// same action — fetch fewer keys — which is why they share one branch.
//
// They are NOT handled by retrying: 307 is deterministic (the same key list
// reads the same granules and trips the same cap forever), and 241 here is
// "Memory limit (for query) exceeded … while reading column hypotheses", i.e.
// also a property of the key list, not of the moment. chhttp classifies 241 as
// retryable for its other callers and does not classify 307 at all; neither
// judgement is wrong there, and neither is useful here.
//
// The floor's narrow retry (186 fix-5) is not an exception to that. It re-asks
// with a DIFFERENT read geometry (one row per block, one thread) on identical
// memory/bytes/time budgets, which is a different question — not the same one
// asked twice in the hope of a different mood.
const (
	chCodeTooManyBytes        = 307 // TOO_MANY_BYTES — max_bytes_to_read tripped
	chCodeMemoryLimitExceeded = 241 // MEMORY_LIMIT_EXCEEDED — max_memory_usage tripped
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
//
// ── WHAT THE FOLD ACTUALLY NEEDS (checked 2026-08-31, 186 fix-2) ──────────────
//
// foldTimeIntelPage reads exactly twelve values off each row: tenant_id,
// correlation_id, window_start, created_at, verdict_tier, top_confidence,
// top_hypothesis, evidence_missing, affected, state — and owner + seam_type,
// which are JSON-extracted from the hypotheses blob. Nothing here is
// speculative, so no column can be dropped to make the read cheaper; the two
// blob extractions are pinned by
// TestTimeIntelBackfillFetchSelectsOnlyWhatTheFoldNeeds.
//
// That matters because `hypotheses` is 94 % of this table and the ENTIRE reason
// the fetch has to be sub-paged. The structural follow-up, recorded here so the
// measurement is not lost: netops.corr_current — which the PICK already reads,
// one narrow row per object — carries ten of those twelve (it gained a narrow
// `owner` column with the #100 triage badges). Only seam_type is missing. If
// the engine ever projected seam_type onto corr_current the way it projected
// owner, this wide read against corr_objects would disappear entirely, and with
// it ~25 GiB of granule reads per page. That is an ENGINE change (a new
// persist-time projection + a backfill), out of this fix's bounded context.
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

// timeIntelFetchKeys is ONE wide read for one key list — the indivisible unit
// the splitter sub-pages and halves. A named function type rather than a method
// value so the live-shape suite can drive the real splitter against a real
// server without the HTTP client (§2: external dependencies are injected).
//
// narrow selects the FLOOR geometry (max_block_size=1, max_threads=1) instead
// of the production one. Every other budget on the wire — memory, bytes, time —
// is identical either way, so a narrow fetch is a differently SHAPED read of
// the same size, never a bigger one.
type timeIntelFetchKeys func(ctx context.Context, keys []timeIntelBackfillKey, narrow bool) ([]map[string]any, error)

// timeIntelFetchOne is the production timeIntelFetchKeys: one bounded, tagged,
// budgeted wide read.
func (s *server) timeIntelFetchOne(ctx context.Context, keys []timeIntelBackfillKey,
	narrow bool) ([]map[string]any, error) {
	from, to := timeIntelKeySpan(keys)
	settings := timeIntelBackfillReadSettings()
	if narrow {
		settings = timeIntelBackfillNarrowReadSettings()
	}
	// Extract owner + seam_type server-side (JSONExtractString) instead of
	// pulling the whole hypotheses blob per object — at scale the blobs would
	// blow past the response cap and truncate.
	return chWorkerQueryTuned(ctx, chWorkerRead{
		SQL:      timeIntelBackfillFetchSQL(keys, from, to),
		Tag:      timeIntelBackfillTag,
		Budget:   timeIntelBackfillBudget,
		MaxBytes: timeIntelBackfillMaxResponseBytes,
		Settings: settings,
	})
}

// timeIntelKeySpan is the [min,max] created_at of a key list — the partition
// bound the wide fetch is pruned with.
//
// A true min/max scan, NOT keys[0]/keys[last]. The page as picked is created_at
// ASC so the endpoints would do, but the splitter hands this function ARBITRARY
// sublists, and a bound derived from the wrong two elements would silently
// exclude rows from the slice and lose their snapshots. Cheap, and it removes
// an ordering assumption from a function that no longer gets to make one.
func timeIntelKeySpan(keys []timeIntelBackfillKey) (time.Time, time.Time) {
	if len(keys) == 0 {
		return time.Time{}, time.Time{}
	}
	from, to := keys[0].CreatedAt, keys[0].CreatedAt
	for _, k := range keys[1:] {
		if k.CreatedAt.Before(from) {
			from = k.CreatedAt
		}
		if k.CreatedAt.After(to) {
			to = k.CreatedAt
		}
	}
	return from, to
}

// timeIntelFetchSplittable reports whether err is a "this key list is too wide"
// refusal — the one class the splitter can act on. Anything else (a schema
// fault, auth, a transport loss) is returned to the caller unchanged: halving a
// key list cannot fix a broken query, and pretending it might would turn one
// loud failure into a hundred quiet ones.
func timeIntelFetchSplittable(err error) bool {
	var che *chhttp.Error
	if !errors.As(err, &che) {
		return false
	}
	return che.Code == chCodeTooManyBytes || che.Code == chCodeMemoryLimitExceeded
}

// timeIntelFetchSplit is one page's fetch tree: the accumulated rows, what it
// had to give up on, and the two budgets that bound it.
type timeIntelFetchSplit struct {
	fetch timeIntelFetchKeys
	rows  []map[string]any

	fetches int // sub-fetches issued (bounded by timeIntelBackfillFetchMaxSubFetches)
	splits  int // sub-fetches that were refused and halved

	// narrowRetries counts floor refusals RESCUED by the narrow-geometry retry
	// (186 fix-5) — objects that would have been skipped as oversize before it.
	// It is the fix's own evidence: > 0 means data that used to be lost is
	// being folded, and 0 on a page with oversize skips means the retry was
	// tried and the object really is irreducible.
	narrowRetries int

	oversizeSkipped int      // objects refused even at the FLOOR geometry (irreducible)
	budgetSkipped   int      // objects the tree ran out of budget before reaching
	skippedIDs      []string // bounded sample for the WARN line
}

// timeIntelFetchPage reads the wide half for one picked page, sub-paged and
// adaptively split so a page that cannot be read WHOLE still advances the
// watermark (tracker 186 fix-2).
//
// The contract, in order of precedence:
//
//  1. A refusal that halving can fix (307/241) is NEVER returned as an error —
//     it is split. This is what makes a fat page cost extra queries instead of
//     costing the watermark.
//  2. At the floor, a single object the production block geometry still cannot
//     read is retried ONCE at max_block_size=1 / max_threads=1 on the same
//     budgets (186 fix-5) — the shape most of these refusals actually are.
//     Success folds the row and counts netops_timeintel_fetch_narrow_retries_total.
//  3. An object refused even THERE is skipped, counted on
//     netops_timeintel_fetch_oversize_skipped_total, named at WARN, and the
//     page continues. One poisoned blob must not be able to hold the whole
//     backfill still — which is precisely what it did before this change.
//  4. Any OTHER error is returned unchanged, so a genuine fault (schema, auth)
//     stays as loud as it was.
func (s *server) timeIntelFetchPage(ctx context.Context, keys []timeIntelBackfillKey) ([]map[string]any, error) {
	return s.timeIntelFetchPageWith(ctx, keys, s.timeIntelFetchOne)
}

// timeIntelFetchPageWith is timeIntelFetchPage over an injected one-shot fetch.
func (s *server) timeIntelFetchPageWith(ctx context.Context, keys []timeIntelBackfillKey,
	one timeIntelFetchKeys) ([]map[string]any, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	// The tree's own wall-clock ceiling, strictly inside the pass context so a
	// cancelled PASS and an exhausted FETCH stay distinguishable (§9).
	fctx, cancel := context.WithTimeout(ctx, timeIntelBackfillFetchSplitDeadline)
	defer cancel()

	sp := &timeIntelFetchSplit{fetch: one, rows: make([]map[string]any, 0, len(keys))}
	for start := 0; start < len(keys); start += timeIntelBackfillFetchSubPageKeys {
		end := start + timeIntelBackfillFetchSubPageKeys
		if end > len(keys) {
			end = len(keys)
		}
		if err := sp.run(ctx, fctx, keys[start:end], 0); err != nil {
			// A non-splittable fault, or the PASS itself being cancelled. Report
			// what the tree did before it stopped, then surface the error.
			s.recordTimeIntelFetchSplit(sp)
			return nil, err
		}
	}
	s.recordTimeIntelFetchSplit(sp)
	return sp.rows, nil
}

// run fetches one sublist, halving it on a 307/241 refusal until it fits or
// until a single key is left — and, at that floor, retrying once at the
// narrowest block geometry before giving up on the object. Returns an error
// ONLY for faults the splitter must not swallow.
//
// TWO contexts, deliberately. pass is the whole pass's — its cancellation is a
// real error and must reach the caller, because a half-fetched page must never
// be read as a complete one. tree is the fetch tree's own deadline, strictly
// inside it — its expiry is a DEGRADATION, counted and logged, and the page
// still completes. Collapsing them into one would make a slow page
// indistinguishable from a shutdown.
func (sp *timeIntelFetchSplit) run(pass, tree context.Context, keys []timeIntelBackfillKey, depth int) error {
	if len(keys) == 0 {
		return nil
	}
	if err := pass.Err(); err != nil {
		return err
	}
	// The tree's deadline, and the query-count cap, are degradations: give up on
	// the rest of this sublist, count it, and let the page complete.
	if tree.Err() != nil || sp.fetches >= timeIntelBackfillFetchMaxSubFetches {
		sp.giveUp(keys, &sp.budgetSkipped)
		return nil
	}

	sp.fetches++
	rows, err := sp.fetch(tree, keys, false)
	if err == nil {
		sp.rows = append(sp.rows, rows...)
		return nil
	}
	if !timeIntelFetchSplittable(err) {
		return err
	}
	if len(keys) <= timeIntelBackfillFetchSplitMinKeys || depth >= timeIntelBackfillFetchSplitMaxDepth {
		// THE FLOOR. Halving has no moves left — but "too wide" and "read the
		// wrong shape" are different questions, and only the first one has been
		// asked so far. MEASURED live (186 fix-4): an object refused at EVERY
		// key count is refused while allocating a 512 MiB chunk for column
		// hypotheses at read_rows = 0 — its granule neighbours' size, not its
		// own (tracker 195) — and both objects probed read cleanly at
		// max_block_size=1 / max_threads=1 inside the same budget. So spend ONE
		// more query at the floor geometry before writing the object off.
		//
		// This is not the retry the const block rules out: the budgets on the
		// wire are unchanged, so the same refusal is not being re-asked in the
		// hope of a different mood — a different, smaller-grained read is.
		if err := pass.Err(); err != nil {
			return err
		}
		if tree.Err() == nil && sp.fetches < timeIntelBackfillFetchMaxSubFetches {
			sp.fetches++
			rows, nerr := sp.fetch(tree, keys, true)
			switch {
			case nerr == nil:
				sp.narrowRetries++
				sp.rows = append(sp.rows, rows...)
				return nil
			case !timeIntelFetchSplittable(nerr):
				// Same contract as the wide read (4 above): a fault is never
				// swallowed just because it surfaced on the retry.
				return nerr
			}
			// Refused at one row on one thread: no key list and no read shape
			// this pass can issue gets this object out. Skip it — LOUDLY — and
			// continue.
			sp.giveUp(keys, &sp.oversizeSkipped)
			return nil
		}
		// The tree ran out of deadline or query budget before it could ASK the
		// narrow question, so irreducibility is UNPROVEN. Counting this under
		// oversize would quietly re-fill the "genuinely unreadable" series with
		// objects nobody measured; it belongs to the budget reason, which is
		// what actually stopped it.
		sp.giveUp(keys, &sp.budgetSkipped)
		return nil
	}
	sp.splits++
	half := len(keys) / 2
	if err := sp.run(pass, tree, keys[:half], depth+1); err != nil {
		return err
	}
	return sp.run(pass, tree, keys[half:], depth+1)
}

// giveUp records keys the tree will not fetch, under the reason's counter.
func (sp *timeIntelFetchSplit) giveUp(keys []timeIntelBackfillKey, into *int) {
	*into += len(keys)
	for _, k := range keys {
		if len(sp.skippedIDs) >= timeIntelBackfillSkipLogIDs {
			return
		}
		// A correlation_id is upstream data (§3): it reaches a log record
		// scrubbed, like every other tenant-controlled string here.
		sp.skippedIDs = append(sp.skippedIDs, scrubLogValue(k.CorrelationID))
	}
}

// recordTimeIntelFetchSplit publishes what one page's fetch tree did: counters
// on /metrics, and — only when something was actually given up — one bounded
// WARN naming the objects. No silent failures (§10); a snapshot that will never
// be written must not be invisible just because the pass succeeded.
func (s *server) recordTimeIntelFetchSplit(sp *timeIntelFetchSplit) {
	if sp.splits > 0 {
		s.timeIntelFetchSplits.Add(int64(sp.splits))
	}
	if sp.narrowRetries > 0 {
		s.timeIntelFetchNarrowRetries.Add(int64(sp.narrowRetries))
	}
	if sp.oversizeSkipped > 0 {
		s.timeIntelFetchOversizeSkipped.Add(int64(sp.oversizeSkipped))
	}
	if sp.budgetSkipped > 0 {
		s.timeIntelFetchBudgetSkipped.Add(int64(sp.budgetSkipped))
	}
	if sp.oversizeSkipped == 0 && sp.budgetSkipped == 0 {
		return
	}
	logWarn("timeintel", "backfill wide fetch skipped objects it could not read within the guard rails — the page still folded and the watermark still advances", map[string]any{
		"oversize_skipped": sp.oversizeSkipped,
		"budget_skipped":   sp.budgetSkipped,
		"narrow_retries":   sp.narrowRetries,
		"sub_fetches":      sp.fetches,
		"splits":           sp.splits,
		"folded":           len(sp.rows),
		"correlation_ids":  sp.skippedIDs,
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
// MergeParts. At the 512 MiB written here the sub-fetch is refused EARLY and the
// splitter absorbs it without ever pressuring merges.
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

// timeIntelBackfillNarrowReadSettings is the floor retry's budget (186 fix-5):
// timeIntelBackfillReadSettings with the block geometry collapsed to one row on
// one thread, and NOTHING else moved.
//
// Stated as an override of the production map rather than a second literal map
// on purpose — a future memory/bytes/time change must reach BOTH reads or the
// retry becomes a hole in the guard rails. The identity is asserted, not
// trusted: timeintel_backfill_test.go pins that these two maps differ in
// exactly max_block_size and max_threads.
func timeIntelBackfillNarrowReadSettings() map[string]string {
	settings := timeIntelBackfillReadSettings()
	settings["max_block_size"] = intToString(timeIntelBackfillNarrowBlockRows)
	settings["max_threads"] = intToString(timeIntelBackfillNarrowThreads)
	return settings
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
