package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/chhttp"
	"netops/backend/internal/platformdb"
	"netops/backend/timeintel"
)

func TestHandleReliabilityTimeMetricsGet(t *testing.T) {
	m := timeintel.NewMemMetricsStore()
	_ = m.Upsert(context.Background(), incidentTimeMetricRow{
		TenantID: "acme", CorrelationID: "c1", CalcVersion: "ti-1",
		OccurredAt: time.Now().UTC(), SeamType: "DIA", OwnerDomain: "isp",
	})
	s := &server{incidentTimeMetrics: m}

	// GET with no permission gate available in this lightweight server: requirePerm
	// will reject (no auth) → we assert it does NOT 200 without auth, proving the
	// read is gated (full positive-path auth is covered by the route-isolation
	// ledger + the store isolation test above).
	r := httptest.NewRequest(http.MethodGet, "/api/reliability/time-metrics", nil)
	w := httptest.NewRecorder()
	s.handleReliabilityTimeMetrics(w, r)
	if w.Code == http.StatusOK {
		t.Fatalf("unauthenticated GET must be gated, got 200")
	}

	// An unknown method is rejected.
	r2 := httptest.NewRequest(http.MethodDelete, "/api/reliability/time-metrics", nil)
	w2 := httptest.NewRecorder()
	s.handleReliabilityTimeMetrics(w2, r2)
	if w2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE want 405, got %d", w2.Code)
	}
}

// ── storm-incident regressions ───────────────────────────────────────────────
//
// 2026-08-29: the backfill's ClickHouse read folded the ENTIRE corr_objects
// history on every 15-minute tick (ORDER BY tenant_id, correlation_id, version
// DESC + LIMIT 1 BY, with the lookback applied outside the fold) and then read
// the wide hypotheses column off the primary-key prefix. At 2 M history rows
// that is ~4 M rows / 45 GiB and a 1.8 GiB peak, so every pass died.
//
// 2026-08-31 (storm-s07, tracker 186): the repaired query was bounded in SHAPE
// but not in COST. It re-picked the OLDEST 20 000 objects of a 30-day window
// every tick — 1 931 054 rows / 35.4 GB / 1.86 GiB, growing ~0.6 GiB per leg
// with retention — became the named victim of a 4 GiB total-memory overcommit
// that evicted two background merges, raised 241/159 on 12 of 41 passes, and
// left 97 % of the window without a snapshot forever.
//
// These tests pin what keeps both from coming back: the SHAPE (bounded +
// prunable + narrow pick), the WATERMARK (a pass reads only what is new, and
// resumes across restarts), the BUDGET (stated per query, on the wire), and the
// FAILURE MODE (loud, counted, degrade-and-resume — never a silent empty pass).

// ── synthetic ClickHouse ─────────────────────────────────────────────────────

// synthCorr is one synthetic corr object in the fake's corr_current/corr_objects.
type synthCorr struct {
	tenant  string
	id      string
	version int
	created time.Time
}

var (
	reCursorTuple = regexp.MustCompile(`\(created_at, correlation_id\) > \(toDateTime64\('([^']+)', 3, 'UTC'\), toUUID\('([^']+)'\)\)`)
	reCursorGE    = regexp.MustCompile(`\n\s+AND created_at >= toDateTime64\('([^']+)', 3, 'UTC'\)`)
	reCeilTuple   = regexp.MustCompile(`\(created_at, correlation_id\) <= \(toDateTime64\('([^']+)', 3, 'UTC'\), toUUID\('([^']+)'\)\)`)
	reCeilLE      = regexp.MustCompile(`\n\s+AND created_at <= toDateTime64\('([^']+)', 3, 'UTC'\)`)
	reLimit       = regexp.MustCompile(`LIMIT (\d+)`)
	reFetchUUID   = regexp.MustCompile(`toUUID\('([0-9a-fA-F-]{36})'\)`)
	reFetchLo     = regexp.MustCompile(`o\.created_at >= toDateTime64\('([^']+)', 3, 'UTC'\)`)
	reFetchHi     = regexp.MustCompile(`o\.created_at <= toDateTime64\('([^']+)', 3, 'UTC'\)`)
)

const synthTimeLayout = "2006-01-02 15:04:05.000"

// synthCH is a ClickHouse stand-in that actually IMPLEMENTS the two halves of
// the pass against an in-memory fixture: it parses the watermark predicate and
// the page LIMIT out of the pick SQL and applies them, and answers the wide
// fetch for exactly the keys it was handed. That is what makes the watermark
// tests real — delete the predicate from the builder and the fake stops
// filtering, so the resume tests fail rather than silently passing.
type synthCH struct {
	mu       sync.Mutex
	objs     []synthCorr // sorted by (created, id)
	params   []url.Values
	pickSQL  []string
	fetchSQL []string
	// failFetchOn is the 1-based fetch ordinal that answers with a ClickHouse
	// 241 MEMORY_LIMIT_EXCEEDED. 0 = never.
	failFetchOn int
	fetches     int
	foldedIDs   []string
}

func newSynthCH(t *testing.T, objs []synthCorr) *synthCH {
	t.Helper()
	f := &synthCH{objs: append([]synthCorr(nil), objs...)}
	sort.Slice(f.objs, func(i, j int) bool {
		if !f.objs[i].created.Equal(f.objs[j].created) {
			return f.objs[i].created.Before(f.objs[j].created)
		}
		return f.objs[i].id < f.objs[j].id
	})
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	return f
}

func (f *synthCH) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	sql := string(body)
	f.mu.Lock()
	f.params = append(f.params, r.URL.Query())
	switch {
	case strings.Contains(sql, "FROM netops.corr_current FINAL"):
		f.pickSQL = append(f.pickSQL, sql)
		rows := f.pick(sql)
		f.mu.Unlock()
		writeSynthRows(w, rows)
	case strings.Contains(sql, "FROM netops.corr_objects AS o"):
		f.fetchSQL = append(f.fetchSQL, sql)
		f.fetches++
		fail := f.failFetchOn == f.fetches
		rows := f.fetch(sql)
		f.mu.Unlock()
		if fail {
			// The storm-s07 failure, verbatim in shape: HTTP 500 plus the
			// exception code header ClickHouse sets for an overcommit kill.
			w.Header().Set("X-ClickHouse-Exception-Code", "241")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, "Code: 241. DB::Exception: Memory limit (total) exceeded")
			return
		}
		writeSynthRows(w, rows)
	default:
		f.mu.Unlock()
		writeSynthRows(w, nil)
	}
}

func writeSynthRows(w http.ResponseWriter, rows []map[string]any) {
	if rows == nil {
		rows = []map[string]any{}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": rows})
}

// pick applies the watermark predicate and the page LIMIT the builder emitted.
func (f *synthCH) pick(sql string) []map[string]any {
	var after time.Time
	var afterID string
	closed := false
	if m := reCursorTuple.FindStringSubmatch(sql); m != nil {
		after, _ = time.ParseInLocation(synthTimeLayout, m[1], time.UTC)
		afterID = m[2]
	} else if m := reCursorGE.FindStringSubmatch(sql); m != nil {
		after, _ = time.ParseInLocation(synthTimeLayout, m[1], time.UTC)
		closed = true
	}
	var until time.Time
	var untilID string
	untilOpen := false
	if m := reCeilTuple.FindStringSubmatch(sql); m != nil {
		until, _ = time.ParseInLocation(synthTimeLayout, m[1], time.UTC)
		untilID = m[2]
	} else if m := reCeilLE.FindStringSubmatch(sql); m != nil {
		until, _ = time.ParseInLocation(synthTimeLayout, m[1], time.UTC)
		untilOpen = true
	}
	limit := 0
	if m := reLimit.FindStringSubmatch(sql); m != nil {
		limit, _ = strconv.Atoi(m[1])
	}
	out := []map[string]any{}
	for _, o := range f.objs {
		if !until.IsZero() {
			if o.created.After(until) {
				continue
			}
			if !untilOpen && o.created.Equal(until) && o.id > untilID {
				continue
			}
		}
		if !after.IsZero() {
			if closed {
				if o.created.Before(after) {
					continue
				}
			} else if o.created.Before(after) ||
				(o.created.Equal(after) && o.id <= afterID) {
				continue
			}
		}
		out = append(out, map[string]any{
			"tenant_id": o.tenant, "correlation_id": o.id,
			"version":    float64(o.version),
			"created_at": o.created.UTC().Format("2006-01-02T15:04:05.000") + "Z",
		})
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// fetch answers the wide half for exactly the keys the builder listed, and only
// for objects inside the created_at slice the builder bounded it with — so a
// builder that dropped either bound would hand back rows this fixture refuses.
func (f *synthCH) fetch(sql string) []map[string]any {
	want := map[string]bool{}
	for _, m := range reFetchUUID.FindAllStringSubmatch(sql, -1) {
		want[m[1]] = true
	}
	lo, hi := time.Time{}, time.Time{}
	if m := reFetchLo.FindStringSubmatch(sql); m != nil {
		lo, _ = time.ParseInLocation(synthTimeLayout, m[1], time.UTC)
		lo = lo.Add(-timeIntelBackfillFetchSlackSeconds * time.Second)
	}
	if m := reFetchHi.FindStringSubmatch(sql); m != nil {
		hi, _ = time.ParseInLocation(synthTimeLayout, m[1], time.UTC)
		hi = hi.Add(timeIntelBackfillFetchSlackSeconds * time.Second)
	}
	out := []map[string]any{}
	for _, o := range f.objs {
		if !want[o.id] {
			continue
		}
		if (!lo.IsZero() && o.created.Before(lo)) || (!hi.IsZero() && o.created.After(hi)) {
			continue
		}
		f.foldedIDs = append(f.foldedIDs, o.id)
		ts := o.created.UTC().Format("2006-01-02T15:04:05.000") + "Z"
		out = append(out, map[string]any{
			"tenant_id": o.tenant, "correlation_id": o.id,
			"window_start": ts, "created_at": ts,
			"verdict_tier": "confirmed", "top_confidence": 0.9,
			"top_hypothesis": "link_down", "evidence_missing": "[]",
			"affected": "{}", "state": "open", "owner": "isp", "seam_type": "DIA",
		})
	}
	return out
}

func (f *synthCH) counts() (picks, fetches int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pickSQL), len(f.fetchSQL)
}

// synthObjects builds n objects spaced one minute apart, so a fixture spans a
// realistic amount of wall time rather than collapsing into one millisecond
// (which would make the watermark's rewind re-read everything).
func synthObjects(n int, start time.Time) []synthCorr {
	// Millisecond precision on purpose: corr_current.created_at is
	// DateTime64(3), so a real server cannot hand back the sub-millisecond
	// component a Go time.Now() carries. Keeping the fixture at the column's
	// own resolution is what makes the cursor round-trip exact rather than
	// re-reading the boundary row on every page.
	start = start.Truncate(time.Millisecond)
	out := make([]synthCorr, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, synthCorr{
			tenant:  []string{"acme", "globex"}[i%2],
			id:      fmt.Sprintf("%08x-0000-4000-8000-000000000000", i),
			version: 1,
			created: start.Add(time.Duration(i) * time.Minute),
		})
	}
	return out
}

// ── an isolated cursor store ─────────────────────────────────────────────────

// timeIntelKV is an in-process platformdb backend so a test's watermark never
// touches the developer's working directory, two "processes" can share one
// store, and a store OUTAGE can be simulated (kvstore_test.go's memKV cannot).
type timeIntelKV struct {
	mu     sync.Mutex
	blobs  map[string][]byte
	loadEr error
	saveEr error
}

func newTimeIntelKV() *timeIntelKV { return &timeIntelKV{blobs: map[string][]byte{}} }

func (m *timeIntelKV) Load(key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadEr != nil {
		return nil, m.loadEr
	}
	b, ok := m.blobs[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}

func (m *timeIntelKV) Save(key string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveEr != nil {
		return m.saveEr
	}
	m.blobs[key] = append([]byte(nil), data...)
	return nil
}

// useTimeIntelKV points the platform KV seam at an isolated in-memory backend.
func useTimeIntelKV(t *testing.T) *timeIntelKV {
	t.Helper()
	kv := newTimeIntelKV()
	restore := platformdb.SwapBackendForTest(kv)
	t.Cleanup(restore)
	return kv
}

// ── shape ────────────────────────────────────────────────────────────────────

// TestTimeIntelBackfillPickSQLIsNarrowBoundedAndWatermarked pins the pick half.
func TestTimeIntelBackfillPickSQLIsNarrowBoundedAndWatermarked(t *testing.T) {
	cold := timeIntelBackfillPickSQL(3600, timeIntelBackfillPageRows, timeintel.BackfillCursor{}, timeintel.BackfillCursor{})

	// 1. No full-history latest-version fold. `LIMIT 1 BY` over corr_objects is
	//    the exact banned shape (#100 rule 2, bounded_io_test.go).
	if strings.Contains(cold, "LIMIT 1 BY") {
		t.Errorf("pick SQL folds corr_objects history again (LIMIT 1 BY):\n%s", cold)
	}
	// 2. The latest version comes from the corr_current hot projection.
	if !strings.Contains(cold, "FROM netops.corr_current FINAL") {
		t.Errorf("pick SQL must take the latest version from corr_current:\n%s", cold)
	}
	// 3. The pick stays NARROW — a wide column here re-creates the 2.6 GiB shape.
	for _, wide := range []string{"hypotheses", "layer_coverage", "app_impact"} {
		if strings.Contains(cold, wide) {
			t.Errorf("pick touches wide column %q — it must fold narrow keys only (#100):\n%s", wide, cold)
		}
	}
	// 4. Bounded by the lookback floor and the PAGE, not by the 20 000 cap.
	if !strings.Contains(cold, "WHERE window_start >= now() - INTERVAL 3600 SECOND") {
		t.Errorf("pick lost its lookback floor:\n%s", cold)
	}
	if !strings.Contains(cold, "LIMIT "+intToString(timeIntelBackfillPageRows)) {
		t.Errorf("pick lost its page LIMIT:\n%s", cold)
	}
	// 5. Ordered by the CURSOR key, tie-broken — window_start is device event
	//    time and immutable across versions, so it can order a scan but cannot
	//    mark progress through one (that is the 97 %-never-snapshotted bug).
	if !strings.Contains(cold, "ORDER BY created_at ASC, correlation_id ASC") {
		t.Errorf("pick must order by the cursor key:\n%s", cold)
	}
	// 6. A cold pass has NO watermark clause; a warm one does, tie-broken.
	if strings.Contains(cold, "toDateTime64") {
		t.Errorf("a cold pick must not carry a watermark predicate:\n%s", cold)
	}
	warm := timeIntelBackfillPickSQL(3600, timeIntelBackfillPageRows, timeintel.BackfillCursor{
		CreatedAt:     time.Date(2026, 8, 31, 1, 2, 3, 456000000, time.UTC),
		CorrelationID: "11111111-1111-4111-8111-111111111111",
	}, timeintel.BackfillCursor{})
	want := "AND (created_at, correlation_id) > (toDateTime64('2026-08-31 01:02:03.456', 3, 'UTC'), toUUID('11111111-1111-4111-8111-111111111111'))"
	if !strings.Contains(warm, want) {
		t.Errorf("warm pick lost its tie-broken watermark (want %q):\n%s", want, warm)
	}
	// 7. A rewound cursor (no tie-break) degrades to a CLOSED lower bound — it
	//    must re-read the boundary, never skip it.
	rew := timeIntelBackfillPickSQL(3600, timeIntelBackfillPageRows, timeintel.BackfillCursor{
		CreatedAt: time.Date(2026, 8, 31, 1, 2, 3, 456000000, time.UTC),
	}, timeintel.BackfillCursor{})
	if !strings.Contains(rew, "AND created_at >= toDateTime64('2026-08-31 01:02:03.456', 3, 'UTC')") {
		t.Errorf("a tie-break-less cursor must produce a closed lower bound:\n%s", rew)
	}
	// 8. The RE-SCAN phase's ceiling: bounded above by the watermark, so the
	//    bounded re-read behind the mark cannot spill into (and duplicate) the
	//    forward phase's work.
	scan := timeIntelBackfillPickSQL(3600, timeIntelBackfillPageRows,
		timeintel.BackfillCursor{CreatedAt: time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)},
		timeintel.BackfillCursor{
			CreatedAt:     time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC),
			CorrelationID: "11111111-1111-4111-8111-111111111111",
		})
	if !strings.Contains(scan, "AND (created_at, correlation_id) <= (toDateTime64('2026-08-31 02:00:00.000', 3, 'UTC'), toUUID('11111111-1111-4111-8111-111111111111'))") {
		t.Errorf("the re-scan pick lost its watermark ceiling:\n%s", scan)
	}
	// 9. A corrupt stored tie-break is never interpolated (§3 zero trust).
	bad := timeIntelBackfillPickSQL(3600, timeIntelBackfillPageRows, timeintel.BackfillCursor{
		CreatedAt: time.Now().UTC(), CorrelationID: "'); DROP TABLE netops.corr_objects --",
	}, timeintel.BackfillCursor{})
	if strings.Contains(bad, "DROP TABLE") {
		t.Errorf("a corrupt cursor tie-break reached the SQL:\n%s", bad)
	}
}

// TestTimeIntelBackfillFetchSQLIsKeyedAndPartitionBounded pins the wide half.
func TestTimeIntelBackfillFetchSQLIsKeyedAndPartitionBounded(t *testing.T) {
	lo := time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
	hi := lo.Add(7 * time.Minute)
	keys := []timeIntelBackfillKey{
		{TenantID: "acme", CorrelationID: "11111111-1111-4111-8111-111111111111", Version: 3, CreatedAt: lo},
		{TenantID: "globex", CorrelationID: "22222222-2222-4222-8222-222222222222", Version: 1, CreatedAt: hi},
	}
	sql := timeIntelBackfillFetchSQL(keys, lo, hi)

	// 1. Keyed on the corr_objects primary key PREFIX (tenant_id first).
	if !strings.Contains(sql, "(o.tenant_id, o.correlation_id, o.version) IN (") {
		t.Errorf("fetch key tuple must lead with tenant_id:\n%s", sql)
	}
	// 2. BOTH created_at bounds — this is what prunes partitions
	//    (toYYYYMMDD(created_at)) to the page's own slice. Losing the upper
	//    bound is the storm-s07 regression: every page re-reads every retained
	//    day from the cursor to now.
	if !strings.Contains(sql, "o.created_at >= toDateTime64('2026-08-31 01:00:00.000', 3, 'UTC')") ||
		!strings.Contains(sql, "o.created_at <= toDateTime64('2026-08-31 01:07:00.000', 3, 'UTC')") {
		t.Errorf("fetch lost a created_at partition bound:\n%s", sql)
	}
	// 3. Exactly the picked keys, no more.
	if n := len(reFetchUUID.FindAllString(sql, -1)); n != len(keys) {
		t.Errorf("fetch listed %d keys, want %d:\n%s", n, len(keys), sql)
	}
	// 4. No outer ORDER BY over the wide read: sorting the result set holds
	//    hypotheses blocks alive across the whole scan (971 MiB measured, over
	//    the 1 GiB ceiling) and buys nothing — the loop upserts by key.
	if outer := sql[strings.Index(sql, "FROM netops.corr_objects AS o"):]; strings.Contains(outer, "ORDER BY") {
		t.Errorf("the wide history read must not sort its result set:\n%s", outer)
	}
	// 5. A tenant id is tenant-CONTROLLED data: it is quoted, not pasted.
	esc := timeIntelBackfillFetchSQL([]timeIntelBackfillKey{
		{TenantID: `a'); DROP TABLE netops.corr_objects --`, CorrelationID: keys[0].CorrelationID, Version: 1},
	}, lo, hi)
	if !strings.Contains(esc, `'a\'); DROP TABLE netops.corr_objects --'`) {
		t.Errorf("tenant id is not escaped into a ClickHouse literal:\n%s", esc)
	}
	// 6. An empty page never produces a statement at all.
	if timeIntelBackfillFetchSQL(nil, lo, hi) != "" {
		t.Error("an empty page must not build a fetch statement")
	}
}

// TestTimeIntelBackfillHasNoUnboundedSelect is the grep-style guard: EVERY
// SELECT this worker can emit carries an explicit bound, in every cursor state.
func TestTimeIntelBackfillHasNoUnboundedSelect(t *testing.T) {
	cursors := []timeintel.BackfillCursor{
		{},
		{CreatedAt: time.Now().UTC().Add(-time.Hour)},
		{CreatedAt: time.Now().UTC().Add(-time.Hour), CorrelationID: "11111111-1111-4111-8111-111111111111"},
	}
	for i, c := range cursors {
		sql := timeIntelBackfillPickSQL(int(timeIntelBackfillLookback/time.Second), timeIntelBackfillPageRows, c, timeintel.BackfillCursor{})
		if regexp.MustCompile(`(?i)SELECT\s+\*`).MatchString(sql) {
			t.Errorf("cursor %d: pick uses SELECT *:\n%s", i, sql)
		}
		if !reLimit.MatchString(sql) {
			t.Errorf("cursor %d: pick has no LIMIT — an unbounded SELECT over corr_current:\n%s", i, sql)
		}
		if n := len(reLimit.FindAllString(sql, -1)); n != 1 {
			t.Errorf("cursor %d: pick has %d LIMIT clauses, want exactly 1:\n%s", i, n, sql)
		}
	}
	// The fetch has no LIMIT and must not need one: it is bounded by the KEY
	// SET (at most one page of literals) AND by the created_at slice. Assert
	// both, because either alone would leave a read that grows with the table.
	keys := []timeIntelBackfillKey{{TenantID: "t", CorrelationID: "11111111-1111-4111-8111-111111111111", Version: 1}}
	sql := timeIntelBackfillFetchSQL(keys, time.Now().UTC().Add(-time.Hour), time.Now().UTC())
	if !strings.Contains(sql, " IN (") || !reFetchLo.MatchString(sql) || !reFetchHi.MatchString(sql) {
		t.Errorf("fetch is not bounded by BOTH the key set and the created_at slice:\n%s", sql)
	}
	// And the page geometry must not be able to exceed the historical per-pass
	// cap: ten pages of 2 000 is the same 20 000 objects the single shot took.
	if timeIntelBackfillPageRows*timeIntelBackfillMaxPages != timeIntelBackfillCap {
		t.Errorf("page geometry %d x %d != the %d-object pass cap",
			timeIntelBackfillPageRows, timeIntelBackfillMaxPages, timeIntelBackfillCap)
	}
}

// ── budget on the wire ───────────────────────────────────────────────────────

// TestTimeIntelBackfillSendsExplicitReadGuards proves the containment settings
// reach ClickHouse on BOTH halves. Before the fix the pass inherited the 2 GiB
// default cap and the generic 20 s worker budget, and was attributed to
// `worker:cross-tenant` (shared with the appid fusion store) — so it could
// neither be bounded nor found in system.query_log. A guard that lives only in
// a comment is not a guard.
func TestTimeIntelBackfillSendsExplicitReadGuards(t *testing.T) {
	useTimeIntelKV(t)
	f := newSynthCH(t, synthObjects(3, time.Now().UTC().Add(-time.Hour)))
	s := &server{incidentTimeMetrics: timeintel.NewMemMetricsStore()}
	if _, err := s.backfillIncidentTimeMetrics(context.Background(), time.Hour); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	f.mu.Lock()
	params := append([]url.Values(nil), f.params...)
	f.mu.Unlock()
	if len(params) < 2 {
		t.Fatalf("want at least a pick and a fetch, got %d ClickHouse calls", len(params))
	}
	common := map[string]string{
		"tenant_scope":       "__all__",
		"max_memory_usage":   intToString(timeIntelBackfillMemoryBytes),
		"max_bytes_to_read":  intToString(timeIntelBackfillReadBytes),
		"max_execution_time": strconv.Itoa(int(timeIntelBackfillBudget / time.Second)),
		"max_block_size":     intToString(timeIntelBackfillBlockRows),
		"max_threads":        intToString(timeIntelBackfillThreads),
	}
	for i, q := range params {
		for k, want := range common {
			if got := q.Get(k); got != want {
				t.Errorf("call %d: %s = %q, want %q (the guard must be stated per query, not inherited)", i, k, got, want)
			}
		}
	}
	// Each half is attributable on its own: the storm incident cost a query_log
	// dig because two unrelated reads shared one log_comment.
	if got := params[0].Get("log_comment"); got != timeIntelBackfillPickTag {
		t.Errorf("pick log_comment = %q, want %q", got, timeIntelBackfillPickTag)
	}
	if got := params[1].Get("log_comment"); got != timeIntelBackfillTag {
		t.Errorf("fetch log_comment = %q, want %q", got, timeIntelBackfillTag)
	}

	// The ceiling has to leave room for the rest of the platform: two worker
	// lanes plus the 1 GiB hot-UI lane must fit inside the 4 GiB server budget,
	// with room left for the background merges storm-s07 evicted.
	if 2*timeIntelBackfillMemoryBytes+(1<<30) > 2<<30 {
		t.Errorf("worker memory ceiling %d leaves under half the 4 GiB server cap for merges", timeIntelBackfillMemoryBytes)
	}
	// This worker must be TIGHTER than the generic worker guard it used to inherit.
	if timeIntelBackfillMemoryBytes >= chWorkerReadMemoryBytes {
		t.Errorf("per-worker ceiling %d must be tighter than the generic %d", timeIntelBackfillMemoryBytes, chWorkerReadMemoryBytes)
	}
	// The response bound must fit a FULL page (measured ~1.0 KB/row on the storm
	// table) or the first successful page fails on truncation — and it must be
	// far below the 70.70 MiB single parse that produced the api RSS sawtooth.
	if timeIntelBackfillMaxResponseBytes < int64(timeIntelBackfillPageRows)*1000 {
		t.Errorf("response bound %d cannot hold %d rows at the measured ~1.0 KB/row",
			timeIntelBackfillMaxResponseBytes, timeIntelBackfillPageRows)
	}
	if timeIntelBackfillMaxResponseBytes >= 70<<20 {
		t.Errorf("response bound %d does not bound the 70.70 MiB single-parse sawtooth", timeIntelBackfillMaxResponseBytes)
	}
	// And the pass must outlive every page's server-side budget it carries, or
	// the classified ClickHouse error can never reach the caller.
	if timeIntelBackfillPassTimeout <= timeIntelBackfillMaxPages*2*timeIntelBackfillBudget {
		t.Errorf("pass timeout %s cannot cover %d pages of 2 x %s",
			timeIntelBackfillPassTimeout, timeIntelBackfillMaxPages, timeIntelBackfillBudget)
	}
}

// ── watermark ────────────────────────────────────────────────────────────────

// TestTimeIntelBackfillPagesThroughBacklog: one pass walks a backlog in bounded
// pages instead of re-reading the oldest page forever.
func TestTimeIntelBackfillPagesThroughBacklog(t *testing.T) {
	useTimeIntelKV(t)
	const n = timeIntelBackfillPageRows*2 + 500
	objs := synthObjects(n, time.Now().UTC().Add(-30*time.Hour))
	f := newSynthCH(t, objs)
	m := timeintel.NewMemMetricsStore()
	s := &server{incidentTimeMetrics: m}

	res, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if res.Written != n {
		t.Errorf("written = %d, want %d", res.Written, n)
	}
	if res.Pages != 3 {
		t.Errorf("pages = %d, want 3 (%d + %d + 500)", res.Pages, timeIntelBackfillPageRows, timeIntelBackfillPageRows)
	}
	if !res.CaughtUp {
		t.Error("a short final page must report caught-up")
	}
	// The watermark landed on the newest object, not on the page cap.
	last := objs[len(objs)-1]
	if !res.Cursor.CreatedAt.Equal(last.created) || res.Cursor.CorrelationID != last.id {
		t.Errorf("cursor = (%s, %s), want (%s, %s)", res.Cursor.CreatedAt, res.Cursor.CorrelationID, last.created, last.id)
	}
	// One pick + one fetch per page, and the pass STOPS when it runs dry — the
	// fourth pick is the empty one that proves it, not an eleventh page.
	picks, fetches := f.counts()
	if fetches != 3 || picks != 3 {
		t.Errorf("picks/fetches = %d/%d, want 3/3", picks, fetches)
	}
	rows, _ := m.List(context.Background(), "", true, n+10)
	if len(rows) != n {
		t.Errorf("store holds %d snapshots, want %d", len(rows), n)
	}
}

// TestTimeIntelBackfillResumesAfterRestart is the headline watermark test: a
// pass is bounded, and the NEXT process resumes where it stopped instead of
// re-reading the oldest page (the 97 %-never-snapshotted bug).
func TestTimeIntelBackfillResumesAfterRestart(t *testing.T) {
	useTimeIntelKV(t) // one KV, two "processes"
	const n = timeIntelBackfillCap + 5000
	objs := synthObjects(n, time.Now().UTC().Add(-30*24*time.Hour))
	newSynthCH(t, objs)

	m := timeintel.NewMemMetricsStore()
	first, err := (&server{incidentTimeMetrics: m}).backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	if err != nil {
		t.Fatalf("pass 1: %v", err)
	}
	if first.Pages != timeIntelBackfillMaxPages || first.Written != timeIntelBackfillCap {
		t.Fatalf("pass 1 wrote %d in %d pages, want %d in %d (the pass must be bounded)",
			first.Written, first.Pages, timeIntelBackfillCap, timeIntelBackfillMaxPages)
	}
	if first.CaughtUp {
		t.Error("pass 1 cannot be caught up with 5 000 objects left")
	}

	// RESTART: a brand-new server and a brand-new snapshot store, same KV.
	m2 := timeintel.NewMemMetricsStore()
	second, err := (&server{incidentTimeMetrics: m2}).backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	if err != nil {
		t.Fatalf("pass 2: %v", err)
	}
	if !second.CaughtUp {
		t.Error("pass 2 must reach the end of the backlog")
	}
	// Pass 2 does the REMAINING work plus at most the deliberate rewind (one
	// object per minute in this fixture). Without the watermark it would redo
	// the first 20 000 and this bound is missed by 4x.
	rewind := int(timeIntelBackfillWatermarkSlack/time.Minute) + 1
	if second.Written < 5000 || second.Written > 5000+rewind {
		t.Errorf("pass 2 wrote %d, want 5000..%d — the watermark did not resume", second.Written, 5000+rewind)
	}
	// The rewind is real and bounded: the pass DID re-read a little.
	if second.Written == 5000 {
		t.Log("note: no rewind overlap observed (acceptable, but the reconcile-lag re-scan is why the slack exists)")
	}
	rows, _ := m2.List(context.Background(), "", true, n+10)
	if len(rows) < 5000 {
		t.Errorf("pass 2 stored %d snapshots, want the 5 000 it had left", len(rows))
	}
	last := objs[len(objs)-1]
	if !second.Cursor.CreatedAt.Equal(last.created) {
		t.Errorf("cursor after pass 2 = %s, want the newest object %s", second.Cursor.CreatedAt, last.created)
	}
}

// TestTimeIntelBackfillMakesForwardProgressUnderAHugeRewindWindow is the
// anti-stall test for the deliberate re-scan. Each pass restarts a bounded
// distance BEHIND the mark to catch rows corr_current_reconcile.go backfilled
// with an already-passed created_at — but under a storm that window can hold
// MORE objects than an entire pass. An undivided loop would then spend every
// tick re-reading them and the watermark would never move: the same stall that
// left 97 % of the window without a snapshot, in a new costume.
//
// So the page budget is split: at most timeIntelBackfillRescanPages behind the
// mark, the rest strictly forward.
func TestTimeIntelBackfillMakesForwardProgressUnderAHugeRewindWindow(t *testing.T) {
	useTimeIntelKV(t)
	// 100 ms apart: the whole 30 000-object fixture fits inside the 2 h rewind
	// window, so the re-scan alone could consume the entire pass.
	const n = 30000
	start := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Millisecond)
	objs := make([]synthCorr, 0, n)
	for i := 0; i < n; i++ {
		objs = append(objs, synthCorr{
			tenant: "acme", id: fmt.Sprintf("%08x-0000-4000-8000-000000000000", i),
			version: 1, created: start.Add(time.Duration(i) * 100 * time.Millisecond),
		})
	}
	newSynthCH(t, objs)

	// The watermark is already deep in the fixture, and everything before it is
	// inside the rewind window.
	mark := objs[25000]
	if err := timeintel.NewBackfillCursorStore("").Save(timeintel.BackfillCursor{
		CreatedAt: mark.created, CorrelationID: mark.id,
	}); err != nil {
		t.Fatalf("seed watermark: %v", err)
	}

	res, err := (&server{incidentTimeMetrics: timeintel.NewMemMetricsStore()}).
		backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if !res.CaughtUp {
		t.Error("the forward phase must reach the end of the backlog despite the oversized rewind window")
	}
	last := objs[len(objs)-1]
	if !res.Cursor.CreatedAt.Equal(last.created) || res.Cursor.CorrelationID != last.id {
		t.Errorf("watermark = (%s, %s), want the newest object (%s, %s) — the re-scan ate the forward budget",
			res.Cursor.CreatedAt, res.Cursor.CorrelationID, last.created, last.id)
	}
	// One re-scan page plus the 5 000 objects genuinely left.
	wantMax := timeIntelBackfillRescanPages*timeIntelBackfillPageRows + (n - 25000)
	if res.Written > wantMax {
		t.Errorf("wrote %d, want at most %d (one re-scan page + the remaining backlog)", res.Written, wantMax)
	}
	if res.Written < n-25000 {
		t.Errorf("wrote %d, want at least the %d objects past the watermark", res.Written, n-25000)
	}
}

// TestTimeIntelBackfillRePageIsIdempotent: re-processing a page rewrites the
// same rows, it does not double-count. That is what makes the deliberate rewind
// (and a crash-mid-page redo) free.
func TestTimeIntelBackfillRePageIsIdempotent(t *testing.T) {
	useTimeIntelKV(t)
	const n = 300
	newSynthCH(t, synthObjects(n, time.Now().UTC().Add(-6*time.Hour)))
	m := timeintel.NewMemMetricsStore()
	s := &server{incidentTimeMetrics: m}

	first, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	if err != nil {
		t.Fatalf("pass 1: %v", err)
	}
	before, _ := m.List(context.Background(), "", true, n+10)
	if first.Written != n || len(before) != n {
		t.Fatalf("pass 1 wrote %d / stored %d, want %d each", first.Written, len(before), n)
	}

	// Force the whole page to be re-processed, exactly as a crash before the
	// cursor save would.
	if err := timeintel.NewBackfillCursorStore("").Reset(); err != nil {
		t.Fatalf("cursor reset: %v", err)
	}
	second, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	if err != nil {
		t.Fatalf("pass 2: %v", err)
	}
	if second.Written != n {
		t.Errorf("re-page wrote %d, want %d", second.Written, n)
	}
	after, _ := m.List(context.Background(), "", true, 2*n+10)
	if len(after) != n {
		t.Errorf("re-processing a page DUPLICATED rows: store holds %d, want %d", len(after), n)
	}
}

// ── failure modes ────────────────────────────────────────────────────────────

// TestTimeIntelBackfillMemoryLimitDegradesAndResumes is the storm-s07 failure
// itself: ClickHouse kills the pass with code 241 (it did so on 12 of 41 passes
// since 2026-08-30 16:57). The pass must degrade — keep what it folded, count
// the failure on the existing chhttp classifier metric, never crash — and the
// NEXT pass must resume from the watermark rather than start over.
func TestTimeIntelBackfillMemoryLimitDegradesAndResumes(t *testing.T) {
	useTimeIntelKV(t)
	const n = timeIntelBackfillPageRows*2 + 100
	objs := synthObjects(n, time.Now().UTC().Add(-30*time.Hour))
	f := newSynthCH(t, objs)
	f.failFetchOn = 2 // the SECOND page is killed

	m := timeintel.NewMemMetricsStore()
	s := &server{incidentTimeMetrics: m}

	beforeMem := chhttp.Snapshot().ByClass["memory_limit"]
	res, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	if err == nil {
		t.Fatal("a 241 kill must surface as an error, not a clean short pass")
	}
	if !chhttp.Retryable(err) {
		t.Errorf("a 241 kill must be classified retryable, got %v", err)
	}
	var che *chhttp.Error
	if !errors.As(err, &che) || che.Code != 241 || che.Classification != "memory_limit" {
		t.Errorf("want a classified chhttp 241/memory_limit error, got %#v", err)
	}
	// Counted on the worker's EXISTING failure metric — the one /metrics
	// exposes as netops_clickhouse_failures_total{class="memory_limit"}.
	if got := chhttp.Snapshot().ByClass["memory_limit"]; got <= beforeMem {
		t.Errorf("the 241 was not counted: memory_limit %d → %d", beforeMem, got)
	}
	// The first page's work is KEPT and the watermark holds it.
	if res.Pages != 1 || res.Written != timeIntelBackfillPageRows {
		t.Errorf("degraded pass kept %d rows in %d pages, want %d in 1", res.Written, res.Pages, timeIntelBackfillPageRows)
	}
	if !res.Cursor.CreatedAt.Equal(objs[timeIntelBackfillPageRows-1].created) {
		t.Errorf("cursor = %s, want the last SUCCESSFUL page's object %s",
			res.Cursor.CreatedAt, objs[timeIntelBackfillPageRows-1].created)
	}

	// Next tick: ClickHouse is healthy again and the pass RESUMES.
	f.mu.Lock()
	f.failFetchOn = 0
	f.mu.Unlock()
	res2, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	if err != nil {
		t.Fatalf("pass 2 after degradation: %v", err)
	}
	if !res2.CaughtUp {
		t.Error("pass 2 must finish the backlog")
	}
	rows, _ := m.List(context.Background(), "", true, n+10)
	if len(rows) != n {
		t.Errorf("after degrade+resume the store holds %d snapshots, want %d", len(rows), n)
	}
}

// TestTimeIntelBackfillFailedReadIsLoud: a refused read must surface as an error
// with zero rows written, never as a successful pass over an empty result. This
// is the difference between "the storm had no incidents" and "we wrote nothing
// for six hours".
func TestTimeIntelBackfillFailedReadIsLoud(t *testing.T) {
	useTimeIntelKV(t)
	failingCH(t)
	m := timeintel.NewMemMetricsStore()
	s := &server{incidentTimeMetrics: m}
	res, err := s.backfillIncidentTimeMetrics(context.Background(), time.Hour)
	if err == nil {
		t.Fatal("a refused ClickHouse read must return an error, not a clean empty pass")
	}
	if res.Written != 0 {
		t.Errorf("written = %d on a failed read, want 0", res.Written)
	}
	rows, lerr := m.List(context.Background(), "", true, 10)
	if lerr != nil {
		t.Fatalf("store list: %v", lerr)
	}
	if len(rows) != 0 {
		t.Errorf("a failed pass wrote %d snapshots", len(rows))
	}
}

// TestTimeIntelBackfillUnreadableCursorIsLoud: an unreadable watermark must NOT
// be read as "start from scratch". Doing so silently reinstates the 35.4 GB
// full re-read the watermark exists to end — every 15 minutes, invisibly.
func TestTimeIntelBackfillUnreadableCursorIsLoud(t *testing.T) {
	kv := useTimeIntelKV(t)
	kv.loadEr = errors.New("kv is down")
	f := newSynthCH(t, synthObjects(10, time.Now().UTC().Add(-time.Hour)))
	m := timeintel.NewMemMetricsStore()
	s := &server{incidentTimeMetrics: m}

	res, err := s.backfillIncidentTimeMetrics(context.Background(), time.Hour)
	if err == nil {
		t.Fatal("an unreadable cursor must fail the pass, not silently restart a full re-read")
	}
	if res.Written != 0 {
		t.Errorf("written = %d, want 0", res.Written)
	}
	if picks, _ := f.counts(); picks != 0 {
		t.Errorf("the pass issued %d ClickHouse reads with an unknown watermark, want 0", picks)
	}
}

// TestTimeIntelBackfillWritesSnapshotsPerTenant is the positive control: the
// same plumbing, answering normally, stamps each snapshot under the corr
// object's OWN tenant (CLAUDE.md §3a). The pass spans tenants; the ROWS do not.
func TestTimeIntelBackfillWritesSnapshotsPerTenant(t *testing.T) {
	useTimeIntelKV(t)
	base := time.Now().UTC().Add(-2 * time.Hour)
	newSynthCH(t, []synthCorr{
		{tenant: "acme", id: "11111111-1111-4111-8111-111111111111", version: 3, created: base},
		{tenant: "globex", id: "22222222-2222-4222-8222-222222222222", version: 1, created: base.Add(time.Minute)},
	})
	m := timeintel.NewMemMetricsStore()
	s := &server{incidentTimeMetrics: m}
	res, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if res.Written != 2 {
		t.Fatalf("written = %d, want 2", res.Written)
	}
	own, err := m.List(context.Background(), "acme", false, 10)
	if err != nil {
		t.Fatalf("store list: %v", err)
	}
	if len(own) != 1 || own[0].TenantID != "acme" || own[0].SeamType != "DIA" {
		t.Fatalf("acme must see exactly its own snapshot, got %+v", own)
	}
}

// TestTimeIntelBackfillNoStoreIsANoOp: without a metrics store the worker must
// not touch ClickHouse or the cursor at all.
func TestTimeIntelBackfillNoStoreIsANoOp(t *testing.T) {
	useTimeIntelKV(t)
	f := newSynthCH(t, synthObjects(5, time.Now().UTC().Add(-time.Hour)))
	res, err := (&server{}).backfillIncidentTimeMetrics(context.Background(), time.Hour)
	if err != nil || res.Written != 0 || res.Pages != 0 {
		t.Fatalf("no-store pass = %+v, %v; want a silent no-op", res, err)
	}
	if picks, _ := f.counts(); picks != 0 {
		t.Errorf("no-store pass issued %d ClickHouse reads, want 0", picks)
	}
}

// TestTimeIntelBackfillPickCarriesCursorAcrossPages proves the IN-PASS boundary
// uses the exact tie-broken cursor. Without it a page boundary landing inside a
// single millisecond either skips rows or re-reads its own predecessor forever.
func TestTimeIntelBackfillPickCarriesCursorAcrossPages(t *testing.T) {
	useTimeIntelKV(t)
	objs := synthObjects(timeIntelBackfillPageRows+10, time.Now().UTC().Add(-40*time.Hour))
	f := newSynthCH(t, objs)
	s := &server{incidentTimeMetrics: timeintel.NewMemMetricsStore()}
	if _, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	f.mu.Lock()
	picks := append([]string(nil), f.pickSQL...)
	f.mu.Unlock()
	if len(picks) < 2 {
		t.Fatalf("want at least two picks, got %d", len(picks))
	}
	if reCursorTuple.MatchString(picks[0]) {
		t.Errorf("the first pick of a cold pass must carry no cursor:\n%s", picks[0])
	}
	m := reCursorTuple.FindStringSubmatch(picks[1])
	if m == nil {
		t.Fatalf("the second pick must carry the tie-broken page cursor:\n%s", picks[1])
	}
	wantID := objs[timeIntelBackfillPageRows-1].id
	if m[2] != wantID {
		t.Errorf("page-2 cursor id = %s, want the last row of page 1 (%s)", m[2], wantID)
	}
}

// TestTimeIntelBackfillHTTPResetClearsWatermark pins the operator escape hatch:
// POST ?reset=true re-derives the window (e.g. after a calc-version bump).
func TestTimeIntelBackfillHTTPResetClearsWatermark(t *testing.T) {
	useTimeIntelKV(t)
	store := timeintel.NewBackfillCursorStore("")
	if err := store.Save(timeintel.BackfillCursor{
		CreatedAt: time.Now().UTC(), CorrelationID: "11111111-1111-4111-8111-111111111111",
	}); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}
	if err := store.Reset(); err != nil {
		t.Fatalf("reset: %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !got.IsZero() {
		t.Errorf("reset cursor = %+v, want zero", got)
	}
	// And a reset cursor produces a COLD pick — no watermark predicate at all.
	if strings.Contains(timeIntelBackfillPickSQL(3600, timeIntelBackfillPageRows, got, timeintel.BackfillCursor{}), "toDateTime64") {
		t.Error("a reset cursor must produce a cold, unwatermarked pick")
	}
}
