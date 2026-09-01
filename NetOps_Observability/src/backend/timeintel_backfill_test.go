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
	"netops/backend/internal/chschema"
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
	// failFetchOn is the 1-based SUB-fetch ordinal that is refused outright.
	// 0 = never. failFetchCode is the DB::Exception code it is refused with,
	// defaulting to 241; the tests that want a refusal the SPLITTER must not
	// swallow set it to a code halving cannot fix.
	failFetchOn   int
	failFetchCode int
	// failCeilPickCode refuses any PICK that carries a ceiling predicate — i.e.
	// the phase-1 re-scan pick, whose window is bounded above by the watermark —
	// with this DB::Exception code. 0 = never. This is the ultra-#5 shape: a
	// deterministic refusal inside the FIXED window BEHIND the mark.
	failCeilPickCode int
	fetches          int
	foldedIDs        []string

	// ── read-budget accounting (186 fix-2) ────────────────────────────────────
	//
	// The live failure is not "the Nth query dies", it is "a query over too many
	// keys reads too many bytes". Modelling it as a per-key cost against a cap
	// is what makes the splitter tests real: a fake that only ever failed on an
	// ordinal would pass just as happily with the splitter deleted, because
	// halving would never change the answer.
	//
	// bytesPerKey x len(keys) > readBytesCap  ⇒  Code 307 TOO_MANY_BYTES,
	// which is exactly the shape measured live (bytes scale with the number of
	// distinct hypotheses granules, i.e. with the number of scattered keys).
	fetchBytesPerKey int
	fetchReadBytes   int
	// poison ids are refused with 241 at ANY size — a single object whose own
	// blob overruns the memory ceiling, which no amount of halving can fix.
	poison map[string]bool
	// narrowPoison ids are the LIVE shape fix-4 measured (186 fix-5): refused
	// with 241 at any key count under the production block geometry, and read
	// cleanly at max_block_size=1 / max_threads=1. Halving never fixes them;
	// only re-shaping the read does.
	narrowPoison map[string]bool
	// fetchNarrow records, per sub-fetch and in order, whether it was issued at
	// the floor geometry — so a test can assert the retry was ASKED for, not
	// merely that the outcome looks right.
	fetchNarrow []bool
	// fetchKeyCounts records the key count of every sub-fetch in order, so a
	// test can assert the halving SEQUENCE and not merely the outcome.
	fetchKeyCounts []int
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
		shadow := aliasShadowError(sql)
		ceilRefuse := 0
		if f.failCeilPickCode != 0 && (reCeilTuple.MatchString(sql) || reCeilLE.MatchString(sql)) {
			ceilRefuse = f.failCeilPickCode
		}
		rows := f.pick(sql)
		f.mu.Unlock()
		if ceilRefuse != 0 {
			// The live failure shape for a refused pick, same as the fetch path.
			w.Header().Set("X-ClickHouse-Exception-Code", strconv.Itoa(ceilRefuse))
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, synthRefusal(ceilRefuse))
			return
		}
		if shadow != "" {
			// What the live server does with a shadowed alias (186 hotfix).
			w.Header().Set("X-ClickHouse-Exception-Code", "43")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, shadow)
			return
		}
		writeSynthRows(w, rows)
	case strings.Contains(sql, "FROM netops.corr_objects AS o"):
		f.fetchSQL = append(f.fetchSQL, sql)
		f.fetches++
		ids := fetchKeyIDs(sql)
		f.fetchKeyCounts = append(f.fetchKeyCounts, len(ids))
		narrow := r.URL.Query().Get("max_block_size") == intToString(timeIntelBackfillNarrowBlockRows) &&
			r.URL.Query().Get("max_threads") == intToString(timeIntelBackfillNarrowThreads)
		f.fetchNarrow = append(f.fetchNarrow, narrow)
		refuse := 0
		switch {
		case f.failFetchOn == f.fetches:
			refuse = f.failFetchCode
			if refuse == 0 {
				refuse = 241
			}
		case !narrow && f.narrowPoisonHit(ids):
			// Refused for the SHAPE of the read, not the size of the key list:
			// the default block's ~512 MiB chunk allocation while reading
			// column hypotheses. One row per block on one thread reads it.
			refuse = 241
		case f.poisonHit(ids):
			// A single object whose own hypotheses blob overruns the ceiling —
			// measured live: a ONE-key fetch that reads 0 bytes and still dies
			// allocating a 512 MiB chunk while reading column hypotheses.
			refuse = 241
		case f.fetchReadBytes > 0 && len(ids)*f.fetchBytesPerKey > f.fetchReadBytes:
			refuse = 307
		}
		var rows []map[string]any
		if refuse == 0 {
			rows = f.fetch(sql)
		}
		f.mu.Unlock()
		if refuse != 0 {
			// The live failure shape, verbatim: HTTP 500 plus the exception-code
			// header ClickHouse sets on a refused read.
			w.Header().Set("X-ClickHouse-Exception-Code", strconv.Itoa(refuse))
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, synthRefusal(refuse))
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

// synthRefusal is the exception body ClickHouse 24.8.14.39 answers a refused
// read with. Both texts are the LIVE ones, copied from the 2026-08-31 runs
// against netops.corr_objects, so a test that matches on the body matches what
// the server really says.
func synthRefusal(code int) string {
	switch code {
	case 307:
		return "Code: 307. DB::Exception: Limit for rows or bytes to read exceeded, " +
			"max bytes: 2.00 GiB, current bytes: 2.00 GiB: While executing MergeTreeSelect. (TOO_MANY_BYTES)"
	case 241:
		return "Code: 241. DB::Exception: Memory limit (for query) exceeded: would use 803.11 MiB " +
			"(attempt to allocate chunk of 536871039 bytes), maximum: 512.00 MiB.: " +
			"(while reading column hypotheses). (MEMORY_LIMIT_EXCEEDED)"
	case 159:
		return "Code: 159. DB::Exception: Timeout exceeded: elapsed 30.1 seconds, " +
			"maximum: 30 seconds. (TIMEOUT_EXCEEDED)"
	default:
		return "Code: " + strconv.Itoa(code) + ". DB::Exception: synthetic refusal"
	}
}

// fetchKeyIDs is the correlation_ids one wide-fetch statement asked for.
func fetchKeyIDs(sql string) []string {
	ms := reFetchUUID.FindAllStringSubmatch(sql, -1)
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m[1])
	}
	return out
}

// poisonHit reports whether this sub-fetch touches an object the fake refuses
// at any size. Caller holds f.mu.
func (f *synthCH) poisonHit(ids []string) bool {
	for _, id := range ids {
		if f.poison[id] {
			return true
		}
	}
	return false
}

// narrowPoisonHit reports whether this sub-fetch touches an object the fake
// refuses under the production block geometry. Caller holds f.mu.
func (f *synthCH) narrowPoisonHit(ids []string) bool {
	for _, id := range ids {
		if f.narrowPoison[id] {
			return true
		}
	}
	return false
}

// subFetchNarrow is the geometry of every sub-fetch, in order.
func (f *synthCH) subFetchNarrow() []bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]bool(nil), f.fetchNarrow...)
}

// subFetchKeyCounts is the key count of every sub-fetch, in order.
func (f *synthCH) subFetchKeyCounts() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.fetchKeyCounts...)
}

// reSelectAlias captures every `<expr> AS <name>` in a projection line.
var reSelectAlias = regexp.MustCompile(`(?m)^\s*(.+?)\s+AS\s+([A-Za-z_][A-Za-z0-9_]*)\s*,?\s*$`)

// aliasShadowError reproduces ClickHouse's alias-resolution rule, which is the
// one thing this fake got wrong before the 186 hotfix: a SELECT alias is
// visible INSIDE the WHERE and ORDER BY of the same query and takes precedence
// over the column of that name. So `toString(correlation_id) AS correlation_id`
// silently re-points every predicate below at a String, and the server answers
//
//	Code 43 ILLEGAL_TYPE_OF_ARGUMENT   (or 386 NO_COMMON_TYPE on the UUID)
//
// while a regex-parsing fake happily matched the predicate text and passed.
//
// The rule below is deliberately narrow — an alias is a violation only when its
// defining expression is NOT the bare column of the same name (`version AS
// version` is a no-op and legal) and the name is then USED in a clause that
// ClickHouse resolves aliases in. That is exactly the shadowing class, with no
// false positive on a plain self-alias.
func aliasShadowError(sql string) string {
	head, rest, ok := strings.Cut(sql, "\n  FROM ")
	if !ok {
		return ""
	}
	// The clauses ClickHouse resolves SELECT aliases inside.
	var clauses string
	if i := strings.Index(rest, "\n WHERE "); i >= 0 {
		clauses = rest[i:]
	} else if i := strings.Index(rest, "\n ORDER BY "); i >= 0 {
		clauses = rest[i:]
	} else {
		return ""
	}
	for _, m := range reSelectAlias.FindAllStringSubmatch(head, -1) {
		expr, alias := strings.TrimSpace(m[1]), m[2]
		if expr == alias {
			continue // a legal no-op self-alias
		}
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(alias) + `\b`).MatchString(clauses) {
			return "Code: 43. DB::Exception: No operation greater between String and DateTime64(3, 'UTC'). " +
				"(ILLEGAL_TYPE_OF_ARGUMENT) — SELECT alias " + alias +
				" shadows the typed column it is derived from, and ClickHouse resolves it inside WHERE/ORDER BY"
		}
	}
	return ""
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
			// The projected names, which are deliberately NOT the column names
			// — see resolveAliases below and timeIntelBackfillPickSQL.
			"tenant_id_s": o.tenant, "correlation_id_s": o.id,
			"version":        float64(o.version),
			"created_at_iso": o.created.UTC().Format("2006-01-02T15:04:05.000") + "Z",
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

// TestTimeIntelBackfillPickAliasesDoNotShadowTypedColumns is the 186 hotfix
// regression, and the class of bug the hermetic corpus could not see before.
//
// ClickHouse resolves a SELECT alias INSIDE the WHERE and ORDER BY of the same
// query. The shipped pick aliased its CONVERTED projections back onto the
// column names they came from, so every cursor predicate compared a String to a
// DateTime64 (Code 43 ILLEGAL_TYPE_OF_ARGUMENT) or to a UUID (Code 386
// NO_COMMON_TYPE), and ORDER BY sorted by UUID TEXT order while the cursor
// advanced in UUID NATIVE order. The cold branch has no cursor predicate, so
// the first pass succeeded, stored a watermark, and every pass after it failed
// on a code chhttp does not retry — a permanently stalled worker.
//
// Asserted on EVERY branch, because only the cursor-bearing ones can trip it.
func TestTimeIntelBackfillPickAliasesDoNotShadowTypedColumns(t *testing.T) {
	at := time.Date(2026, 8, 31, 1, 2, 3, 456000000, time.UTC)
	const id = "11111111-1111-4111-8111-111111111111"
	branches := map[string]string{
		"cold": timeIntelBackfillPickSQL(3600, timeIntelBackfillPageRows,
			timeintel.BackfillCursor{}, timeintel.BackfillCursor{}),
		"forward tuple bound": timeIntelBackfillPickSQL(3600, timeIntelBackfillPageRows,
			timeintel.BackfillCursor{CreatedAt: at, CorrelationID: id}, timeintel.BackfillCursor{}),
		"closed lower bound": timeIntelBackfillPickSQL(3600, timeIntelBackfillPageRows,
			timeintel.BackfillCursor{CreatedAt: at}, timeintel.BackfillCursor{}),
		"re-scan ceiling": timeIntelBackfillPickSQL(3600, timeIntelBackfillPageRows,
			timeintel.BackfillCursor{CreatedAt: at, CorrelationID: id},
			timeintel.BackfillCursor{CreatedAt: at.Add(time.Hour), CorrelationID: id}),
	}
	for name, sql := range branches {
		if msg := aliasShadowError(sql); msg != "" {
			t.Errorf("%s branch: %s\n%s", name, msg, sql)
		}
	}
	// The predicates and the sort must therefore be on the RAW typed columns,
	// and the projection must carry the non-shadowing names the row scan reads.
	cold := branches["cold"]
	for _, want := range []string{"AS tenant_id_s", "AS correlation_id_s", "AS created_at_iso"} {
		if !strings.Contains(cold, want) {
			t.Errorf("pick projection lost %q — timeIntelPickPage decodes that name:\n%s", want, cold)
		}
	}
	if !strings.Contains(cold, "ORDER BY created_at ASC, correlation_id ASC") {
		t.Errorf("ORDER BY must sort the raw typed columns (UUID text order != UUID native order):\n%s", cold)
	}

	// SELF-CHECK: the detector must actually detect. Feed it the shape that was
	// rejected on the live server — a fake that cannot fail the old query is a
	// fake that would have passed the bug through a second time.
	shadowed := `
SELECT toString(tenant_id)      AS tenant_id,
       toString(correlation_id) AS correlation_id,
       version                  AS version,
       ` + chschema.ISO("created_at") + ` AS created_at
  FROM netops.corr_current FINAL
 WHERE window_start >= now() - INTERVAL 3600 SECOND
   AND (created_at, correlation_id) > (toDateTime64('2026-08-31 01:02:03.456', 3, 'UTC'), toUUID('` + id + `'))
 ORDER BY created_at ASC, correlation_id ASC
 LIMIT 2000
 FORMAT JSON`
	if aliasShadowError(shadowed) == "" {
		t.Fatal("aliasShadowError did not flag the shape ClickHouse rejected with Code 43 — the fake is blind to alias shadowing again")
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
	// One pick per page, and the pass STOPS when it runs dry — the fourth pick
	// is the empty one that proves it, not an eleventh page.
	//
	// The FETCH count is no longer one per page (186 fix-2): the wide half is
	// sub-paged at timeIntelBackfillFetchSubPageKeys because a whole 2 000-key
	// fetch cannot fit under the read/memory guard rails on the live table. It
	// is still EXACTLY the sub-pages, with no splitting, because nothing here is
	// refused — a count above this means the fetch is halving when it has no
	// reason to.
	wantFetches := timeIntelSubPagesFor(timeIntelBackfillPageRows)*2 + timeIntelSubPagesFor(500)
	picks, fetches := f.counts()
	if picks != 3 || fetches != wantFetches {
		t.Errorf("picks/fetches = %d/%d, want 3/%d", picks, fetches, wantFetches)
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

// TestTimeIntelBackfillUnsplittableFailureDegradesAndResumes: a refusal the
// splitter must NOT swallow (here 159 TIMEOUT_EXCEEDED — halving a key list
// cannot fix a server that ran out of time) still surfaces as a classified,
// retryable error, still keeps the pages already folded, and still resumes from
// the watermark on the next tick.
//
// This used to be the 241 test. 241 moved to the SPLIT path (186 fix-2) because
// on the live table it means "this key list is too wide", which halving does
// fix; 159 is what is left of the original class.
func TestTimeIntelBackfillUnsplittableFailureDegradesAndResumes(t *testing.T) {
	useTimeIntelKV(t)
	const n = timeIntelBackfillPageRows*2 + 100
	objs := synthObjects(n, time.Now().UTC().Add(-30*time.Hour))
	f := newSynthCH(t, objs)
	// The first sub-fetch of the SECOND page is killed.
	f.failFetchOn = timeIntelSubPagesFor(timeIntelBackfillPageRows) + 1
	f.failFetchCode = 159

	m := timeintel.NewMemMetricsStore()
	s := &server{incidentTimeMetrics: m}

	beforeTimeout := chhttp.Snapshot().ByClass["server_timeout"]
	res, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	if err == nil {
		t.Fatal("a 159 kill must surface as an error, not a clean short pass")
	}
	if !chhttp.Retryable(err) {
		t.Errorf("a 159 kill must be classified retryable, got %v", err)
	}
	var che *chhttp.Error
	if !errors.As(err, &che) || che.Code != 159 || che.Classification != "server_timeout" {
		t.Errorf("want a classified chhttp 159/server_timeout error, got %#v", err)
	}
	// Counted on the worker's EXISTING failure metric — the one /metrics
	// exposes as netops_clickhouse_failures_total{class="server_timeout"}.
	if got := chhttp.Snapshot().ByClass["server_timeout"]; got <= beforeTimeout {
		t.Errorf("the 159 was not counted: server_timeout %d → %d", beforeTimeout, got)
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

// ── adaptive fetch splitting (tracker 186 fix-2) ──────────────────────────────
//
// The failure these tests exist for: on 2026-08-31, with the pick finally
// working, the WIDE fetch for a 2 000-key page read 2.24 GiB and was refused
// with Code 307 TOO_MANY_BYTES — every tick, identically, because the pass is
// deterministic. pages = 0, no watermark write, a permanent stall.
//
// The rule the fix encodes: DEGRADE BY SPLITTING, NEVER BY STALLING.

// timeIntelSubPagesFor is how many sub-fetches a key list of n is cut into
// before any splitting.
func timeIntelSubPagesFor(n int) int {
	if n <= 0 {
		return 0
	}
	return (n + timeIntelBackfillFetchSubPageKeys - 1) / timeIntelBackfillFetchSubPageKeys
}

// TestTimeIntelFetchSplittableActsOnlyOnBudgetRefusals pins the trigger set. A
// splitter that fired on everything would turn one loud schema fault into a
// hundred quiet ones; a splitter that fired on nothing is the stall.
func TestTimeIntelFetchSplittableActsOnlyOnBudgetRefusals(t *testing.T) {
	cases := []struct {
		code int
		want bool
		why  string
	}{
		{307, true, "TOO_MANY_BYTES — the observed stall; deterministic, only fewer keys fix it"},
		{241, true, "MEMORY_LIMIT_EXCEEDED while reading column hypotheses — a property of the key list"},
		{159, false, "TIMEOUT_EXCEEDED — the server ran out of time, not the key list out of room"},
		{43, false, "ILLEGAL_TYPE_OF_ARGUMENT — a broken query; halving it stays broken"},
		{516, false, "auth — halving is not a credential"},
		{0, false, "no exception code at all"},
	}
	for _, c := range cases {
		err := error(&chhttp.Error{Op: "fetch", Status: 500, Code: c.code})
		if got := timeIntelFetchSplittable(err); got != c.want {
			t.Errorf("code %d: splittable = %v, want %v (%s)", c.code, got, c.want, c.why)
		}
	}
	if timeIntelFetchSplittable(errors.New("transport lost")) {
		t.Error("a non-ClickHouse error must never be split — the read may have half-happened")
	}
	if timeIntelFetchSplittable(nil) {
		t.Error("nil is not a refusal")
	}
}

// TestTimeIntelKeySpanIsMinMaxNotEndpoints: the splitter hands the SQL builder
// arbitrary sublists, so the partition bound must be a real min/max. Endpoints
// of an unsorted sublist would exclude rows from the created_at slice and lose
// exactly those objects' snapshots — silently, since the fetch would succeed.
func TestTimeIntelKeySpanIsMinMaxNotEndpoints(t *testing.T) {
	base := time.Date(2026, 8, 22, 1, 0, 0, 0, time.UTC)
	keys := []timeIntelBackfillKey{
		{CreatedAt: base.Add(5 * time.Minute)},
		{CreatedAt: base},
		{CreatedAt: base.Add(9 * time.Minute)},
		{CreatedAt: base.Add(2 * time.Minute)},
	}
	from, to := timeIntelKeySpan(keys)
	if !from.Equal(base) || !to.Equal(base.Add(9*time.Minute)) {
		t.Errorf("span = [%s, %s], want [%s, %s]", from, to, base, base.Add(9*time.Minute))
	}
	if f, tt := timeIntelKeySpan(nil); !f.IsZero() || !tt.IsZero() {
		t.Errorf("empty span = [%s, %s], want zero", f, tt)
	}
}

// TestTimeIntelBackfillFetchHalvesUntilItFits is the headline: a wide fetch the
// server refuses for read volume must be HALVED until it is accepted, and the
// page must fold every object anyway.
//
// MUTANT: delete the split branch in timeIntelFetchSplit.run and this test
// fails — the pass returns the 307 and writes nothing, which is the live stall.
func TestTimeIntelBackfillFetchHalvesUntilItFits(t *testing.T) {
	useTimeIntelKV(t)
	const n = 200
	objs := synthObjects(n, time.Now().UTC().Add(-30*time.Hour))
	f := newSynthCH(t, objs)
	// The live shape, scaled: bytes grow with the number of scattered keys, and
	// the cap admits at most 16 of them.
	f.fetchBytesPerKey = 12
	f.fetchReadBytes = 16 * 12

	m := timeintel.NewMemMetricsStore()
	s := &server{incidentTimeMetrics: m}
	res, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	if err != nil {
		t.Fatalf("a read-budget refusal must be split, not returned: %v", err)
	}
	if res.Written != n {
		t.Errorf("written = %d, want %d — splitting must not lose objects", res.Written, n)
	}
	if res.Cursor.CorrelationID != objs[n-1].id {
		t.Errorf("cursor = %s, want the last object %s", res.Cursor.CorrelationID, objs[n-1].id)
	}
	if got := s.timeIntelFetchSplits.Load(); got == 0 {
		t.Error("netops_timeintel_fetch_splits_total stayed 0 — the page was never actually split")
	}
	if got := s.timeIntelFetchOversizeSkipped.Load() + s.timeIntelFetchBudgetSkipped.Load(); got != 0 {
		t.Errorf("a splittable page skipped %d objects — nothing here is unreadable", got)
	}
	// The SEQUENCE, not just the outcome: every sub-fetch that was refused must
	// be followed by one of half its size, down to an accepted 16.
	counts := f.subFetchKeyCounts()
	wantPrefix := []int{64, 32, 16, 16, 32, 16, 16}
	if len(counts) < len(wantPrefix) {
		t.Fatalf("sub-fetch key counts = %v, want at least the halving prefix %v", counts, wantPrefix)
	}
	for i, want := range wantPrefix {
		if counts[i] != want {
			t.Fatalf("sub-fetch key counts = %v, want prefix %v (differs at %d)", counts[:len(wantPrefix)], wantPrefix, i)
		}
	}
	for i, c := range counts {
		if c > timeIntelBackfillFetchSubPageKeys {
			t.Errorf("sub-fetch %d asked for %d keys, above the %d sub-page cut", i, c, timeIntelBackfillFetchSubPageKeys)
		}
	}
	rows, _ := m.List(context.Background(), "", true, n+10)
	if len(rows) != n {
		t.Errorf("store holds %d snapshots, want %d", len(rows), n)
	}
}

// TestTimeIntelBackfillPoisonedObjectIsSkippedAndWatermarkAdvances is the
// second half of the contract, and the one that decides whether the worker can
// stall at all: ONE object whose own hypotheses blob overruns the memory
// ceiling (measured live — a one-key fetch reading 0 bytes still dies
// allocating a 512 MiB chunk) must be skipped, counted and named, while every
// other object on the page is folded and the watermark moves PAST it.
//
// MUTANT: delete the min-keys skip branch and this test fails — the splitter
// either recurses forever or returns the 241, and the watermark never passes
// the poisoned object, which is the stall in a new costume.
func TestTimeIntelBackfillPoisonedObjectIsSkippedAndWatermarkAdvances(t *testing.T) {
	useTimeIntelKV(t)
	const n = 130
	objs := synthObjects(n, time.Now().UTC().Add(-30*time.Hour))
	poisoned := objs[70] // inside the second sub-page, not on a boundary
	f := newSynthCH(t, objs)
	f.poison = map[string]bool{poisoned.id: true}

	m := timeintel.NewMemMetricsStore()
	s := &server{incidentTimeMetrics: m}
	res, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	if err != nil {
		t.Fatalf("one unreadable object must not fail the pass: %v", err)
	}
	if res.Written != n-1 {
		t.Errorf("written = %d, want %d (everything but the poisoned object)", res.Written, n-1)
	}
	// THE point of the fix: the watermark is past the poisoned object, so the
	// next tick does not re-read the same failing page forever.
	if res.Cursor.CorrelationID != objs[n-1].id {
		t.Errorf("cursor = %s, want the last object %s — the watermark did not pass the poison",
			res.Cursor.CorrelationID, objs[n-1].id)
	}
	if !res.Cursor.CreatedAt.After(poisoned.created) {
		t.Errorf("cursor at %s is not past the poisoned object at %s", res.Cursor.CreatedAt, poisoned.created)
	}
	if got := s.timeIntelFetchOversizeSkipped.Load(); got != 1 {
		t.Errorf("netops_timeintel_fetch_oversize_skipped_total{reason=\"oversize\"} = %d, want 1", got)
	}
	// Since 186 fix-5 an oversize skip is only allowed to be RECORDED after the
	// floor geometry was tried and refused too — otherwise "irreducible" is a
	// claim nobody tested. This object is refused at every geometry, so the
	// retry happened, found nothing, and the rescue counter stayed 0.
	if !containsTrue(f.subFetchNarrow()) {
		t.Error("no sub-fetch was issued at the floor geometry — the object was written off without the narrow retry")
	}
	if got := s.timeIntelFetchNarrowRetries.Load(); got != 0 {
		t.Errorf("netops_timeintel_fetch_narrow_retries_total = %d, want 0 — nothing was rescued here", got)
	}
	if got := s.timeIntelFetchBudgetSkipped.Load(); got != 0 {
		t.Errorf("split_budget skips = %d, want 0 — this page had budget to spare", got)
	}
	if got := s.timeIntelFetchSplits.Load(); got == 0 {
		t.Error("the poisoned sub-page was never split — a 64-key skip would have cost 63 healthy objects")
	}
	// The skip is EXACTLY one object: its neighbours are in the store.
	rows, _ := m.List(context.Background(), "", true, n+10)
	if len(rows) != n-1 {
		t.Fatalf("store holds %d snapshots, want %d", len(rows), n-1)
	}
	for _, r := range rows {
		if r.CorrelationID == poisoned.id {
			t.Errorf("the poisoned object %s was snapshotted — the fake never returned it", poisoned.id)
		}
	}
	for _, want := range []string{objs[69].id, objs[71].id} {
		found := false
		for _, r := range rows {
			if r.CorrelationID == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("neighbour %s of the poisoned object was lost — the skip is wider than one object", want)
		}
	}
	// A SECOND pass makes no further progress claim and does not re-skip: the
	// watermark is past it. This is the anti-stall assertion.
	before := s.timeIntelFetchOversizeSkipped.Load()
	res2, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	if err != nil {
		t.Fatalf("pass 2: %v", err)
	}
	if !res2.CaughtUp {
		t.Error("pass 2 must report caught-up — the backlog was drained past the poison")
	}
	if got := s.timeIntelFetchOversizeSkipped.Load(); got != before+1 {
		// The bounded re-scan behind the watermark re-reads the poisoned object
		// exactly once more; anything beyond that is a loop.
		t.Errorf("oversize skips %d → %d over one re-scan, want exactly one more", before, got)
	}
}

// containsTrue reports whether any sub-fetch in the sequence was narrow.
func containsTrue(bs []bool) bool {
	for _, b := range bs {
		if b {
			return true
		}
	}
	return false
}

// TestTimeIntelBackfillNarrowRetryRescuesAFloorRefusal is the 186 fix-5
// contract: an object the production block geometry refuses at EVERY key count
// — the exact live shape fix-4 measured, a ~512 MiB chunk allocation while
// reading column hypotheses — must be retried ONCE at max_block_size=1 /
// max_threads=1 and FOLDED, not skipped as oversize.
//
// This is data loss recovered, not an optimisation: before the retry these
// objects (~2 per 2 000-key page live, ~26 per pass) were silently missing
// snapshots forever, because the watermark had already moved past them.
//
// MUTANT: delete the narrow-retry branch in timeIntelFetchSplit.run and this
// test fails — written drops to n-2 and the two objects are counted as
// oversize skips, which is the avoidable loss this fix removes.
func TestTimeIntelBackfillNarrowRetryRescuesAFloorRefusal(t *testing.T) {
	useTimeIntelKV(t)
	const n = 130
	objs := synthObjects(n, time.Now().UTC().Add(-30*time.Hour))
	// Two objects, in different sub-pages and off the halving boundaries — the
	// live density (2 per 2 000 keys), scaled to this page.
	shaped := []synthCorr{objs[35], objs[100]}
	f := newSynthCH(t, objs)
	f.narrowPoison = map[string]bool{shaped[0].id: true, shaped[1].id: true}

	m := timeintel.NewMemMetricsStore()
	s := &server{incidentTimeMetrics: m}
	res, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	if err != nil {
		t.Fatalf("a shape refusal must be re-shaped, not returned: %v", err)
	}
	if res.Written != n {
		t.Errorf("written = %d, want %d — the narrow retry must fold every object, not lose the refused ones", res.Written, n)
	}
	if got := s.timeIntelFetchNarrowRetries.Load(); got != 2 {
		t.Errorf("netops_timeintel_fetch_narrow_retries_total = %d, want 2", got)
	}
	if got := s.timeIntelFetchOversizeSkipped.Load(); got != 0 {
		t.Errorf("oversize skips = %d, want 0 — nothing here is irreducible", got)
	}
	if got := s.timeIntelFetchBudgetSkipped.Load(); got != 0 {
		t.Errorf("split_budget skips = %d, want 0 — this page had budget to spare", got)
	}
	// The retry is spent at the FLOOR, never as a second try at a wide sublist:
	// every narrow sub-fetch asks for exactly one key.
	counts, narrow := f.subFetchKeyCounts(), f.subFetchNarrow()
	if len(counts) != len(narrow) {
		t.Fatalf("fake recorded %d key counts and %d geometries", len(counts), len(narrow))
	}
	narrowed := 0
	for i, isNarrow := range narrow {
		if !isNarrow {
			continue
		}
		narrowed++
		if counts[i] != timeIntelBackfillFetchSplitMinKeys {
			t.Errorf("narrow sub-fetch %d asked for %d keys, want the %d-key floor — a wide retry is a second bill, not a re-shape",
				i, counts[i], timeIntelBackfillFetchSplitMinKeys)
		}
	}
	if narrowed != 2 {
		t.Errorf("%d narrow sub-fetches, want exactly 2 (one per shape-refused object) — the retry must not become a per-refusal habit", narrowed)
	}
	// And the rescued objects are really in the store, not merely counted.
	rows, _ := m.List(context.Background(), "", true, n+10)
	if len(rows) != n {
		t.Fatalf("store holds %d snapshots, want %d", len(rows), n)
	}
	for _, want := range shaped {
		found := false
		for _, r := range rows {
			if r.CorrelationID == want.id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("shape-refused object %s was counted as rescued but never snapshotted", want.id)
		}
	}
}

// TestTimeIntelBackfillNarrowRetryKeepsEveryOtherBudget pins what the retry is
// allowed to change. It re-SHAPES the read; it must not re-PRICE it.
//
// A retry that quietly relaxed max_memory_usage or max_bytes_to_read would be
// the storm-s07 regression re-entering through the one path that runs on the
// worst objects on the page — so the difference between the two settings maps
// is asserted to be exactly two keys, both on the wire and in the builder.
func TestTimeIntelBackfillNarrowRetryKeepsEveryOtherBudget(t *testing.T) {
	wide, narrow := timeIntelBackfillReadSettings(), timeIntelBackfillNarrowReadSettings()
	if len(wide) != len(narrow) {
		t.Fatalf("narrow settings have %d keys, wide %d — the retry must send the SAME guards", len(narrow), len(wide))
	}
	for k, want := range wide {
		got, ok := narrow[k]
		if !ok {
			t.Errorf("narrow settings dropped %q — a guard the retry does not send is a guard it does not have", k)
			continue
		}
		switch k {
		case "max_block_size":
			if got != intToString(timeIntelBackfillNarrowBlockRows) || got != "1" {
				t.Errorf("narrow max_block_size = %q, want 1 (the floor geometry fix-4 measured)", got)
			}
		case "max_threads":
			if got != intToString(timeIntelBackfillNarrowThreads) || got != "1" {
				t.Errorf("narrow max_threads = %q, want 1", got)
			}
		default:
			if got != want {
				t.Errorf("narrow settings moved %q from %q to %q — the retry may re-shape the read, never re-price it", k, want, got)
			}
		}
	}
	// The narrow geometry must actually BE narrower, or the retry is a plain
	// repeat of a deterministic refusal.
	if timeIntelBackfillNarrowBlockRows >= timeIntelBackfillBlockRows ||
		timeIntelBackfillNarrowThreads > timeIntelBackfillThreads {
		t.Errorf("floor geometry %dx%d is not narrower than the production %dx%d",
			timeIntelBackfillNarrowBlockRows, timeIntelBackfillNarrowThreads,
			timeIntelBackfillBlockRows, timeIntelBackfillThreads)
	}

	// And on the wire: the retry's own query carries the same memory/bytes/time
	// budget the wide read does.
	useTimeIntelKV(t)
	const n = 70
	objs := synthObjects(n, time.Now().UTC().Add(-30*time.Hour))
	f := newSynthCH(t, objs)
	f.narrowPoison = map[string]bool{objs[20].id: true}
	s := &server{incidentTimeMetrics: timeintel.NewMemMetricsStore()}
	if _, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if got := s.timeIntelFetchNarrowRetries.Load(); got != 1 {
		t.Fatalf("narrow retries = %d, want 1 — the wire assertion below would be vacuous", got)
	}
	f.mu.Lock()
	params := append([]url.Values(nil), f.params...)
	f.mu.Unlock()
	seen := 0
	for i, q := range params {
		if q.Get("max_block_size") != intToString(timeIntelBackfillNarrowBlockRows) ||
			q.Get("log_comment") != timeIntelBackfillTag {
			continue
		}
		seen++
		for k, want := range map[string]string{
			"tenant_scope":       "__all__",
			"max_memory_usage":   intToString(timeIntelBackfillMemoryBytes),
			"max_bytes_to_read":  intToString(timeIntelBackfillReadBytes),
			"max_execution_time": strconv.Itoa(int(timeIntelBackfillBudget / time.Second)),
			"max_threads":        intToString(timeIntelBackfillNarrowThreads),
		} {
			if got := q.Get(k); got != want {
				t.Errorf("narrow retry call %d: %s = %q, want %q", i, k, got, want)
			}
		}
	}
	if seen != 1 {
		t.Errorf("%d narrow-geometry fetches on the wire, want exactly 1", seen)
	}
}

// TestTimeIntelBackfillFetchSelectsOnlyWhatTheFoldNeeds pins the column set of
// the WIDE read, which is the expensive half.
//
// hypotheses is 94 % of corr_objects (70 GiB uncompressed) and is the entire
// reason the fetch has to be split at all, so "does the fold actually need it"
// is a question with a 20-GiB-per-page answer. It DOES: `owner` and `seam_type`
// are both JSON-extracted from it and both land in the snapshot
// (MetricRow.Owner / .OwnerDomain / .SeamType, and DriverContext.Owner). The
// extraction stays SERVER-side — pulling the blob itself would blow the
// response cap — and no THIRD extraction may be added without re-measuring.
func TestTimeIntelBackfillFetchSelectsOnlyWhatTheFoldNeeds(t *testing.T) {
	keys := []timeIntelBackfillKey{{
		TenantID: "global", CorrelationID: "55befe37-0418-5dc4-8727-43006a30edab",
		Version: 1, CreatedAt: time.Now().UTC(),
	}}
	sql := timeIntelBackfillFetchSQL(keys, keys[0].CreatedAt, keys[0].CreatedAt)

	// Every column foldTimeIntelPage reads out of a fetch row.
	for _, want := range []string{
		"tenant_id", "correlation_id", "window_start", "created_at", "verdict_tier",
		"top_confidence", "top_hypothesis", "evidence_missing", "affected", "state",
		"owner", "seam_type",
	} {
		if !strings.Contains(sql, " AS "+want) {
			t.Errorf("fetch does not project %q, which foldTimeIntelPage reads", want)
		}
	}
	// The blob is never selected raw — only extracted from.
	if strings.Contains(sql, "o.hypotheses         ") || strings.Contains(sql, "o.hypotheses AS") {
		t.Error("the fetch selects the raw hypotheses blob — that is 94 % of corr_objects and blows the response cap")
	}
	if got := strings.Count(sql, "JSONExtractString(o.hypotheses"); got != 2 {
		t.Errorf("the fetch makes %d hypotheses extractions, want exactly 2 (owner, seam_type) — a third needs a re-measure", got)
	}
	// And no column the fold does not read: the cost is per COLUMN read, so a
	// speculative extra is a real bill on a 70 GiB table.
	for _, banned := range []string{"o.attribution", "o.app_impact", "o.layer_coverage", "o.signal_count", "o.window_end"} {
		if strings.Contains(sql, banned) {
			t.Errorf("the fetch reads %s, which foldTimeIntelPage never looks at", banned)
		}
	}
}

// TestTimeIntelBackfillFetchTreeIsBounded: the splitter must not be able to run
// an unbounded number of queries against the store. Every key poisoned is the
// worst case — a full binary tree — and the sub-fetch cap must stop it, count
// the remainder under the budget reason, and STILL advance the watermark.
func TestTimeIntelBackfillFetchTreeIsBounded(t *testing.T) {
	useTimeIntelKV(t)
	const n = 400
	objs := synthObjects(n, time.Now().UTC().Add(-30*time.Hour))
	f := newSynthCH(t, objs)
	f.poison = map[string]bool{}
	for _, o := range objs {
		f.poison[o.id] = true // nothing on this page is readable at any size
	}

	m := timeintel.NewMemMetricsStore()
	s := &server{incidentTimeMetrics: m}
	res, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	if err != nil {
		t.Fatalf("a wholly unreadable page must still complete: %v", err)
	}
	if res.Written != 0 {
		t.Errorf("written = %d, want 0 — nothing on this page is readable", res.Written)
	}
	if !res.CaughtUp || res.Cursor.CorrelationID != objs[n-1].id {
		t.Errorf("the watermark must still cross an unreadable page: caught_up=%v cursor=%s want %s",
			res.CaughtUp, res.Cursor.CorrelationID, objs[n-1].id)
	}
	_, fetches := f.counts()
	if fetches > timeIntelBackfillFetchMaxSubFetches {
		t.Errorf("the fetch tree ran %d sub-fetches, above the %d cap", fetches, timeIntelBackfillFetchMaxSubFetches)
	}
	skipped := s.timeIntelFetchOversizeSkipped.Load() + s.timeIntelFetchBudgetSkipped.Load()
	if skipped != int64(n) {
		t.Errorf("skipped %d objects, want all %d counted — an uncounted skip is a silent data loss", skipped, n)
	}
}

// TestTimeIntelBackfillPassTimeoutCoversTheFetchTree: the pass deadline must
// exceed what one page's loop is ALLOWED to spend, or it silently becomes the
// real bound and pages die mid-tree with their work unrecorded.
func TestTimeIntelBackfillPassTimeoutCoversTheFetchTree(t *testing.T) {
	perPage := timeIntelBackfillBudget + timeIntelBackfillFetchSplitDeadline + timeIntelBackfillPagePause
	if timeIntelBackfillPassTimeout <= time.Duration(timeIntelBackfillMaxPages)*perPage {
		t.Errorf("pass timeout %s does not cover %d pages of %s",
			timeIntelBackfillPassTimeout, timeIntelBackfillMaxPages, perPage)
	}
	if timeIntelBackfillFetchSplitDeadline < timeIntelBackfillBudget {
		t.Errorf("the fetch tree's deadline (%s) is under ONE sub-fetch's server budget (%s) — the first sub-fetch could never finish",
			timeIntelBackfillFetchSplitDeadline, timeIntelBackfillBudget)
	}
	if timeIntelBackfillFetchSplitMinKeys != 1 {
		t.Errorf("min split = %d: a floor above 1 discards the healthy objects sharing a poisoned object's sublist and reports a list of ids instead of the one that is broken",
			timeIntelBackfillFetchSplitMinKeys)
	}
	// 64 -> 1 needs six halvings; the depth guard must never be what stops a
	// descent before the min-keys floor does.
	need := 0
	for k := timeIntelBackfillFetchSubPageKeys; k > timeIntelBackfillFetchSplitMinKeys; k /= 2 {
		need++
	}
	if timeIntelBackfillFetchSplitMaxDepth < need {
		t.Errorf("max depth %d cannot reach a %d-key sublist from a %d-key sub-page (needs %d)",
			timeIntelBackfillFetchSplitMaxDepth, timeIntelBackfillFetchSplitMinKeys,
			timeIntelBackfillFetchSubPageKeys, need)
	}
}

// ── ultra finding #5: the re-scan must never block the mark ──────────────────

// TestTimeIntelBackfillRescanFailureDoesNotBlockTheMark: a deterministic 159
// TIMEOUT in the phase-1 re-scan (159 is NOT splittable — only 307/241 are)
// used to abort the pass BEFORE phase 2, the only mark-advancing phase, so a
// fixed failing window behind the mark meant a permanently failing backfill
// every tick. Now phase 1 degrades loudly and phase 2 still runs.
func TestTimeIntelBackfillRescanFailureDoesNotBlockTheMark(t *testing.T) {
	useTimeIntelKV(t)
	const n = 200
	objs := synthObjects(n, time.Now().UTC().Add(-6*time.Hour))
	f := newSynthCH(t, objs)
	f.failCeilPickCode = 159 // the re-scan pick (the only ceilinged pick) dies

	// A warm mark mid-fixture so phase 1 actually runs.
	mark := objs[100]
	if err := timeintel.NewBackfillCursorStore("").Save(timeintel.BackfillCursor{
		CreatedAt: mark.created, CorrelationID: mark.id,
	}); err != nil {
		t.Fatalf("seed watermark: %v", err)
	}

	s := &server{incidentTimeMetrics: timeintel.NewMemMetricsStore()}
	res, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	if err != nil {
		t.Fatalf("a re-scan failure must not fail the pass: %v", err)
	}
	if !res.CaughtUp {
		t.Error("phase 2 must run to caught-up despite the dead re-scan")
	}
	last := objs[n-1]
	if !res.Cursor.CreatedAt.Equal(last.created) || res.Cursor.CorrelationID != last.id {
		t.Errorf("watermark = (%s, %s), want the newest object (%s, %s) — the re-scan blocked the mark",
			res.Cursor.CreatedAt, res.Cursor.CorrelationID, last.created, last.id)
	}
	if res.Written != n-101 {
		t.Errorf("forward phase wrote %d, want %d (everything past the mark; the dead re-scan contributed nothing)",
			res.Written, n-101)
	}
	if got := s.timeIntelRescanFailures.Load(); got != 1 {
		t.Errorf("netops_timeintel_rescan_failures_total = %d, want 1", got)
	}
	if got := s.timeIntelRescanSkips.Load(); got != 1 {
		t.Errorf("netops_timeintel_rescan_skips_total = %d, want 1 — a ClickHouse refusal must move the skip floor", got)
	}
}

// TestTimeIntelBackfillRescanSkipsPastAFailingRegion: consecutive refusals walk
// the re-scan's start FORWARD in bounded, counted steps, so a deterministically
// unreadable region behind the mark costs a bounded number of ticks — the
// splitter's philosophy one layer up: progress over completeness, loudly. A
// completed re-scan clears the floor.
func TestTimeIntelBackfillRescanSkipsPastAFailingRegion(t *testing.T) {
	useTimeIntelKV(t)
	objs := synthObjects(10, time.Now().UTC().Add(-3*time.Hour))
	f := newSynthCH(t, objs)
	f.failCeilPickCode = 159

	// Mark on the NEWEST object: the forward phase is already caught up, so the
	// re-scan window is fixed and each pass's re-scan start is comparable.
	mark := objs[len(objs)-1]
	if err := timeintel.NewBackfillCursorStore("").Save(timeintel.BackfillCursor{
		CreatedAt: mark.created, CorrelationID: mark.id,
	}); err != nil {
		t.Fatalf("seed watermark: %v", err)
	}
	s := &server{incidentTimeMetrics: timeintel.NewMemMetricsStore()}
	for i := 0; i < 2; i++ {
		if _, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback); err != nil {
			t.Fatalf("pass %d: %v", i+1, err)
		}
	}
	// The two re-scan picks (the ceilinged ones) must start one bounded step apart.
	f.mu.Lock()
	var rescanFrom []time.Time
	for _, sql := range f.pickSQL {
		if !reCeilTuple.MatchString(sql) && !reCeilLE.MatchString(sql) {
			continue
		}
		m := reCursorGE.FindStringSubmatch(sql)
		if m == nil {
			t.Fatalf("re-scan pick carries no closed lower bound:\n%s", sql)
		}
		at, perr := time.ParseInLocation(synthTimeLayout, m[1], time.UTC)
		if perr != nil {
			t.Fatalf("parse re-scan bound: %v", perr)
		}
		rescanFrom = append(rescanFrom, at)
	}
	f.mu.Unlock()
	if len(rescanFrom) != 2 {
		t.Fatalf("want 2 re-scan picks, got %d", len(rescanFrom))
	}
	if got := rescanFrom[1].Sub(rescanFrom[0]); got != timeIntelBackfillRescanSkipStep {
		t.Errorf("pass 2's re-scan started %s after pass 1's, want the bounded skip step %s", got, timeIntelBackfillRescanSkipStep)
	}
	if got := s.timeIntelRescanSkips.Load(); got != 2 {
		t.Errorf("netops_timeintel_rescan_skips_total = %d, want 2", got)
	}
	// Health returns: the next COMPLETED re-scan clears the floor.
	f.mu.Lock()
	f.failCeilPickCode = 0
	f.mu.Unlock()
	if _, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback); err != nil {
		t.Fatalf("healthy pass: %v", err)
	}
	if !s.timeIntelRescanFloor.IsZero() {
		t.Errorf("a completed re-scan must clear the skip floor, still at %s", s.timeIntelRescanFloor)
	}
}

// ── ultra finding #3: invalid rows advance and are counted ───────────────────

// TestTimeIntelBackfillFullyInvalidPageStillAdvances: a page whose EVERY row
// fails validation used to return caughtUp=true with neither the page cursor
// nor the mark advanced — the permanent re-pick of the same 2 000 corrupt rows,
// every tick, with the store never gaining a snapshot past them. Now the RAW
// tail advances the watermark and the rows are counted on
// netops_timeintel_invalid_rows_total.
func TestTimeIntelBackfillFullyInvalidPageStillAdvances(t *testing.T) {
	useTimeIntelKV(t)
	start := time.Now().UTC().Add(-40 * time.Hour).Truncate(time.Millisecond)
	objs := make([]synthCorr, 0, timeIntelBackfillPageRows+5)
	for i := 0; i < timeIntelBackfillPageRows; i++ {
		objs = append(objs, synthCorr{
			tenant: "acme",
			// 36 chars, right shape, NON-HEX: fails ValidCorrelationUUID.
			id:      fmt.Sprintf("zzzzzzzz-%04d-4000-8000-000000000000", i),
			version: 1, created: start.Add(time.Duration(i) * time.Minute),
		})
	}
	base := start.Add(time.Duration(timeIntelBackfillPageRows+10) * time.Minute)
	for i := 0; i < 5; i++ {
		objs = append(objs, synthCorr{
			tenant: "acme", id: fmt.Sprintf("%08x-0000-4000-8000-000000000000", i),
			version: 1, created: base.Add(time.Duration(i) * time.Minute),
		})
	}
	newSynthCH(t, objs)
	m := timeintel.NewMemMetricsStore()
	s := &server{incidentTimeMetrics: m}
	res, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if res.Written != 5 {
		t.Errorf("written = %d, want the 5 valid objects — the invalid page blocked the pass", res.Written)
	}
	if !res.CaughtUp {
		t.Error("the pass must reach caught-up past the invalid page")
	}
	last := objs[len(objs)-1]
	if !res.Cursor.CreatedAt.Equal(last.created) || res.Cursor.CorrelationID != last.id {
		t.Errorf("watermark = (%s, %s), want (%s, %s)", res.Cursor.CreatedAt, res.Cursor.CorrelationID, last.created, last.id)
	}
	// The full invalid page, plus the boundary row the closed bound re-reads on
	// page 2 (the invalid tail carries no tie-break, deliberately).
	if got := s.timeIntelInvalidRows.Load(); got != timeIntelBackfillPageRows+1 {
		t.Errorf("netops_timeintel_invalid_rows_total = %d, want %d", got, timeIntelBackfillPageRows+1)
	}
	rows, _ := m.List(context.Background(), "", true, 100)
	if len(rows) != 5 {
		t.Errorf("store holds %d snapshots, want 5", len(rows))
	}
}

// TestTimeIntelBackfillInvalidTailRowStillAdvancesWatermark: the in-code claim
// "the page's LAST key still advances the watermark past it" was FALSE when the
// tail row itself was invalid — the filtered list ended one row early, so the
// invalid tail sat exactly on the caught-up boundary and was re-picked forever.
// The mark must land on the RAW tail, with the tie-break degraded to empty.
func TestTimeIntelBackfillInvalidTailRowStillAdvancesWatermark(t *testing.T) {
	useTimeIntelKV(t)
	base := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Millisecond)
	objs := []synthCorr{
		{tenant: "acme", id: "11111111-1111-4111-8111-111111111111", version: 1, created: base},
		{tenant: "acme", id: "22222222-2222-4222-8222-222222222222", version: 1, created: base.Add(time.Minute)},
		{tenant: "acme", id: "zznot-a-uuid-but-36-characters-long!", version: 1, created: base.Add(2 * time.Minute)},
	}
	newSynthCH(t, objs)
	s := &server{incidentTimeMetrics: timeintel.NewMemMetricsStore()}
	res, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if res.Written != 2 {
		t.Errorf("written = %d, want 2", res.Written)
	}
	if !res.Cursor.CreatedAt.Equal(objs[2].created) {
		t.Errorf("watermark = %s, want the RAW tail %s — the invalid tail row will be re-picked forever",
			res.Cursor.CreatedAt, objs[2].created)
	}
	if res.Cursor.CorrelationID != "" {
		t.Errorf("an invalid tail id must degrade the tie-break to empty, got %q", res.Cursor.CorrelationID)
	}
	if got := s.timeIntelInvalidRows.Load(); got != 1 {
		t.Errorf("netops_timeintel_invalid_rows_total = %d, want 1", got)
	}
}

// ── ultra finding #6: serialized passes, resets never clobbered ──────────────

// TestTimeIntelBackfillPassesAreSerialized: the ticker pass and the manual POST
// pass share one inflight guard — a pass that finds another running yields with
// errTimeIntelBackfillInFlight and touches neither ClickHouse nor the cursor.
func TestTimeIntelBackfillPassesAreSerialized(t *testing.T) {
	useTimeIntelKV(t)
	f := newSynthCH(t, synthObjects(5, time.Now().UTC().Add(-time.Hour)))
	s := &server{incidentTimeMetrics: timeintel.NewMemMetricsStore()}

	s.timeIntelPassMu.Lock() // another pass is in flight
	res, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	s.timeIntelPassMu.Unlock()
	if !errors.Is(err, errTimeIntelBackfillInFlight) {
		t.Fatalf("err = %v, want errTimeIntelBackfillInFlight", err)
	}
	if res.Written != 0 || res.Pages != 0 {
		t.Errorf("a yielded pass did work: %+v", res)
	}
	if picks, fetches := f.counts(); picks != 0 || fetches != 0 {
		t.Errorf("a yielded pass touched ClickHouse: %d picks, %d fetches", picks, fetches)
	}
	// And with the guard free the same server runs normally.
	if _, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback); err != nil {
		t.Fatalf("pass after release: %v", err)
	}
}

// resetDuringPassStore triggers an operator ?reset in the middle of the pass's
// FIRST upsert — the exact interleaving that used to let the pass's blind
// platformdb.Save land AFTER the reset and silently undo it.
type resetDuringPassStore struct {
	timeintel.MetricsStore
	srv  *server
	once sync.Once
}

func (r *resetDuringPassStore) Upsert(ctx context.Context, row timeintel.MetricRow) error {
	var rerr error
	r.once.Do(func() { rerr = r.srv.timeIntelResetCursor() })
	if rerr != nil {
		return rerr
	}
	return r.MetricsStore.Upsert(ctx, row)
}

// TestTimeIntelBackfillResetDuringPassIsNeverClobbered: a reset that lands
// mid-pass STANDS — the in-flight pass's watermark save is refused as stale
// (the pass stops with errTimeIntelBackfillStale) and the stored cursor stays
// zero, so the next pass re-derives the whole window as the operator asked.
func TestTimeIntelBackfillResetDuringPassIsNeverClobbered(t *testing.T) {
	useTimeIntelKV(t)
	newSynthCH(t, synthObjects(10, time.Now().UTC().Add(-time.Hour)))
	s := &server{}
	s.incidentTimeMetrics = &resetDuringPassStore{MetricsStore: timeintel.NewMemMetricsStore(), srv: s}

	_, err := s.backfillIncidentTimeMetrics(context.Background(), timeIntelBackfillLookback)
	if !errors.Is(err, errTimeIntelBackfillStale) {
		t.Fatalf("err = %v, want errTimeIntelBackfillStale", err)
	}
	got, lerr := timeintel.NewBackfillCursorStore("").Load()
	if lerr != nil {
		t.Fatalf("load cursor: %v", lerr)
	}
	if !got.IsZero() {
		t.Errorf("the pass CLOBBERED the reset: stored cursor = %+v, want zero", got)
	}
}
