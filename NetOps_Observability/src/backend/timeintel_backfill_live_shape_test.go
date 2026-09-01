package backend

// timeintel_backfill_live_shape_test.go — the test class that was MISSING when
// the tracker-186 pick shipped, and whose absence let a query ClickHouse cannot
// execute reach a deploy pre-check.
//
// What the existing corpus already covers, and why it was not enough:
//
//   - timeintel_backfill_test.go is hermetic. Its synthetic server parses the
//     SQL with regexes, so it proves the builder EMITS the predicates — never
//     that a real server ACCEPTS them. It passed on SQL that raises
//     Code 43 ILLEGAL_TYPE_OF_ARGUMENT on every warm pass.
//   - timeintel_backfill_equiv_integration_test.go does talk to a real server,
//     but it is `//go:build integration` behind CH_TEST_URL and it CREATES AND
//     DROPS a scratch database — it can only ever run against a throwaway, so
//     it runs by hand, and it did not run.
//
// This file closes the gap from the other side: it is in the DEFAULT build (a
// plain `go test ./...` picks it up), it is strictly READ-ONLY, and it executes
// the SQL the production builders actually emit — every cursor-bearing branch —
// against whatever ClickHouse is reachable, which on a developer box or the
// deploy host is the live stack.
//
// GUARD (so CI with no stack stays green). The test enables ITSELF by probing:
// docker on PATH → a running container whose name contains "clickhouse" →
// `SELECT 1` answered → netops.corr_current and netops.corr_objects present.
// Any link missing is a clean t.Skip, never a failure. Override the container
// with TIMEINTEL_LIVE_CH_CONTAINER; set it to "off" to skip unconditionally.
//
// SHIP-SAFETY (scripts/CLAUDE.md §16.5 applied to a test that touches a live
// database): every statement is screened by mustBeReadOnlySQL before it is
// handed to the server — SELECT-only, no write/DDL verb anywhere — and the
// production per-query budget (max_bytes_to_read / max_memory_usage /
// max_execution_time) is carried on the wire, so a mistake costs a failed test
// and never a mutated or overloaded production table.

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"netops/backend/chhttp"
	"netops/backend/timeintel"
)

// liveCHTimeout bounds one docker exec. The server-side cap is
// max_execution_time (30 s, the production budget); this is the outer bound on
// the whole round trip including container startup latency.
const liveCHTimeout = 90 * time.Second

// liveCHWriteVerb is the ship-safety screen: any of these anywhere in a
// statement disqualifies it from being sent to a live server by this file.
var liveCHWriteVerb = regexp.MustCompile(`(?i)\b(INSERT|ALTER|DROP|CREATE|TRUNCATE|DELETE|UPDATE|ATTACH|DETACH|RENAME|OPTIMIZE|SYSTEM|GRANT|REVOKE|SET)\b`)

// mustBeReadOnlySQL refuses to execute anything that is not a bare SELECT.
func mustBeReadOnlySQL(t *testing.T, sql string) {
	t.Helper()
	trimmed := strings.TrimSpace(sql)
	if !strings.HasPrefix(strings.ToUpper(trimmed), "SELECT") {
		t.Fatalf("live-shape test may only run SELECTs, got:\n%s", sql)
	}
	if m := liveCHWriteVerb.FindString(trimmed); m != "" {
		t.Fatalf("live-shape test refuses a statement carrying %q:\n%s", m, sql)
	}
}

// liveCHContainer finds a reachable ClickHouse or skips the test. It probes
// instead of trusting an env var so the corpus runs by default where a stack
// exists and is silent where one does not.
func liveCHContainer(t *testing.T) string {
	t.Helper()
	if v := strings.TrimSpace(os.Getenv("TIMEINTEL_LIVE_CH_CONTAINER")); v != "" {
		if strings.EqualFold(v, "off") {
			t.Skip("TIMEINTEL_LIVE_CH_CONTAINER=off — live shape check disabled")
		}
		if !liveCHUsable(t, v) {
			t.Skipf("TIMEINTEL_LIVE_CH_CONTAINER=%q is not answering — skipping live shape check", v)
		}
		return v
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not on PATH — no live ClickHouse to check the pick/fetch shape against")
	}
	ctx, cancel := context.WithTimeout(context.Background(), liveCHTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "ps",
		"--filter", "status=running", "--format", "{{.Names}}").Output()
	if err != nil {
		t.Skipf("docker ps failed (%v) — skipping live shape check", err)
	}
	for _, name := range strings.Split(string(out), "\n") {
		name = strings.TrimSpace(name)
		if name == "" || !strings.Contains(strings.ToLower(name), "clickhouse") {
			continue
		}
		if liveCHUsable(t, name) {
			return name
		}
	}
	t.Skip("no running ClickHouse container with the netops corr tables — skipping live shape check")
	return ""
}

// liveCHUsable answers whether this container is a ClickHouse that holds the two
// tables the pass reads. Both must exist: a shape check against a server without
// the tables would prove nothing and fail for the wrong reason.
func liveCHUsable(t *testing.T, container string) bool {
	t.Helper()
	out, err := runLiveCH(container, `SELECT count() AS n FROM system.tables
 WHERE database = 'netops' AND name IN ('corr_current','corr_objects') FORMAT JSON`)
	if err != nil {
		return false
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if json.Unmarshal([]byte(out), &parsed) != nil || len(parsed.Data) != 1 {
		return false
	}
	return asFloat(parsed.Data[0]["n"]) == 2
}

// runLiveCH executes one statement with clickhouse-client inside the container.
func runLiveCH(container, sql string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), liveCHTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "exec", container,
		"clickhouse-client", "--query", sql)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", &liveCHError{msg: msg}
	}
	return string(out), nil
}

type liveCHError struct{ msg string }

func (e *liveCHError) Error() string { return e.msg }

// liveCHProbeTag marks every read this file issues, so a query_log dig (and the
// scale ladder's own grading) can tell a test probe apart from the production
// pass — which carries timeIntelBackfillTag instead. Without it the two are
// indistinguishable in system.query_log and a probe run pollutes a rung.
const liveCHProbeTag = "probe186fix5"

// liveCHSettingsFrom appends a per-query budget the Go client would send as URL
// parameters. The builders emit no SETTINGS clause of their own (the client
// adds them), so a shape check that omitted them would test a query the worker
// never actually runs — and max_bytes_to_read is precisely the guard a shape
// regression would trip first.
//
// It takes the budget rather than assuming the production one so the
// narrow-geometry retry (186 fix-5) can be executed with the settings it really
// sends rather than with the wide ones.
func liveCHSettingsFrom(read map[string]string) string {
	kv := map[string]string{
		"tenant_scope":       "'__all__'",
		"max_execution_time": "30",
		"log_comment":        "'" + liveCHProbeTag + "'",
	}
	for k, v := range read {
		kv[k] = v
	}
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+kv[k])
	}
	return "\n SETTINGS " + strings.Join(parts, ", ")
}

// withLiveSettings splices the budget in ahead of FORMAT JSON, which must stay
// last. Everything else about the builder output is untouched — the point of
// this file is to run the PRODUCTION string, not a paraphrase of it.
func withLiveSettings(sql string) string {
	return withLiveSettingsFrom(sql, timeIntelBackfillReadSettings())
}

// withLiveSettingsFrom is withLiveSettings over an explicit read budget.
func withLiveSettingsFrom(sql string, read map[string]string) string {
	const tail = "\n FORMAT JSON"
	if !strings.HasSuffix(sql, tail) {
		return sql + liveCHSettingsFrom(read)
	}
	return strings.TrimSuffix(sql, tail) + liveCHSettingsFrom(read) + tail
}

// execLiveShape runs one builder-produced statement and fails with the server's
// own message. Returns the decoded rows.
func execLiveShape(t *testing.T, container, label, sql string) []map[string]any {
	t.Helper()
	full := withLiveSettings(sql)
	mustBeReadOnlySQL(t, full)
	t.Logf("── %s ──\n%s", label, full)
	out, err := runLiveCH(container, full)
	if err != nil {
		t.Fatalf("%s REJECTED by live ClickHouse:\n%v\n\nSQL:\n%s", label, err, full)
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("%s: response is not JSON: %v", label, err)
	}
	t.Logf("%s ACCEPTED — %d rows", label, len(parsed.Data))
	return parsed.Data
}

// TestTimeIntelBackfillPickAcceptedByLiveClickHouse executes EVERY cursor branch
// of the pick against a live server.
//
// The cold branch alone is what the deployed build proved, and that is the trap:
// a cold pick carries no cursor predicate, so it is accepted, stores a
// watermark, and hands every subsequent pass to a branch that raises Code 43 —
// which is NOT retryable (chhttp classifies only 241/159), so the worker stalls
// for good. Every branch that can ever be built must be executed here.
func TestTimeIntelBackfillPickAcceptedByLiveClickHouse(t *testing.T) {
	container := liveCHContainer(t)
	t.Logf("live ClickHouse container: %s", container)

	// A real UUID and a real timestamp — the branch selection in the builder
	// turns on ValidCorrelationUUID, so the id must be well formed to reach the
	// tuple-comparison branches at all.
	at := time.Date(2026, 8, 22, 1, 8, 15, 31000000, time.UTC)
	ceil := time.Date(2026, 8, 31, 6, 0, 0, 0, time.UTC)
	const id = "55befe37-0418-5dc4-8727-43006a30edab"
	const ceilID = "ffffffff-ffff-ffff-ffff-ffffffffffff"

	cases := []struct {
		label string
		from  timeintel.BackfillCursor
		until timeintel.BackfillCursor
	}{
		{"cold pick (no cursor)", timeintel.BackfillCursor{}, timeintel.BackfillCursor{}},
		{"forward tuple bound (warm cursor)",
			timeintel.BackfillCursor{CreatedAt: at, CorrelationID: id}, timeintel.BackfillCursor{}},
		{"closed lower bound (rewound cursor, no tie-break)",
			timeintel.BackfillCursor{CreatedAt: at}, timeintel.BackfillCursor{}},
		{"re-scan ceiling, tie-broken (both bounds)",
			timeintel.BackfillCursor{CreatedAt: at, CorrelationID: id},
			timeintel.BackfillCursor{CreatedAt: ceil, CorrelationID: ceilID}},
		{"re-scan ceiling, no tie-break",
			timeintel.BackfillCursor{CreatedAt: at},
			timeintel.BackfillCursor{CreatedAt: ceil}},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			sql := timeIntelBackfillPickSQL(int(timeIntelBackfillLookback/time.Second),
				timeIntelBackfillPageRows, c.from, c.until)
			execLiveShape(t, container, c.label, sql)
		})
	}
}

// TestTimeIntelBackfillPickColumnsMatchTheRowScan pins the OTHER half of the
// alias fix: the projected names must be the non-shadowing ones, and they must
// be exactly the keys timeIntelPickPage reads. A rename on one side only would
// leave the worker decoding empty strings — a silent zero-key page, which is
// indistinguishable from "nothing new" and would stall the pass just as quietly
// as the Code 43 did loudly.
func TestTimeIntelBackfillPickColumnsMatchTheRowScan(t *testing.T) {
	container := liveCHContainer(t)
	sql := timeIntelBackfillPickSQL(int(timeIntelBackfillLookback/time.Second), 1,
		timeintel.BackfillCursor{}, timeintel.BackfillCursor{})
	rows := execLiveShape(t, container, "pick column contract", sql)
	if len(rows) == 0 {
		t.Skip("live corr_current has no rows in the lookback window — nothing to check the column contract against")
	}
	for _, want := range []string{"tenant_id_s", "correlation_id_s", "created_at_iso", "version"} {
		if _, ok := rows[0][want]; !ok {
			t.Errorf("pick result has no column %q — timeIntelPickPage reads that key and would decode a zero value; got %v", want, keysOf(rows[0]))
		}
	}
	// And the shadowing names must be GONE, or a future edit could "work" by
	// accident against the wrong column.
	for _, banned := range []string{"correlation_id", "created_at", "tenant_id"} {
		if _, ok := rows[0][banned]; ok {
			t.Errorf("pick projects %q again — that alias shadows the typed column inside WHERE/ORDER BY (Code 43); got %v", banned, keysOf(rows[0]))
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestTimeIntelBackfillCursorPagingAgreesWithScanOrderOnLiveServer is the
// ORDER BY half of the hotfix, and the reason renaming created_at alone was not
// enough. The cursor is compared as a (DateTime64, UUID) tuple server-side; if
// ORDER BY bound the String aliases instead, the scan would advance in UUID
// TEXT order while the cursor advanced in UUID NATIVE order, and every object
// between the two orders would be stepped over and never snapshotted.
//
// The check is order-agnostic in its own right: page 1 followed by page 2-past-
// the-cursor must equal one unbroken scan of the same length. That equality can
// only hold if the ordering and the cursor comparison are the same order.
func TestTimeIntelBackfillCursorPagingAgreesWithScanOrderOnLiveServer(t *testing.T) {
	container := liveCHContainer(t)
	const page = 5
	lookback := int(timeIntelBackfillLookback / time.Second)

	one := execLiveShape(t, container, "page 1 (cold, LIMIT 5)",
		timeIntelBackfillPickSQL(lookback, page, timeintel.BackfillCursor{}, timeintel.BackfillCursor{}))
	if len(one) < page {
		t.Skipf("live corr_current returned %d rows in the window, need %d to page — skipping", len(one), page)
	}
	last := one[len(one)-1]
	cursor := timeintel.BackfillCursor{
		CreatedAt:     parseCHTime(last["created_at_iso"]),
		CorrelationID: strings.TrimSpace(asString(last["correlation_id_s"])),
	}
	if cursor.CreatedAt.IsZero() || !timeintel.ValidCorrelationUUID(cursor.CorrelationID) {
		t.Fatalf("page 1's last row does not yield a usable cursor: %v", last)
	}
	two := execLiveShape(t, container, "page 2 (cursor past page 1's last row)",
		timeIntelBackfillPickSQL(lookback, page, cursor, timeintel.BackfillCursor{}))

	straight := execLiveShape(t, container, "one unbroken scan (LIMIT 10)",
		timeIntelBackfillPickSQL(lookback, 2*page, timeintel.BackfillCursor{}, timeintel.BackfillCursor{}))
	if len(straight) < len(one)+len(two) {
		t.Skipf("only %d rows available for the unbroken scan, paged halves hold %d — skipping",
			len(straight), len(one)+len(two))
	}
	paged := append(append([]map[string]any{}, one...), two...)
	for i := range paged {
		g := asString(paged[i]["correlation_id_s"]) + "@" + asString(paged[i]["created_at_iso"])
		w := asString(straight[i]["correlation_id_s"]) + "@" + asString(straight[i]["created_at_iso"])
		if g != w {
			t.Fatalf("row %d: paged scan gave %s, unbroken scan gave %s — ORDER BY and the cursor comparison disagree, objects between the two orders are being skipped", i, g, w)
		}
	}
	// Strictly forward: the cursor must not re-serve page 1's last row.
	for _, r := range two {
		if asString(r["correlation_id_s"]) == cursor.CorrelationID &&
			parseCHTime(r["created_at_iso"]).Equal(cursor.CreatedAt) {
			t.Fatalf("page 2 re-served the cursor row %s — the forward bound is not strict", cursor.CorrelationID)
		}
	}
}

// TestTimeIntelBackfillFetchAcceptedByLiveClickHouse executes the WIDE half for
// keys taken from the live pick, so the tuple-IN literal list, the toUUID()
// conversions and the partition-pruning created_at slice are all proved against
// real data rather than a regex.
func TestTimeIntelBackfillFetchAcceptedByLiveClickHouse(t *testing.T) {
	container := liveCHContainer(t)
	lookback := int(timeIntelBackfillLookback / time.Second)
	picked := execLiveShape(t, container, "pick for fetch keys (LIMIT 3)",
		timeIntelBackfillPickSQL(lookback, 3, timeintel.BackfillCursor{}, timeintel.BackfillCursor{}))

	keys := make([]timeIntelBackfillKey, 0, len(picked))
	for _, r := range picked {
		id := strings.TrimSpace(asString(r["correlation_id_s"]))
		created := parseCHTime(r["created_at_iso"])
		if !timeintel.ValidCorrelationUUID(id) || created.IsZero() {
			continue
		}
		keys = append(keys, timeIntelBackfillKey{
			TenantID:      asString(r["tenant_id_s"]),
			CorrelationID: id,
			Version:       int(asFloat(r["version"])),
			CreatedAt:     created,
		})
	}
	if len(keys) == 0 {
		// Still prove the fetch TYPE-CHECKS, with a key that matches nothing.
		keys = append(keys, timeIntelBackfillKey{
			TenantID:      "global",
			CorrelationID: "55befe37-0418-5dc4-8727-43006a30edab",
			Version:       1,
			CreatedAt:     time.Now().UTC().Add(-time.Hour),
		})
	}
	from, to := keys[0].CreatedAt, keys[len(keys)-1].CreatedAt
	if to.Before(from) {
		from, to = to, from
	}
	rows := execLiveShape(t, container, "wide fetch (keyed tuple IN + created_at slice)",
		timeIntelBackfillFetchSQL(keys, from, to))
	if len(rows) == 0 {
		return
	}
	// The fetch's aliases ARE the column names, which is safe only because every
	// predicate there is table-qualified (o.created_at). Pin that the row loop's
	// keys are the ones it gets back.
	for _, want := range []string{"tenant_id", "correlation_id", "window_start", "created_at", "owner", "seam_type"} {
		if _, ok := rows[0][want]; !ok {
			t.Errorf("fetch result has no column %q — the snapshot row loop reads it; got %v", want, keysOf(rows[0]))
		}
	}
}

// ── adaptive fetch splitting, against the live table (tracker 186 fix-2) ──────
//
// The 2026-08-31 deploy proved the pick works and the FETCH does not: a single
// wide read for one 2 000-key page read 2.24 GiB and was refused with Code 307
// TOO_MANY_BYTES, every tick, identically. These tests execute that exact shape
// and then drive the PRODUCTION splitter over real keys, so "it converges" is a
// measurement rather than a claim.

// liveSubFetch is one sub-fetch the splitter issued, as observed.
type liveSubFetch struct {
	keys   int
	code   int // 0 = accepted
	rows   int
	narrow bool // issued at the floor geometry (max_block_size=1/max_threads=1)
}

// liveFetchKeys adapts clickhouse-client-in-the-container to the splitter's
// one-shot fetch seam, translating the server's refusal into the classified
// chhttp error the splitter branches on. It runs the PRODUCTION builder with
// the PRODUCTION settings — the point is to exercise the real decision, not a
// paraphrase of it.
func liveFetchKeys(t *testing.T, container string, log *[]liveSubFetch) timeIntelFetchKeys {
	t.Helper()
	return func(_ context.Context, keys []timeIntelBackfillKey, narrow bool) ([]map[string]any, error) {
		from, to := timeIntelKeySpan(keys)
		read := timeIntelBackfillReadSettings()
		if narrow {
			read = timeIntelBackfillNarrowReadSettings()
		}
		sql := withLiveSettingsFrom(timeIntelBackfillFetchSQL(keys, from, to), read)
		mustBeReadOnlySQL(t, sql)
		out, err := runLiveCH(container, sql)
		if err != nil {
			code := liveExceptionCode(err.Error())
			*log = append(*log, liveSubFetch{keys: len(keys), code: code, narrow: narrow})
			return nil, &chhttp.Error{
				Op: "worker query " + timeIntelBackfillTag, Status: 500,
				Code: code, Message: err.Error(), Outcome: chhttp.OutcomeRejected,
			}
		}
		var parsed struct {
			Data []map[string]any `json:"data"`
		}
		if jerr := json.Unmarshal([]byte(out), &parsed); jerr != nil {
			t.Fatalf("sub-fetch of %d keys: response is not JSON: %v", len(keys), jerr)
		}
		*log = append(*log, liveSubFetch{keys: len(keys), rows: len(parsed.Data), narrow: narrow})
		return parsed.Data, nil
	}
}

// reLiveExceptionCode reads the DB::Exception code out of a clickhouse-client
// stderr line. Same grammar chhttp parses off the HTTP body.
var reLiveExceptionCode = regexp.MustCompile(`Code:\s*(\d+)`)

func liveExceptionCode(msg string) int {
	m := reLiveExceptionCode.FindStringSubmatch(msg)
	if len(m) < 2 {
		return 0
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0
	}
	return n
}

// livePickKeys runs the production pick and decodes it exactly as
// timeIntelPickPage does.
func livePickKeys(t *testing.T, container string, n int, from timeintel.BackfillCursor) []timeIntelBackfillKey {
	t.Helper()
	rows := execLiveShape(t, container, "pick "+strconv.Itoa(n)+" keys",
		timeIntelBackfillPickSQL(int(timeIntelBackfillLookback/time.Second), n, from, timeintel.BackfillCursor{}))
	keys := make([]timeIntelBackfillKey, 0, len(rows))
	for _, r := range rows {
		id := strings.TrimSpace(asString(r["correlation_id_s"]))
		created := parseCHTime(r["created_at_iso"])
		if !timeintel.ValidCorrelationUUID(id) || created.IsZero() {
			continue
		}
		keys = append(keys, timeIntelBackfillKey{
			TenantID:      asString(r["tenant_id_s"]),
			CorrelationID: id,
			Version:       int(asFloat(r["version"])),
			CreatedAt:     created,
		})
	}
	return keys
}

// TestTimeIntelBackfillWholePageFetchIsRefusedByLiveClickHouse executes the
// EXACT failing shape — one un-split wide fetch for a full 2 000-key page — and
// asserts the live server refuses it.
//
// It is written as an assertion, not a reproduction: if a future change ever
// makes a whole-page fetch acceptable (a narrower column set, a smaller blob,
// a bigger cap), this test says so loudly rather than leaving the sub-paging in
// place as unexplained overhead.
func TestTimeIntelBackfillWholePageFetchIsRefusedByLiveClickHouse(t *testing.T) {
	container := liveCHContainer(t)
	keys := livePickKeys(t, container, timeIntelBackfillPageRows, timeintel.BackfillCursor{})
	if len(keys) < timeIntelBackfillPageRows {
		t.Skipf("live corr_current holds %d keys in the window, need a full %d-key page", len(keys), timeIntelBackfillPageRows)
	}
	from, to := timeIntelKeySpan(keys)
	sql := withLiveSettings(timeIntelBackfillFetchSQL(keys, from, to))
	mustBeReadOnlySQL(t, sql)
	_, err := runLiveCH(container, sql)
	if err == nil {
		t.Log("NOTE: a whole-page wide fetch is now ACCEPTED by this server — the sub-page cut may be re-measurable")
		return
	}
	code := liveExceptionCode(err.Error())
	t.Logf("whole-page fetch of %d keys REFUSED with code %d: %s", len(keys), code, err)
	if code != chCodeTooManyBytes && code != chCodeMemoryLimitExceeded {
		t.Fatalf("whole-page fetch failed with code %d, which the splitter does NOT act on — the stall would be permanent:\n%v", code, err)
	}
}

// TestTimeIntelBackfillFetchSplitterConvergesOnLiveClickHouse drives the
// PRODUCTION splitter over real keys and asserts it converges: every sub-fetch
// is at or under the sub-page cut, refusals are halved rather than returned,
// and every key is accounted for as either folded or explicitly skipped.
func TestTimeIntelBackfillFetchSplitterConvergesOnLiveClickHouse(t *testing.T) {
	container := liveCHContainer(t)
	// Four sub-pages' worth: enough to exercise the sub-page loop AND leave the
	// tree room to halve inside the production deadline over docker exec, whose
	// per-query process spawn is an order of magnitude slower than the HTTP path
	// the worker really uses.
	const want = 4 * timeIntelBackfillFetchSubPageKeys
	keys := livePickKeys(t, container, want, timeintel.BackfillCursor{})
	if len(keys) == 0 {
		t.Skip("live corr_current has no rows in the lookback window")
	}

	var log []liveSubFetch
	s := &server{}
	rows, err := s.timeIntelFetchPageWith(context.Background(), keys, liveFetchKeys(t, container, &log))
	if err != nil {
		t.Fatalf("the splitter returned an error over %d live keys — it must degrade, not stall: %v", len(keys), err)
	}
	skipped := s.timeIntelFetchOversizeSkipped.Load() + s.timeIntelFetchBudgetSkipped.Load()
	for i, f := range log {
		t.Logf("sub-fetch %2d: %4d keys → code %d, %d rows (narrow=%v)", i, f.keys, f.code, f.rows, f.narrow)
		if f.keys > timeIntelBackfillFetchSubPageKeys {
			t.Errorf("sub-fetch %d asked for %d keys, above the %d sub-page cut", i, f.keys, timeIntelBackfillFetchSubPageKeys)
		}
	}
	t.Logf("splitter over %d live keys: %d sub-fetches, %d splits, %d rows, %d skipped (%d oversize, %d budget)",
		len(keys), len(log), s.timeIntelFetchSplits.Load(), len(rows), skipped,
		s.timeIntelFetchOversizeSkipped.Load(), s.timeIntelFetchBudgetSkipped.Load())

	if len(log) > timeIntelBackfillFetchMaxSubFetches {
		t.Errorf("the tree ran %d sub-fetches, above the %d cap", len(log), timeIntelBackfillFetchMaxSubFetches)
	}
	// Every refusal must have been acted on: a logged refusal with no smaller
	// sub-fetch after it would mean the splitter gave up silently.
	for i, f := range log {
		if f.code == 0 {
			continue
		}
		if i+1 >= len(log) {
			if skipped == 0 {
				t.Errorf("the last sub-fetch was refused (code %d) and nothing was skipped — that refusal vanished", f.code)
			}
			continue
		}
		if log[i+1].narrow {
			// The floor retry re-asks for the SAME keys at a narrower block
			// geometry — that IS the action taken on this refusal (186 fix-5).
			continue
		}
		if log[i+1].keys >= f.keys && f.keys > timeIntelBackfillFetchSplitMinKeys {
			t.Errorf("sub-fetch %d was refused at %d keys and the next asked for %d — the list did not halve",
				i, f.keys, log[i+1].keys)
		}
	}
	// Accounting: nothing may disappear between the pick and the fold.
	if int64(len(rows))+skipped < int64(len(keys)) {
		t.Errorf("%d keys in, %d rows + %d skipped out — %d objects are unaccounted for",
			len(keys), len(rows), skipped, int64(len(keys))-int64(len(rows))-skipped)
	}
}

// TestTimeIntelBackfillPassShapeAdvancesWatermarkOnLiveClickHouse is the whole
// pass, read-only: pick a page, split-fetch it, and compute the cursor the pass
// WOULD persist. Nothing is written — not to ClickHouse, not to the snapshot
// store, not to the cursor KV — but the watermark arithmetic is the production
// one, so "the pass would advance" is proved rather than assumed.
//
// This is the assertion the live stall violated: the pre-fix pass produced
// pages = 0 and never wrote a watermark, so every 15-minute tick repeated the
// identical failing read forever.
func TestTimeIntelBackfillPassShapeAdvancesWatermarkOnLiveClickHouse(t *testing.T) {
	container := liveCHContainer(t)
	const page = 2 * timeIntelBackfillFetchSubPageKeys
	keys := livePickKeys(t, container, page, timeintel.BackfillCursor{})
	if len(keys) == 0 {
		t.Skip("live corr_current has no rows in the lookback window")
	}

	var log []liveSubFetch
	s := &server{}
	rows, err := s.timeIntelFetchPageWith(context.Background(), keys, liveFetchKeys(t, container, &log))
	if err != nil {
		t.Fatalf("page fetch: %v", err)
	}
	// What run() does with the page: the cursor comes from the PICK's last key,
	// never from what the fetch managed to return — which is exactly why a
	// poisoned object cannot hold the mark still.
	last := keys[len(keys)-1]
	start := timeintel.BackfillCursor{}
	next := start.Advance(last.CreatedAt, last.CorrelationID, time.Now().UTC())
	if next.IsZero() || !next.CreatedAt.Equal(last.CreatedAt) || next.CorrelationID != last.CorrelationID {
		t.Fatalf("the pass would not advance: cursor %+v after a %d-key page", next, len(keys))
	}
	t.Logf("simulated pass: pick %d keys → %d sub-fetches → %d rows folded, %d skipped; watermark %s → %s (%s)",
		len(keys), len(log), len(rows),
		s.timeIntelFetchOversizeSkipped.Load()+s.timeIntelFetchBudgetSkipped.Load(),
		"zero", next.CreatedAt.Format(time.RFC3339Nano), next.CorrelationID)

	// And the NEXT pick, from that cursor, must be strictly past the page — the
	// other half of "no repeat forever".
	after := livePickKeys(t, container, 5, next)
	for _, k := range after {
		if k.CreatedAt.Before(next.CreatedAt) ||
			(k.CreatedAt.Equal(next.CreatedAt) && k.CorrelationID <= next.CorrelationID) {
			t.Errorf("the pick after the advanced watermark re-served %s@%s — the pass would repeat",
				k.CorrelationID, k.CreatedAt)
		}
	}
}

// TestTimeIntelBackfillFetchSplitterFoldsAWholeLivePage replays the PRODUCTION
// splitter over a full 2 000-key page of the live table — the exact unit the
// worker fetches — and asserts the whole page is accounted for, with the floor
// refusals RESCUED by the narrow-geometry retry rather than skipped (186 fix-5).
//
// OPT-IN. Unlike the rest of this file it is not a shape check but a
// MEASUREMENT: 2 000 keys over docker exec is ~32 sub-pages plus the split tree
// and costs minutes of a developer's `go test`, so it runs only when asked. The
// cheap 256-key convergence check above stays in the default build.
//
// Every read it issues carries log_comment='probe186fix5' (liveCHProbeTag), so
// a scale run graded off system.query_log can discount this replay.
//
// TRANSPORT. The page is replayed in liveReplaySliceKeys-key slices, each
// getting its own production fetch tree. That is not a weaker splitter — the
// sub-page loop is already independent per 64-key cut and every decision under
// test (halve, floor, narrow-retry, skip) is taken inside one sub-page — it is
// a correction for the harness: this file talks to ClickHouse through
// `docker exec`, which pays a process spawn per query (measured 1.4-1.5 s
// under concurrent load, against the worker's sub-second HTTP path), so a
// whole page in ONE tree exhausts timeIntelBackfillFetchSplitDeadline on the
// transport rather than on anything the splitter did. Slicing keeps the
// wall-clock budget per query honest while still covering all 2 000 keys.
const liveReplaySliceKeys = 512

func TestTimeIntelBackfillFetchSplitterFoldsAWholeLivePage(t *testing.T) {
	if strings.TrimSpace(os.Getenv("TIMEINTEL_LIVE_FULL_PAGE")) == "" {
		t.Skip("set TIMEINTEL_LIVE_FULL_PAGE=1 to replay a whole live page (minutes of live reads)")
	}
	container := liveCHContainer(t)
	keys := livePickKeys(t, container, timeIntelBackfillPageRows, timeintel.BackfillCursor{})
	if len(keys) < timeIntelBackfillPageRows {
		t.Skipf("live corr_current holds %d keys in the window, need a full %d-key page", len(keys), timeIntelBackfillPageRows)
	}

	var log []liveSubFetch
	s := &server{}
	started := time.Now()
	folded := 0
	for start := 0; start < len(keys); start += liveReplaySliceKeys {
		end := start + liveReplaySliceKeys
		if end > len(keys) {
			end = len(keys)
		}
		rows, err := s.timeIntelFetchPageWith(context.Background(), keys[start:end], liveFetchKeys(t, container, &log))
		if err != nil {
			t.Fatalf("the splitter returned an error over live keys [%d,%d) — it must degrade, not stall: %v", start, end, err)
		}
		folded += len(rows)
	}
	elapsed := time.Since(started)
	narrow, refused := 0, 0
	for _, f := range log {
		if f.narrow {
			narrow++
		}
		if f.code != 0 {
			refused++
		}
	}
	t.Logf("full-page replay [%s → %s]: %d keys → %d sub-fetches (%d refused, %d narrow, %s/query), %d splits, %d rows folded in %s; "+
		"narrow_retries=%d oversize_skipped=%d budget_skipped=%d",
		started.UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339),
		len(keys), len(log), refused, narrow, (elapsed / time.Duration(max(len(log), 1))).Round(10*time.Millisecond),
		s.timeIntelFetchSplits.Load(), folded, elapsed.Round(time.Second),
		s.timeIntelFetchNarrowRetries.Load(), s.timeIntelFetchOversizeSkipped.Load(), s.timeIntelFetchBudgetSkipped.Load())

	skipped := s.timeIntelFetchOversizeSkipped.Load() + s.timeIntelFetchBudgetSkipped.Load()
	if int64(folded)+skipped != int64(len(keys)) {
		t.Errorf("%d keys in, %d rows + %d skipped out — the page does not add up", len(keys), folded, skipped)
	}
	// The fix's own assertion: an object may only be written off as oversize
	// AFTER the floor geometry was tried on it and refused too. A one-key
	// refusal with no narrow sub-fetch of the same key after it means the
	// retry was skipped and the loss is avoidable.
	for i, f := range log {
		if f.code == 0 || f.keys > timeIntelBackfillFetchSplitMinKeys || f.narrow {
			continue
		}
		if i+1 >= len(log) || !log[i+1].narrow || log[i+1].keys != f.keys {
			t.Errorf("floor sub-fetch %d was refused at %d keys and was not retried at the narrow geometry — that is avoidable data loss",
				i, f.keys)
		}
	}
	if s.timeIntelFetchBudgetSkipped.Load() > 0 {
		t.Errorf("%d objects were skipped for split budget on a single page — the tree ran out of %s / %d sub-fetches",
			s.timeIntelFetchBudgetSkipped.Load(), timeIntelBackfillFetchSplitDeadline, timeIntelBackfillFetchMaxSubFetches)
	}
	if got := s.timeIntelFetchOversizeSkipped.Load(); got > 0 {
		t.Logf("NOTE: %d objects were refused even at max_block_size=1/max_threads=1 — irreducible, and worth an operator's look", got)
	}
}

// ── ClickHouse-native UUID order (ultra finding #4) ──────────────────────────

// TestTimeIntelLiveUUIDOrderMatchesCursorComparator re-verifies, against a real
// server, the empirical fact timeintel.CompareCorrelationUUID encodes: ORDER BY
// on a UUID compares the SECOND half of the canonical text first, big-endian
// within each half (first measured 2026-09-01, ClickHouse 24.8.14.39,
// log_comment 'probe-ultra-ti'). The cursor's Ahead/Advance tie-break and the
// pick SQL's ORDER BY + tuple predicate must agree on ONE order, or every
// same-millisecond page boundary is re-read or skipped — so the agreement is
// pinned against the live server, not only against a probe transcript.
func TestTimeIntelLiveUUIDOrderMatchesCursorComparator(t *testing.T) {
	container := liveCHContainer(t)
	fixture := []string{
		"0000000a-0000-0000-0000-000000000000",
		"a0000000-0000-0000-0000-000000000000",
		"ffffffff-ffff-ffff-0000-000000000001",
		"00000000-0000-0000-0000-00000000000a",
		"00000000-0000-0000-a000-000000000000",
		"00000000-0000-0000-ffff-ffffffffffff",
		"00000000-0000-0001-ffff-ffffffffffff",
	}
	// Hand the server TEXT order — deliberately not the expected answer — so a
	// server that echoed its input would fail rather than trivially pass.
	shuffled := append([]string(nil), fixture...)
	sort.Strings(shuffled)
	var arr strings.Builder
	for i, id := range shuffled {
		if i > 0 {
			arr.WriteString(",")
		}
		arr.WriteString("toUUID('" + id + "')")
	}
	sql := `SELECT toString(u) AS u_s FROM (SELECT arrayJoin([` + arr.String() + `]) AS u) ORDER BY u ASC FORMAT JSON`
	mustBeReadOnlySQL(t, sql)
	out, err := runLiveCH(container, sql)
	if err != nil {
		t.Fatalf("live UUID order probe: %v", err)
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed.Data) != len(fixture) {
		t.Fatalf("server returned %d rows, want %d", len(parsed.Data), len(fixture))
	}
	got := make([]string, 0, len(parsed.Data))
	for _, r := range parsed.Data {
		got = append(got, asString(r["u_s"]))
	}
	want := append([]string(nil), fixture...)
	sort.Slice(want, func(i, j int) bool { return timeintel.CompareCorrelationUUID(want[i], want[j]) < 0 })
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("live server order and CompareCorrelationUUID disagree at %d:\n server: %v\n cursor: %v", i, got, want)
		}
	}
}
