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

// liveCHHasProjectedSeamType answers whether this server's corr_current has
// already converged onto the tracker-197 column.
//
// The fold's read selects c.seam_type, so a server that has not yet run the
// boot ALTER (chschema.CorrSchemaDDL) answers Code 47 UNKNOWN_IDENTIFIER — a
// TRANSIENT deployment state, not a defect in the builder, and exactly the
// class of "link missing" this file skips on rather than fails on (see the
// GUARD note at the top). Skipping is what keeps a developer box mid-upgrade,
// and CI with a stale volume, from reporting a red build for a schema the next
// api boot converges on its own.
//
// It is deliberately NOT folded into liveCHUsable: the PICK half is unaffected
// by the column and must keep being checked against a not-yet-converged server.
func liveCHHasProjectedSeamType(t *testing.T, container string) bool {
	t.Helper()
	out, err := runLiveCH(container, `SELECT count() AS n FROM system.columns
 WHERE database = 'netops' AND table = 'corr_current' AND name = 'seam_type' FORMAT JSON`)
	if err != nil {
		return false
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if json.Unmarshal([]byte(out), &parsed) != nil || len(parsed.Data) != 1 {
		return false
	}
	return asFloat(parsed.Data[0]["n"]) == 1
}

// liveCHWithSeamType is liveCHContainer plus that convergence check, for the
// tests that execute the fold's read.
func liveCHWithSeamType(t *testing.T) string {
	t.Helper()
	container := liveCHContainer(t)
	if !liveCHHasProjectedSeamType(t, container) {
		t.Skip("live netops.corr_current has no seam_type column yet — the api boot converge (tracker 197 ADD COLUMN) has not run against this server")
	}
	return container
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

// TestTimeIntelBackfillFetchAcceptedByLiveClickHouse executes the fold's read
// for keys taken from the live pick, so the tuple-IN literal list, the toUUID()
// conversions and the FINAL collapse are proved against real data rather than a
// regex — including that `seam_type` EXISTS as a column on the live table
// (tracker 197: a server that has not run the converge ALTER answers
// Code 47 UNKNOWN_IDENTIFIER, and this is where that would surface).
func TestTimeIntelBackfillFetchAcceptedByLiveClickHouse(t *testing.T) {
	container := liveCHWithSeamType(t)
	keys := livePickKeys(t, container, 3, timeintel.BackfillCursor{})
	if len(keys) == 0 {
		// Still prove the fetch TYPE-CHECKS, with a key that matches nothing.
		keys = append(keys, timeIntelBackfillKey{
			TenantID:      "global",
			CorrelationID: "55befe37-0418-5dc4-8727-43006a30edab",
			Version:       1,
			CreatedAt:     time.Now().UTC().Add(-time.Hour),
		})
	}
	rows := execLiveShape(t, container, "fold fetch (keyed tuple IN over corr_current FINAL)",
		timeIntelBackfillFetchSQL(keys))
	if len(rows) == 0 {
		return
	}
	// The fetch's aliases ARE the column names, which is safe only because every
	// predicate there is table-qualified (c.tenant_id). Pin that the row loop's
	// keys are the ones it gets back — all twelve.
	for _, want := range []string{
		"tenant_id", "correlation_id", "window_start", "window_end", "created_at",
		"verdict_tier", "top_confidence", "top_hypothesis", "evidence_missing",
		"affected", "state", "owner", "seam_type",
	} {
		if _, ok := rows[0][want]; !ok {
			t.Errorf("fetch result has no column %q — the snapshot row loop reads it; got %v", want, keysOf(rows[0]))
		}
	}
}

// ── the fold's read against the live table (tracker 197) ─────────────────────
//
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

// TestTimeIntelBackfillWholePageFetchIsAcceptedByLiveClickHouse is the exact
// INVERSION of the test it replaces, and the live proof of tracker 197.
//
// Against corr_objects, ONE un-split fetch for a full 2 000-key page read
// 2.24 GiB and was refused with Code 307 TOO_MANY_BYTES — every tick,
// identically, because the pass is deterministic. That refusal is why the
// sub-paging splitter, its halving tree, its floor retry and its oversize-skip
// path existed. Re-measured here on the resident corpus while building this
// change: 1.18 GiB for a 64-key SUB-page, and the whole page still refused at
// the 2 GiB cap.
//
// With the twelfth value projected onto corr_current, the same page is one
// keyed read of the narrow projection — 555 MiB, 0.83 s, 36 MiB peak — and the
// server ACCEPTS it inside the production budget. If that ever stops being
// true, this test says so loudly rather than letting the pass stall.
func TestTimeIntelBackfillWholePageFetchIsAcceptedByLiveClickHouse(t *testing.T) {
	container := liveCHWithSeamType(t)
	keys := livePickKeys(t, container, timeIntelBackfillPageRows, timeintel.BackfillCursor{})
	if len(keys) < timeIntelBackfillPageRows {
		t.Skipf("live corr_current holds %d keys in the window, need a full %d-key page", len(keys), timeIntelBackfillPageRows)
	}
	sql := withLiveSettings(timeIntelBackfillFetchSQL(keys))
	mustBeReadOnlySQL(t, sql)
	started := time.Now()
	out, err := runLiveCH(container, sql)
	elapsed := time.Since(started)
	if err != nil {
		code := liveExceptionCode(err.Error())
		t.Fatalf("a whole-page fetch of %d keys was REFUSED with code %d — the pass would stall on every tick:\n%v",
			len(keys), code, err)
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if jerr := json.Unmarshal([]byte(out), &parsed); jerr != nil {
		t.Fatalf("whole-page fetch: response is not JSON: %v", jerr)
	}
	t.Logf("whole-page fetch: %d keys → %d rows in %s, ONE query inside the production budget",
		len(keys), len(parsed.Data), elapsed.Round(10*time.Millisecond))
	// Every picked key must come back. FINAL collapses re-persists, so a short
	// answer means rows are being LOST, not deduplicated.
	if len(parsed.Data) < len(keys) {
		t.Errorf("%d keys in, %d rows out — %d objects would go unsnapshotted",
			len(keys), len(parsed.Data), len(keys)-len(parsed.Data))
	}
}

// TestTimeIntelBackfillPassShapeAdvancesWatermarkOnLiveClickHouse is the whole
// pass, read-only: pick a page, fetch it, and compute the cursor the pass WOULD
// persist. Nothing is written — not to ClickHouse, not to the snapshot store,
// not to the cursor KV — but the watermark arithmetic is the production one, so
// "the pass would advance" is proved rather than assumed.
//
// This is the assertion the live stall violated: the pre-fix pass produced
// pages = 0 and never wrote a watermark, so every 15-minute tick repeated the
// identical failing read forever.
func TestTimeIntelBackfillPassShapeAdvancesWatermarkOnLiveClickHouse(t *testing.T) {
	container := liveCHWithSeamType(t)
	const page = 128
	keys := livePickKeys(t, container, page, timeintel.BackfillCursor{})
	if len(keys) == 0 {
		t.Skip("live corr_current has no rows in the lookback window")
	}
	rows := execLiveShape(t, container, "fold fetch for the simulated page",
		timeIntelBackfillFetchSQL(keys))

	// What run() does with the page: the cursor comes from the PICK's last key,
	// never from what the fetch managed to return.
	last := keys[len(keys)-1]
	start := timeintel.BackfillCursor{}
	next := start.Advance(last.CreatedAt, last.CorrelationID, time.Now().UTC())
	if next.IsZero() || !next.CreatedAt.Equal(last.CreatedAt) || next.CorrelationID != last.CorrelationID {
		t.Fatalf("the pass would not advance: cursor %+v after a %d-key page", next, len(keys))
	}
	t.Logf("simulated pass: pick %d keys → 1 fetch → %d rows folded; watermark zero → %s (%s)",
		len(keys), len(rows), next.CreatedAt.Format(time.RFC3339Nano), next.CorrelationID)

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
