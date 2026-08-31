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

// liveCHSettings appends the production per-query budget the Go client sends as
// URL parameters. The builders emit no SETTINGS clause of their own (the client
// adds them), so a shape check that omitted them would test a query the worker
// never actually runs — and max_bytes_to_read is precisely the guard a shape
// regression would trip first.
func liveCHSettings() string {
	kv := map[string]string{"tenant_scope": "'__all__'", "max_execution_time": "30"}
	for k, v := range timeIntelBackfillReadSettings() {
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
	const tail = "\n FORMAT JSON"
	if !strings.HasSuffix(sql, tail) {
		return sql + liveCHSettings()
	}
	return strings.TrimSuffix(sql, tail) + liveCHSettings() + tail
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
