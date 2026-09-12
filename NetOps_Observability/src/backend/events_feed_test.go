// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"netops/backend/timeintel"
)

func TestFeedCursorRoundTrip(t *testing.T) {
	sid := "0192f1a2-3b4c-7d5e-8f60-112233445566"
	enc := encodeFeedCursor(1718460000123, sid)
	ms, gotSid, ok := decodeFeedCursor(enc)
	if !ok || ms != 1718460000123 || gotSid != sid {
		t.Fatalf("round-trip failed: ms=%d sid=%q ok=%v", ms, gotSid, ok)
	}
	// garbage / non-UUID signal id must be rejected (fail-closed: no cursor clause)
	if _, _, ok := decodeFeedCursor("not-base64!!"); ok {
		t.Fatal("expected garbage cursor to be rejected")
	}
	bad := encodeFeedCursor(1, "not-a-uuid")
	if _, _, ok := decodeFeedCursor(bad); ok {
		t.Fatal("expected non-UUID signal id to be rejected")
	}
}

func TestSanitizeCHText(t *testing.T) {
	cases := map[string]string{
		"leaf1":            "leaf1",
		"path:a->b":        "path:a->b",
		"Gi0/1":            "Gi0/1",
		"a' OR '1'='1":     "a OR 11",         // quotes + '=' stripped
		"foo;DROP TABLE x": "fooDROP TABLE x", // ';' stripped
		"x\\y":             "xy",              // backslash stripped
	}
	for in, want := range cases {
		if got := sanitizeCHText(in); got != want {
			t.Errorf("sanitizeCHText(%q) = %q, want %q", in, got, want)
		}
	}
	// length bound
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}
	if got := sanitizeCHText(string(long)); len(got) != 128 {
		t.Errorf("expected length cap 128, got %d", len(got))
	}
}

func TestFeedTitle(t *testing.T) {
	if got := feedTitle("bgp_adjacency_change", "10.0.0.1", "syslog"); got != "BGP neighbor change — 10.0.0.1" {
		t.Errorf("bgp title = %q", got)
	}
	if got := feedTitle("probe_loss", "path:dallas->equinix", "probe"); got != "Packet loss — path:dallas->equinix" {
		t.Errorf("probe title = %q", got)
	}
	// no entity → kind only, no trailing separator
	if got := feedTitle("sot_drift", "", "sot_drift"); got != "Inventory drift" {
		t.Errorf("empty-entity title = %q", got)
	}
	if got := feedTitle("unknown", "unknown", "metric"); got != "Unknown" {
		t.Errorf("unknown-entity title = %q", got)
	}
}

// The unified feed's honesty contract (owner directive: DON'T HIDE): the
// response carries the TRUE window count (a real COUNT over the same filters,
// cursor-independent), every ClickHouse read rides the caller's tenant_scope,
// and a short page never dangles a next_cursor.
func TestEventsFeedTotalTenantScopedAndHonestCursor(t *testing.T) {
	sqls, scopes := corrFakeCH(t)
	s := corrTestServer(t)

	w := httptest.NewRecorder()
	s.handleEventsFeed(w, req(http.MethodGet, "/api/events/feed?from=24h&severity=crit&limit=50", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	for i, sc := range *scopes {
		if sc != "acme" {
			t.Fatalf("TENANT LEAK: feed query %d ran at tenant_scope=%q, want acme", i, sc)
		}
	}
	// items + total + 3 facets = 5 reads; the total query is a real COUNT over
	// the SAME filtered window (severity filter included), not the page length.
	var totalSQL string
	for _, q := range *sqls {
		if strings.Contains(q, "count() AS c") && !strings.Contains(q, "GROUP BY") {
			totalSQL = q
		}
	}
	if totalSQL == "" {
		t.Fatalf("no true-total COUNT query issued; queries:\n%s", strings.Join(*sqls, "\n---\n"))
	}
	for _, must := range []string{"FROM netops.corr_signals", "severity = 'crit'", "ts >= now() - INTERVAL 86400 SECOND"} {
		if !strings.Contains(totalSQL, must) {
			t.Errorf("total query missing %q:\n%s", must, totalSQL)
		}
	}
	var body struct {
		Total      int64  `json:"total"`
		NextCursor string `json:"next_cursor"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.NextCursor != "" {
		t.Errorf("short (empty) page must not advertise a next_cursor, got %q", body.NextCursor)
	}
}

func TestFeedTotalSQLShape(t *testing.T) {
	sql := feedTotalSQL("ts >= now() - INTERVAL 3600 SECOND AND source = 'syslog'")
	if !strings.Contains(sql, "count()") || !strings.Contains(sql, "source = 'syslog'") ||
		!strings.Contains(sql, "INTERVAL 3600 SECOND") {
		t.Errorf("total SQL lost its filters:\n%s", sql)
	}
}

// #81 P3G: address-like feed entities are named via the unified app resolver —
// entity_app appears and the title gains "(app)" ONLY when identity is on file;
// everything else renders byte-identical to before (no "unknown" spam).
func TestEventsFeedEntityAppEnrichment(t *testing.T) {
	// fake CH serving one prefix-entity row (acme's tagged cloud IP) and one
	// device row; the count/facet queries get empty data.
	items := `{"meta":[],"data":[
	  {"signal_id":"0192f1a2-3b4c-7d5e-8f60-112233445566","ts_iso":"2026-07-20T00:00:00Z","ts_ms":"1752969600000",
	   "source":"flow","kind":"flow_volume_anomaly","severity":"warn","entity_type":"prefix","entity_id":"10.0.1.10/32","site":""},
	  {"signal_id":"0192f1a2-3b4c-7d5e-8f60-112233445577","ts_iso":"2026-07-20T00:00:01Z","ts_ms":"1752969601000",
	   "source":"syslog","kind":"link_state_change","severity":"warn","entity_type":"device","entity_id":"leaf1","site":""}
	],"rows":2}`
	first := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if first {
			first = false
			_, _ = w.Write([]byte(items))
			return
		}
		_, _ = w.Write([]byte(`{"meta":[],"data":[],"rows":0}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")

	s := batchTestServer(t) // roles + cloudApp: acme's 10.0.1.10 → billing

	w := httptest.NewRecorder()
	s.handleEventsFeed(w, req(http.MethodGet, "/api/events/feed?from=24h", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Items) != 2 {
		t.Fatalf("items = %d, want 2", len(body.Items))
	}
	ipRow, devRow := body.Items[0], body.Items[1]
	if got := ipRow["entity_app"]; got != "billing" {
		t.Fatalf("entity_app = %v, want billing", got)
	}
	if got := ipRow["title"]; got != "Traffic volume change — 10.0.1.10/32 (billing)" {
		t.Fatalf("enriched title = %q", got)
	}
	// non-address entity: no entity_app key, title unchanged
	if _, has := devRow["entity_app"]; has {
		t.Fatalf("device row must not carry entity_app: %+v", devRow)
	}
	if got := devRow["title"]; got != "Link up/down — leaf1" {
		t.Fatalf("device title changed: %q", got)
	}
}

// feedEntityApp is default-closed: another tenant's identity never names an
// entity, non-address kinds never resolve, and unresolved stays "".
func TestFeedEntityAppScoping(t *testing.T) {
	s := batchTestServer(t)
	ov := tenantOverrides{}
	if got := s.feedEntityApp("acme", false, ov, nil, "prefix", "10.0.1.10/32"); got != "billing" {
		t.Fatalf("acme prefix → %q, want billing", got)
	}
	if got := s.feedEntityApp("globex", false, ov, nil, "prefix", "10.0.1.10/32"); got != "" {
		t.Fatalf("TENANT LEAK: globex resolved acme's identity: %q", got)
	}
	if got := s.feedEntityApp("acme", false, ov, nil, "device", "10.0.1.10"); got != "" {
		t.Fatalf("device entity must not resolve: %q", got)
	}
	if got := s.feedEntityApp("acme", false, ov, nil, "prefix", "203.0.113.9"); got != "" {
		t.Fatalf("unresolved must stay empty, got %q", got)
	}
}

// ── 3.9-02: the keyset cursor and the ORDER BY must sort by the SAME order ──
//
// ClickHouse does not order a UUID the way its canonical text orders (the two
// 64-bit halves are swapped relative to the text — measured, see
// timeintel/cursor.go). So `ORDER BY s.signal_id` and a predicate over
// `toString(s.signal_id)` are two DIFFERENT total orders, and on a millisecond
// tie that straddles a page boundary the walk drops rows and repeats others.
//
// The test below is not a string assertion on the SQL: it stands up a
// ClickHouse stand-in that EVALUATES the page query the way the server would —
// sorting by whatever the ORDER BY names, filtering by whatever the cursor
// predicate names — and then walks every page. The invariant is the one an
// operator actually depends on: every row in the window comes back exactly
// once.

// feedFakeRow is one row of the fake corr_signals table.
type feedFakeRow struct {
	id string
	ms int64
}

var (
	feedOrderByRe  = regexp.MustCompile(`ORDER BY s\.ts DESC, (\S+) DESC`)
	feedLimitRe    = regexp.MustCompile(`LIMIT (\d+)`)
	feedCursorRe   = regexp.MustCompile(`\(s\.ts < '([^']+)' OR \(s\.ts = '[^']+' AND (.+)\)\)`)
	feedCHTimeForm = "2006-01-02 15:04:05.000"
)

// feedTieCompare answers a tie-break comparison the way ClickHouse would for
// the SQL expression the query names: the raw UUID column compares in
// ClickHouse's native UUID order, toString() compares as text.
func feedTieCompare(expr, a, b string) (int, error) {
	switch expr {
	case "s.signal_id":
		return timeintel.CompareCorrelationUUID(a, b), nil
	case "toString(s.signal_id)":
		return strings.Compare(a, b), nil
	default:
		return 0, fmt.Errorf("unrecognised tie-break expression %q", expr)
	}
}

// feedEvalPageSQL runs the feed's page query against the in-memory table.
func feedEvalPageSQL(sql string, rows []feedFakeRow) ([]feedFakeRow, error) {
	om := feedOrderByRe.FindStringSubmatch(sql)
	if om == nil {
		return nil, errors.New("page query carries no recognisable ORDER BY")
	}
	orderExpr := om[1]
	lm := feedLimitRe.FindStringSubmatch(sql)
	if lm == nil {
		return nil, errors.New("page query carries no LIMIT")
	}
	limit, err := strconv.Atoi(lm[1])
	if err != nil {
		return nil, fmt.Errorf("unreadable LIMIT: %w", err)
	}

	kept := make([]feedFakeRow, 0, len(rows))
	if cm := feedCursorRe.FindStringSubmatch(sql); cm != nil {
		ts, err := time.Parse(feedCHTimeForm, cm[1])
		if err != nil {
			return nil, fmt.Errorf("unreadable cursor timestamp %q: %w", cm[1], err)
		}
		curMS := ts.UTC().UnixMilli()
		lhs, rhs, found := strings.Cut(cm[2], " < ")
		if !found {
			return nil, fmt.Errorf("unrecognised tie-break predicate %q", cm[2])
		}
		curID := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(rhs, "toUUID("), ")"), "'")
		for _, row := range rows {
			switch {
			case row.ms < curMS:
				kept = append(kept, row)
			case row.ms == curMS:
				c, err := feedTieCompare(lhs, row.id, curID)
				if err != nil {
					return nil, err
				}
				if c < 0 {
					kept = append(kept, row)
				}
			}
		}
	} else {
		kept = append(kept, rows...)
	}

	var sortErr error
	sort.SliceStable(kept, func(i, j int) bool {
		if kept[i].ms != kept[j].ms {
			return kept[i].ms > kept[j].ms // ts DESC
		}
		c, err := feedTieCompare(orderExpr, kept[i].id, kept[j].id)
		if err != nil {
			sortErr = err
		}
		return c > 0 // tie-break DESC
	})
	if sortErr != nil {
		return nil, sortErr
	}
	if len(kept) > limit {
		kept = kept[:limit]
	}
	return kept, nil
}

// feedCursorFakeCH stands up the evaluating ClickHouse stand-in.
func feedCursorFakeCH(t *testing.T, rows []feedFakeRow) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sql := string(b)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(sql, "GROUP BY k"): // facets
			_, _ = w.Write([]byte(`{"meta":[],"data":[],"rows":0}`))
			return
		case strings.Contains(sql, "count() AS c"): // true window total
			fmt.Fprintf(w, `{"meta":[],"data":[{"c":"%d"}],"rows":1}`, len(rows))
			return
		}
		page, err := feedEvalPageSQL(sql, rows)
		if err != nil {
			t.Errorf("fake ClickHouse could not evaluate the page query: %v\n%s", err, sql)
			http.Error(w, "unevaluable", http.StatusBadRequest)
			return
		}
		out := make([]string, 0, len(page))
		for _, row := range page {
			ts := time.UnixMilli(row.ms).UTC()
			out = append(out, fmt.Sprintf(
				`{"signal_id":%q,"ts_iso":%q,"ts_ms":"%d","source":"syslog","kind":"link_state_change",`+
					`"severity":"warn","entity_type":"device","entity_id":"leaf1","site":"","attrs":"{}"}`,
				row.id, ts.Format(time.RFC3339Nano), row.ms))
		}
		fmt.Fprintf(w, `{"meta":[],"data":[%s],"rows":%d}`, strings.Join(out, ","), len(out))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
}

func TestEventsFeedPageWalkReturnsEveryRowExactlyOnce(t *testing.T) {
	// Six ids that share ONE millisecond. Their text order and ClickHouse's
	// native UUID order are deliberately scrambled relative to each other: the
	// fourth group drives the native order, the first group the text order.
	tied := []string{
		"00000001-0000-0000-0003-000000000000",
		"00000002-0000-0000-0006-000000000000",
		"00000003-0000-0000-0001-000000000000",
		"00000004-0000-0000-0005-000000000000",
		"00000005-0000-0000-0002-000000000000",
		"00000006-0000-0000-0004-000000000000",
	}
	// Fixture guard: if the two orders ever agreed, this test would pass for
	// the wrong reason.
	agree := true
	for i := 1; i < len(tied); i++ {
		if (timeintel.CompareCorrelationUUID(tied[i-1], tied[i]) < 0) != (strings.Compare(tied[i-1], tied[i]) < 0) {
			agree = false
			break
		}
	}
	if agree {
		t.Fatal("fixture is useless: the native UUID order and the text order agree on these ids")
	}

	const base int64 = 1752969600000
	rows := []feedFakeRow{
		{"11111111-0000-0000-0001-000000000000", base + 3},
		{"22222222-0000-0000-0002-000000000000", base + 2},
		{"33333333-0000-0000-0003-000000000000", base + 1},
	}
	for _, id := range tied {
		rows = append(rows, feedFakeRow{id, base}) // the millisecond tie
	}
	rows = append(rows, feedFakeRow{"44444444-0000-0000-0004-000000000000", base - 1})

	feedCursorFakeCH(t, rows)
	s := corrTestServer(t)

	// limit 3 puts a page boundary INSIDE the tie block, which is the only
	// place the two orders can disagree.
	seen := map[string]int{}
	cursor := ""
	for page := 0; page < 20; page++ {
		url := "/api/events/feed?from=24h&limit=3"
		if cursor != "" {
			url += "&cursor=" + cursor
		}
		w := httptest.NewRecorder()
		s.handleEventsFeed(w, req(http.MethodGet, url, "", acme()))
		if w.Code != http.StatusOK {
			t.Fatalf("page %d: status = %d (body %s)", page, w.Code, w.Body.String())
		}
		var body struct {
			Items      []map[string]any `json:"items"`
			NextCursor string           `json:"next_cursor"`
		}
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
			t.Fatalf("page %d: decode: %v", page, err)
		}
		for _, it := range body.Items {
			seen[fmt.Sprintf("%v", it["signal_id"])]++
		}
		if body.NextCursor == "" {
			break
		}
		cursor = body.NextCursor
	}

	var dropped, duplicated []string
	for _, row := range rows {
		switch n := seen[row.id]; {
		case n == 0:
			dropped = append(dropped, row.id)
		case n > 1:
			duplicated = append(duplicated, fmt.Sprintf("%s×%d", row.id, n))
		}
	}
	if len(dropped) > 0 {
		t.Errorf("the page walk DROPPED %d of %d rows: %v", len(dropped), len(rows), dropped)
	}
	if len(duplicated) > 0 {
		t.Errorf("the page walk REPEATED rows: %v", duplicated)
	}
	if len(seen) > len(rows) {
		t.Errorf("the walk returned %d distinct ids, table holds %d", len(seen), len(rows))
	}
}
