// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
