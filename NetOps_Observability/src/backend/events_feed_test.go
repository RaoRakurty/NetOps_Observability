package main

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
		"leaf1":                 "leaf1",
		"path:a->b":             "path:a->b",
		"Gi0/1":                 "Gi0/1",
		"a' OR '1'='1":          "a OR 11",       // quotes + '=' stripped
		"foo;DROP TABLE x":      "fooDROP TABLE x", // ';' stripped
		"x\\y":                  "xy",            // backslash stripped
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
	// unmapped kind humanizes
	if got := kindNoc("qos_drops"); got != "Qos drops" {
		t.Errorf("kindNoc fallback = %q", got)
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
