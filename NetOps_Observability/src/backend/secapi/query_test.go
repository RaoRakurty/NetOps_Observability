package secapi

// query_test.go — the query builders are BYTE-PINNED.
//
// A shape assertion ("contains tenant_id") would still pass if the isolation
// clause moved somewhere the engine ignores it, or if a filter silently became
// a `should` instead of a `filter`. Pinning the exact marshalled body means any
// change to the wire — including one that only MOVES a clause — has to be made
// deliberately, in the same commit, by an author who read what they changed.
//
// Also pinned here: cursor round-tripping, filter validation (a bad value is a
// 400, never a silently empty result set) and the limit caps.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/oslog"
)

var (
	pinSince = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	pinUntil = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
)

// pinTenantClause is the real oslog.TenantFilter output for a scoped tenant —
// the same value the handler passes, not a stand-in.
func pinTenantClause() map[string]any {
	return oslog.TenantFilter("acme", false, []string{"rtr-1"}, []string{"10.0.0.1"})
}

// pinFullFilters exercises every filter at once so no clause can be dropped
// without the pin changing.
func pinFullFilters() Filters {
	return Filters{
		Severity: []string{"critical", "high"}, Status: []string{"Fail"},
		Seam: []string{"ISP"}, Framework: []string{"CIS"}, Device: []string{"rtr-1"},
		Q: "telnet", Since: pinSince, Until: pinUntil,
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// pinnedTenantScope is the isolation clause every pinned body below opens with.
// It is spelled out once so a diff shows the WHOLE clause when it changes.
const pinnedTenantScope = `{"bool":{"minimum_should_match":1,"should":[{"term":{"tenant_id":"acme"}},{"bool":{"must":[{"bool":{"minimum_should_match":1,"should":[{"term":{"tenant_id":""}},{"bool":{"must_not":[{"exists":{"field":"tenant_id"}}]}}]}},{"bool":{"minimum_should_match":1,"should":[{"terms":{"host":["rtr-1"]}},{"terms":{"hostname":["rtr-1"]}},{"terms":{"source_ip":["10.0.0.1"]}}]}}]}}]}}`

const pinnedRange = `{"range":{"ts":{"format":"strict_date_optional_time","gte":"2026-08-01T00:00:00Z","lte":"2026-09-01T00:00:00Z"}}}`

func TestListBodyIsPinned(t *testing.T) {
	want := `{"_source":true,"query":{"bool":{"filter":[` + pinnedTenantScope + `,` + pinnedRange +
		`,{"terms":{"severity":["critical","high"]}},{"terms":{"attrs.status":["Fail"]}},` +
		`{"bool":{"minimum_should_match":1,"should":[{"terms":{"seam_type":["ISP"]}},{"terms":{"seam_id":["ISP"]}}]}},` +
		`{"terms":{"attrs.standards":["CIS"]}},` +
		`{"bool":{"minimum_should_match":1,"should":[{"terms":{"entity_id":["rtr-1"]}},{"terms":{"entity_tokens":["rtr-1"]}}]}},` +
		`{"simple_query_string":{"default_operator":"and","fields":["attrs.control_title","attrs.control_id","attrs.raw_rule_id","entity_id","title","control_title","observed","intended","detail","status_detail","remediation"],"lenient":true,"query":"telnet"}}]}},` +
		`"size":100,"sort":[{"ts":{"order":"desc","unmapped_type":"date"}},{"cx_finding_id":{"order":"desc","unmapped_type":"keyword"}}],"track_total_hits":true}`
	if got := mustJSON(t, ListBody(pinFullFilters(), pinTenantClause(), 100, PagePos{})); got != want {
		t.Errorf("list body changed.\n got: %s\nwant: %s", got, want)
	}
}

// TestListBodyCurrentCollapseIsPinned pins the CURRENT-state shape: a collapse
// on native_id (so one verdict identity yields one row) plus the cardinality
// aggregation that supplies the honest group total — hits.total would count
// documents, i.e. every historical verdict, and inflate the page's "total".
func TestListBodyCurrentCollapseIsPinned(t *testing.T) {
	f := Filters{Since: pinSince, Until: pinUntil, Current: true}
	want := `{"_source":true,"aggs":{"current_total":{"cardinality":{"field":"native_id","precision_threshold":40000}}},` +
		`"collapse":{"field":"native_id"},"from":50,"query":{"bool":{"filter":[` + pinnedRange + `]}},` +
		`"size":50,` +
		`"sort":[{"ts":{"order":"desc","unmapped_type":"date"}},{"cx_finding_id":{"order":"desc","unmapped_type":"keyword"}}]}`
	got := mustJSON(t, ListBody(f, nil, 50, PagePos{From: 50}))
	if got != want {
		t.Errorf("current-collapse list body changed.\n got: %s\nwant: %s", got, want)
	}
	// track_total_hits must NOT be set alongside a collapse: it would report a
	// document count as if it were the number of current findings.
	if strings.Contains(got, "track_total_hits") {
		t.Error("track_total_hits must not accompany the collapse — it counts documents, not verdict identities")
	}
}

func TestFacetsBodyIsPinned(t *testing.T) {
	want := `{"aggs":{"evidence_class":{"terms":{"field":"attrs.evidence_class","order":[{"_count":"desc"},{"_key":"asc"}],"size":50}},` +
		`"framework":{"terms":{"field":"attrs.standards","order":[{"_count":"desc"},{"_key":"asc"}],"size":50}},` +
		`"seam":{"terms":{"field":"seam_type","order":[{"_count":"desc"},{"_key":"asc"}],"size":50}},` +
		`"severity":{"terms":{"field":"severity","order":[{"_count":"desc"},{"_key":"asc"}],"size":50}},` +
		`"status":{"terms":{"field":"attrs.status","order":[{"_count":"desc"},{"_key":"asc"}],"size":50}}},` +
		`"query":{"bool":{"filter":[` + pinnedTenantScope + `,` + pinnedRange + `]}},"size":0,"track_total_hits":true}`
	if got := mustJSON(t, FacetsBody(Filters{Since: pinSince, Until: pinUntil}, pinTenantClause())); got != want {
		t.Errorf("facets body changed.\n got: %s\nwant: %s", got, want)
	}
}

func TestCurrentFoldBodyIsPinned(t *testing.T) {
	f := Filters{Since: pinSince, Until: pinUntil, Current: true}
	want := `{"aggs":{"by_native":{"aggs":{"latest":{"top_hits":{"_source":{"includes":["severity","attrs.status","seam_type","seam_id","attrs.standards","attrs.evidence_class","entity_id","attrs.scan_id","ts"]},"size":1,"sort":[{"ts":{"order":"desc"}}]}}},` +
		`"terms":{"field":"native_id","order":[{"_key":"asc"}],"size":5000}},` +
		`"native_total":{"cardinality":{"field":"native_id","precision_threshold":40000}}},` +
		`"query":{"bool":{"filter":[` + pinnedTenantScope + `,` + pinnedRange + `]}},"size":0,"track_total_hits":false}`
	if got := mustJSON(t, CurrentFoldBody(f, pinTenantClause(), MaxCurrentGroups)); got != want {
		t.Errorf("current fold body changed.\n got: %s\nwant: %s", got, want)
	}
}

func TestTrendBodyIsPinned(t *testing.T) {
	want := `{"aggs":{"trend":{"aggs":{"status":{"terms":{"field":"attrs.status","size":6}}},` +
		`"date_histogram":{"extended_bounds":{"max":"2026-09-01T00:00:00Z","min":"2026-08-01T00:00:00Z"},"field":"ts","fixed_interval":"1d","min_doc_count":0}}},` +
		`"query":{"bool":{"filter":[` + pinnedTenantScope + `,` + pinnedRange + `]}},"size":0,"track_total_hits":false}`
	if got := mustJSON(t, TrendBody(Filters{Since: pinSince, Until: pinUntil}, pinTenantClause(), "1d")); got != want {
		t.Errorf("trend body changed.\n got: %s\nwant: %s", got, want)
	}
}

func TestGetBodyIsPinnedAndTenantScoped(t *testing.T) {
	want := `{"query":{"bool":{"filter":[` + pinnedTenantScope + `,` + pinnedRange +
		`,{"term":{"cx_finding_id":"deadbeef"}}]}},"size":1,` +
		`"sort":[{"ts":{"order":"desc","unmapped_type":"date"}}],"track_total_hits":false}`
	if got := mustJSON(t, GetBody("deadbeef", pinTenantClause(), pinSince, pinUntil)); got != want {
		t.Errorf("get body changed.\n got: %s\nwant: %s", got, want)
	}
}

func TestCoverageBodyIsPinned(t *testing.T) {
	f := Filters{Since: pinSince, Until: pinUntil, Current: true}
	want := `{"aggs":{"assessed_devices":{"cardinality":{"field":"entity_id","precision_threshold":40000}},` +
		`"last_scan":{"top_hits":{"_source":{"includes":["attrs.scan_id","ts"]},"size":1,"sort":[{"ts":{"order":"desc"}}]}}},` +
		`"query":{"bool":{"filter":[` + pinnedTenantScope + `,` + pinnedRange + `]}},"size":0,"track_total_hits":false}`
	if got := mustJSON(t, CoverageBody(f, pinTenantClause())); got != want {
		t.Errorf("coverage body changed.\n got: %s\nwant: %s", got, want)
	}
}

// TestPlatformOwnerBodyCarriesNoTenantClause pins the OTHER half of the
// contract: oslog.TenantFilter returns nil for the cross-tenant platform owner,
// and the builder must then emit NO per-doc tenant clause at all (a `null`
// clause in the filter array would make OpenSearch reject the query, turning
// the platform view into a 400 instead of a cross-tenant read).
func TestPlatformOwnerBodyCarriesNoTenantClause(t *testing.T) {
	tc := oslog.TenantFilter("global", true, nil, nil)
	if tc != nil {
		t.Fatalf("TenantFilter must be nil for a cross-tenant caller, got %v", tc)
	}
	got := mustJSON(t, ListBody(Filters{Since: pinSince, Until: pinUntil}, tc, 10, PagePos{}))
	if strings.Contains(got, "tenant_id") {
		t.Errorf("platform body must carry no tenant clause: %s", got)
	}
	if strings.Contains(got, "null") {
		t.Errorf("a nil tenant clause must be OMITTED, not marshalled as null: %s", got)
	}
}

// TestIndexPatternNamesOnlyTheCallersIndices is the at-rest half of §3a: a
// scoped tenant's pattern never names another tenant's index family, so a
// dropped query filter still cannot reach another tenant's documents.
func TestIndexPatternNamesOnlyTheCallersIndices(t *testing.T) {
	own := oslog.TenantIndexPattern(Signal, "acme", false)
	if own != "netops-secfindings-acme-*,netops-secfindings-untagged-*" {
		t.Fatalf("scoped pattern = %q", own)
	}
	if strings.Contains(own, "globex") {
		t.Fatal("TENANT LEAK: a scoped pattern named another tenant")
	}
	if cross := oslog.TenantIndexPattern(Signal, "global", true); cross != "netops-secfindings-*" {
		t.Fatalf("cross-tenant pattern = %q, want netops-secfindings-*", cross)
	}
}

// ---- cursor ----------------------------------------------------------------

func TestCursorRoundTrip(t *testing.T) {
	const id = "3f2a9c1e5b7d0a4f6e8c2b1d9a7f5e3c1b0d8a6f4e2c0b9d7a5f3e1c9b7d5a30"
	cur, ok := DecodeCursor(EncodeKeysetCursor(1_756_000_000_123, id))
	if !ok || cur.Collapsed || cur.Millis != 1_756_000_000_123 || cur.DocID != id {
		t.Fatalf("keyset round trip failed: %+v ok=%v", cur, ok)
	}
	cur, ok = DecodeCursor(EncodeOffsetCursor(400))
	if !ok || !cur.Collapsed || cur.Offset != 400 {
		t.Fatalf("offset round trip failed: %+v ok=%v", cur, ok)
	}
	// The two kinds are distinguishable, which is what lets the handler ignore
	// a cursor replayed in the wrong mode instead of paging with nonsense.
	if k, _ := DecodeCursor(EncodeKeysetCursor(1, id)); k.Collapsed {
		t.Fatal("a keyset cursor decoded as collapsed")
	}
}

func TestCursorRejectsGarbage(t *testing.T) {
	for _, bad := range []string{
		"not-base64!!",
		"",                           // empty
		"YWJj",                       // valid base64, no separator
		"a3wxMjN8",                   // "k|123|" — empty id
		"a3wxMjN8YWJjIGRlZg",         // "k|123|abc def" — id with a space
		"a3wtMXxhYmM",                // "k|-1|abc" — negative millis
		"a3xub3QtYS1udW1iZXJ8YWJj",   // "k|not-a-number|abc"
		"a3wxMjN8YTtEUk9QIFRBQkxF",   // "k|123|a;DROP TABLE"
		"a3wxMjN8Kioqd2lsZGNhcmQqKg", // "k|123|***wildcard**"
		"Y3wtNQ",                     // "c|-5" — negative offset
		"Y3wxMDAwMDE",                // "c|100001" — past the result window
		"eHwxMjN8YWJj",               // "x|123|abc" — unknown kind
	} {
		if _, ok := DecodeCursor(bad); ok {
			t.Errorf("DecodeCursor(%q) accepted a malformed cursor", bad)
		}
	}
}

// TestCollapsedPagingUsesFromNotSearchAfter is the pin on a constraint VERIFIED
// LIVE against the deployed OpenSearch 2.16: a body carrying both `collapse` and
// `search_after` is rejected outright ("cannot use `collapse` in conjunction
// with `search_after`"), before the mapping is even consulted. The collapsed
// list therefore pages by `from`. Without this test the mistake is invisible to
// every unit test and shows up as a 400 on page 2 in production.
func TestCollapsedPagingUsesFromNotSearchAfter(t *testing.T) {
	f := Filters{Since: pinSince, Until: pinUntil, Current: true}
	got := mustJSON(t, ListBody(f, nil, 50, PagePos{From: 100}))
	if strings.Contains(got, "search_after") {
		t.Fatalf("a collapsed body must NEVER carry search_after — OpenSearch rejects the pair: %s", got)
	}
	if !strings.Contains(got, `"from":100`) {
		t.Fatalf("the collapsed page position was lost: %s", got)
	}
	// The uncollapsed path is the mirror image: keyset, never an offset.
	got = mustJSON(t, ListBody(Filters{Since: pinSince, Until: pinUntil}, nil, 50, PagePos{After: []any{int64(7), "id"}}))
	if strings.Contains(got, `"from"`) {
		t.Fatalf("the uncollapsed list must page by keyset, not offset: %s", got)
	}
	if !strings.Contains(got, `"search_after":[7,"id"]`) {
		t.Fatalf("keyset lost: %s", got)
	}
}

// ---- filter validation -----------------------------------------------------

// manyTokens builds n DISTINCT filter tokens (a repeated value would dedupe
// away and never reach the cap, which is the point of testing distinct ones).
func manyTokens(n int) string {
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		parts = append(parts, "dev-"+strconv.Itoa(i))
	}
	return strings.Join(parts, ",")
}

func filterReq(t *testing.T, query string) *http.Request {
	t.Helper()
	return httptest.NewRequest(http.MethodGet, "/api/security/findings?"+query, nil)
}

func TestParseFiltersRejectsBadValues(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct{ name, query, wantSubstr string }{
		{"bad severity", "severity=hgih", "severity must be one of"},
		{"bad status", "status=broken", "status must be one of"},
		{"unsafe seam token", "seam=ISP%20OR%201%3D1", "unsupported value"},
		{"unsafe device token", "device=%3Cscript%3E", "unsupported value"},
		{"too many devices", "device=" + manyTokens(25), "at most 20 values"},
		{"bad current", "current=maybe", "current must be one of"},
		{"bad since", "since=yesterday", "since:"},
		{"inverted window", "since=2026-09-01T00:00:00Z&until=2026-08-01T00:00:00Z", "strictly before"},
		{"over-wide window", "since=2020-01-01T00:00:00Z&until=2026-09-01T00:00:00Z", "at most 365 days"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseFilters(filterReq(t, tc.query), now)
			if err == nil {
				t.Fatalf("%s was ACCEPTED — a bad filter must be a 400, never a silently empty result", tc.query)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error %q does not name the problem (want %q)", err, tc.wantSubstr)
			}
		})
	}
}

func TestParseFiltersCanonicalizes(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f, err := ParseFilters(filterReq(t, "severity=HIGH,high,critical&status=warn&current=true"), now)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Severity) != 2 || f.Severity[0] != "high" || f.Severity[1] != "critical" {
		t.Errorf("severity = %v, want deduped+lowercased [high critical]", f.Severity)
	}
	if len(f.Status) != 1 || f.Status[0] != "Warning" {
		t.Errorf("status = %v, want the canonical stored token [Warning]", f.Status)
	}
	if !f.Current {
		t.Error("current=true was not honoured")
	}
	if f.Until != now || f.Since != now.Add(-DefaultWindow) {
		t.Errorf("default window = [%s, %s], want the last %s", f.Since, f.Until, DefaultWindow)
	}
}

// TestStatusVocabularyKeepsNonVerdictsAddressable is the §5g honesty rule as a
// test: NotApplicable and Error must be selectable and must have their own
// facet keys. Folding them into pass/warn/fail — or dropping them — is how an
// unassessed control silently reads as clean.
func TestStatusVocabularyKeepsNonVerdictsAddressable(t *testing.T) {
	for _, alias := range []string{"not_applicable", "na", "error", "unknown"} {
		if _, ok := StatusAliases[alias]; !ok {
			t.Errorf("status alias %q is not addressable", alias)
		}
	}
	for _, canon := range []string{"Pass", "Warning", "Fail", "NotApplicable", "Error", "Unknown"} {
		if _, ok := StatusFacetKeys[canon]; !ok {
			t.Errorf("stored status %q has no facet key — it would vanish from the counts", canon)
		}
	}
	if StatusFacetKeys["NotApplicable"] == StatusFacetKeys["Pass"] {
		t.Fatal("NotApplicable must NEVER fold onto pass")
	}
}

// ---- bounds ----------------------------------------------------------------

func TestBoundedIntCapsAndFailsClosed(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x?limit=501", nil)
	if _, err := boundedInt(r, "limit", DefaultListLimit, 1, MaxListLimit); err == nil {
		t.Fatal("limit=501 must be a 400 — silently clamping returns fewer rows than asked with a 200")
	}
	r = httptest.NewRequest(http.MethodGet, "/x?limit=abc", nil)
	if _, err := boundedInt(r, "limit", DefaultListLimit, 1, MaxListLimit); err == nil {
		t.Fatal("limit=abc must be a 400")
	}
	r = httptest.NewRequest(http.MethodGet, "/x", nil)
	n, err := boundedInt(r, "limit", DefaultListLimit, 1, MaxListLimit)
	if err != nil || n != DefaultListLimit {
		t.Fatalf("absent limit = (%d, %v), want the default", n, err)
	}
	r = httptest.NewRequest(http.MethodGet, "/x?limit=500", nil)
	if n, err := boundedInt(r, "limit", DefaultListLimit, 1, MaxListLimit); err != nil || n != MaxListLimit {
		t.Fatalf("limit=500 = (%d, %v), want the cap accepted", n, err)
	}
}

func TestParseBucketAndBucketBudget(t *testing.T) {
	if _, err := ParseBucket("13m"); err == nil {
		t.Fatal("an unknown bucket must be a 400, never a silent fallback to 1d")
	}
	iv, err := ParseBucket("")
	if err != nil || iv != "1d" {
		t.Fatalf("default bucket = (%q, %v), want 1d", iv, err)
	}
	// A year at 1h is 8,761 points — refused, not silently coarsened.
	wide := Filters{Since: pinUntil.Add(-MaxWindow), Until: pinUntil}
	n, err := TrendBucketCount(wide, "1h")
	if err != nil {
		t.Fatalf("bucket count: %v", err)
	}
	if n <= MaxTrendBuckets {
		t.Fatalf("a 365-day window at 1h should exceed the %d-bucket cap, got %d", MaxTrendBuckets, n)
	}
	if n, err := TrendBucketCount(Filters{Since: pinSince, Until: pinUntil}, "1d"); err != nil || n != 32 {
		t.Fatalf("31 days at 1d = (%d, %v), want 32 dense buckets", n, err)
	}
}
